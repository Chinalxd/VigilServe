"""Real service/process monitoring over WinRM/SSH.

Collects process-level metrics (CPU, memory) together with port/process
liveness checks. Every value is returned from a real remote command.
"""

from __future__ import annotations

import re
from typing import Dict, List

from services.remote_safety import ps_quote, safe_image, safe_int, sh_quote


class ServiceMonitorError(Exception):
    """Raised when the monitor cannot connect or execute a check."""


def _connect_agent(server):
    """Open a RemoteAgent connection and return it, or None on failure."""
    from services.remote_agent import RemoteAgent

    agent = RemoteAgent(server)
    if not agent.connect():
        return None
    return agent




def _alive_from_status(status: str) -> str:
    """Map a raw running/stopped/unknown status to alive_status."""
    return "running" if status == "running" else ("stopped" if status == "stopped" else "unknown")


def _alert_status(alive_status: str, running_status: str) -> str:
    """Derive alert status from process and service states."""
    if alive_status == "stopped" or running_status == "stopped":
        return "critical"
    if alive_status == "unknown" or running_status == "unknown":
        return "warning"
    return "normal"




def _parse_process_metrics(output: str) -> Dict[str, Dict]:
    """Parse 'key:alive=true|cpu=1.2|mem=3.4|ws=56.7|pid=123|path=C:\foo' lines."""
    result: Dict[str, Dict] = {}
    for line in output.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        key, payload = line.split(":", 1)
        key = key.strip()
        item: Dict = {"alive": 0.0, "cpu": 0.0, "mem": 0.0, "ws": 0.0, "pid": 0.0, "path": ""}
        for part in payload.split("|"):
            if "=" not in part:
                continue
            pkey, pval = part.split("=", 1)
            pkey = pkey.strip().lower()
            pval = pval.strip()
            if pkey == "path":
                item[pkey] = pval
                continue
            try:
                item[pkey] = float(pval)
            except (ValueError, KeyError):
                pass
        result[key] = item
    return result


def _parse_ps_lines(output: str) -> List[Dict[str, str]]:
    """Parse 'comm pcpu pmem pid' lines from ps."""
    rows: List[Dict[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.rsplit(None, 3)
        if len(parts) < 4:
            continue
        pid, pmem, pcpu, comm = parts[-1], parts[-2], parts[-3], "".join(parts[:-3]).strip()
        rows.append({"comm": comm, "pcpu": pcpu, "pmem": pmem, "pid": pid})
    return rows




def _winrm_check_ports(agent, services: List) -> Dict[int, str]:
    """Batch-check TCP ports over one WinRM connection."""
    results: Dict[int, str] = {}
    port_services = [svc for svc in services
                     if safe_int(svc.port, 1, 65535) is not None]
    if not port_services:
        return results

    ports = sorted({safe_int(svc.port, 1, 65535) for svc in port_services})
    ps = (
        "$ports=@(" + ",".join(str(p) for p in ports) + "); "
        "foreach ($port in $ports) { "
        "  $r = Test-NetConnection -ComputerName 127.0.0.1 -Port $port "
        "         -WarningAction SilentlyContinue; "
        "  Write-Output \"$port:$($r.TcpTestSucceeded)\" "
        "}"
    )
    out = agent._run_winrm(ps)

    for line in out.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        port_str, val = line.split(":", 1)
        val = val.strip().lower()
        status = "running" if val in {"true", "open"} else "stopped"
        for svc in port_services:
            if str(svc.port) == port_str:
                results[svc.id] = status
    return results


def _winrm_check_processes(agent, services: List) -> Dict[int, Dict[str, float]]:
    """Check process existence and collect CPU/memory metrics over WinRM."""
    results: Dict[int, Dict[str, float]] = {}
    if not services:
        return results

    targets = []
    for svc in services:
        # safe_image() 会拒绝引号/分号/反引号/换行等一切可用于闭合注入的字符；
        # ps_quote() 再做一次单引号转义，两层兜底。
        image = safe_image(svc.image_name or svc.process_name or svc.name or "")
        if image:
            targets.append(f"@{{ id={safe_int(svc.id, 0) or 0}; image={ps_quote(image)} }}")

    if not targets:
        return results

    ps = (
        "$targets = @(" + ", ".join(targets) + "); "
        "$procs = Get-Process -ErrorAction SilentlyContinue; "
        "$totalMemMb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB, 0); "
        r"$counters = (Get-Counter '\Process(*)\% Processor Time' -MaxSamples 1 -ErrorAction SilentlyContinue).CounterSamples; "
        "foreach ($t in $targets) { "
        "  $name = $t.image; "
        "  $matches = @($procs | Where-Object { $_.Name -eq $name -or $_.Name -like \"$name*\" }); "
        "  if ($matches.Count -gt 0) { "
        "    $p = $matches | Sort-Object WorkingSet -Descending | Select-Object -First 1; "
        "    $wsMb = [math]::Round($p.WorkingSet / 1MB, 1); "
        "    $memPct = if ($totalMemMb -gt 0) { [math]::Round(($wsMb / $totalMemMb) * 100, 1) } else { 0 }; "
        "    $baseName = $p.Name; "
        "    $cpuSample = $counters | Where-Object { $_.InstanceName -eq $baseName -or $_.InstanceName -like \"$baseName#*\" } | Select-Object -First 1; "
        "    $cpuPct = if ($cpuSample) { [math]::Round($cpuSample.CookedValue, 1) } else { 0 }; "
        "    $procPath = if ($p.Path) { $p.Path } else { '' }; "
        "    Write-Output \"$($t.id):alive=true|cpu=$cpuPct|mem=$memPct|ws=$wsMb|pid=$($p.Id)|path=$procPath\" "
        "  } else { "
        "    Write-Output \"$($t.id):alive=false|cpu=0|mem=0|ws=0|pid=0|path=\" "
        "  } "
        "}"
    )
    out = agent._run_winrm(ps)
    return _parse_process_metrics(out)




def _ssh_check_ports(agent, services: List) -> Dict[int, str]:
    """Batch-check TCP ports over one SSH connection."""
    results: Dict[int, str] = {}
    port_services = [svc for svc in services
                     if safe_int(svc.port, 1, 65535) is not None]
    if not port_services:
        return results

    ports = sorted({safe_int(svc.port, 1, 65535) for svc in port_services})
    port_list = " ".join(str(p) for p in ports)
    cmd = (
        f"for port in {port_list}; do "
        f"  if ss -tlnp 2>/dev/null | grep -q \":$port \" || "
        f"     netstat -tlnp 2>/dev/null | grep -q \":$port \"; then "
        f"    echo \"$port:open\"; "
        f"  else echo \"$port:closed\"; fi; "
        f"done"
    )
    out = agent._run_ssh(cmd)

    for line in out.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        port_str, val = line.split(":", 1)
        status = "running" if val.strip().lower() == "open" else "stopped"
        for svc in port_services:
            if str(svc.port) == port_str:
                results[svc.id] = status
    return results


def _ssh_check_processes(agent, services: List) -> Dict[int, Dict]:
    """Check process existence and collect CPU/memory/path metrics over SSH."""
    results: Dict[int, Dict] = {}
    if not services:
        return results

    images = []
    for svc in services:
        image = safe_image(svc.image_name or svc.process_name or svc.name or "")
        if image and image not in images:
            images.append(image)

    if not images:
        return results

    cmd = (
        "ps -eo comm:50,pcpu,pmem,pid --no-headers | "
        "awk '{comm=$1; for(i=2;i<=NF-3;i++) comm=comm\" \"$i; "
        "print comm, $(NF-2), $(NF-1), $NF}'"
    )
    out = agent._run_ssh(cmd)
    rows = _parse_ps_lines(out)

    pid_to_svc: Dict[str, int] = {}
    for svc in services:
        image = safe_image(svc.image_name or svc.process_name or svc.name or "")
        if not image:
            results[svc.id] = {"alive": 0.0, "cpu": 0.0, "mem": 0.0, "ws": 0.0, "pid": 0.0, "path": ""}
            continue

        matched = None
        for row in rows:
            comm = row["comm"]
            if comm == image or comm.endswith("/" + image):
                matched = row
                break
            if re.search(rf"\b{re.escape(image)}\b", comm):
                matched = row

        if matched:
            pid = matched["pid"]
            pid_to_svc[pid] = svc.id
            results[svc.id] = {
                "alive": 1.0,
                "cpu": float(matched["pcpu"]) if matched["pcpu"] else 0.0,
                "mem": float(matched["pmem"]) if matched["pmem"] else 0.0,
                "ws": 0.0,
                "pid": float(pid) if pid else 0.0,
                "path": "",
            }
        else:
            results[svc.id] = {"alive": 0.0, "cpu": 0.0, "mem": 0.0, "ws": 0.0, "pid": 0.0, "path": ""}

    if pid_to_svc:
        # PID 来自远端 ps 输出，只保留纯数字，避免被伪造进程名带出 shell 元字符
        pid_to_svc = {p: sid for p, sid in pid_to_svc.items() if p.isdigit()}
        if not pid_to_svc:
            return results
        pid_list = " ".join(pid_to_svc.keys())
        path_cmd = (
            f"for pid in {pid_list}; do "
            f"  path=$(readlink -f /proc/$pid/exe 2>/dev/null || echo ''); "
            f"  echo \"$pid:$path\"; "
            f"done"
        )
        try:
            path_out = agent._run_ssh(path_cmd)
            for line in path_out.splitlines():
                line = line.strip()
                if ":" not in line:
                    continue
                pid, path = line.split(":", 1)
                svc_id = pid_to_svc.get(pid)
                if svc_id and svc_id in results:
                    results[svc_id]["path"] = path.strip()
        except Exception:
            pass

    return results




def _server_disk_percent(server) -> float:
    """Return the current overall disk percent for the server."""
    try:
        from database import SessionLocal
        from models import MetricSnapshot
        db = SessionLocal()
        try:
            latest = (
                db.query(MetricSnapshot)
                .filter(MetricSnapshot.server_id == server.id)
                .order_by(MetricSnapshot.timestamp.desc())
                .first()
            )
            if latest and latest.disk_percent:
                return float(latest.disk_percent)
        finally:
            db.close()
    except Exception:
        pass

    partitions = getattr(server, "disk_partitions", None) or []
    if partitions:
        try:
            return max(float(p.get("percent", 0) or 0) for p in partitions)
        except (ValueError, TypeError):
            pass
    return 0.0


def check_services_for_server(server, services: List) -> Dict[int, Dict]:
    """Check all monitored services for a server in one remote session.

    Returns a dict mapping ``service.id`` to a dictionary with keys:
      - alive_status: running | stopped | unknown
      - running_status: running | stopped | unknown
      - cpu_percent: float
      - memory_percent: float
      - disk_percent: float
      - disk_mbps: float        # disk write speed in MB/s
      - network_mbps: float     # network throughput in Mbps
      - alert_status: normal | warning | critical
      - pid: int
      - path: str               # image file directory/path
    """
    if not services:
        return {}

    protocol = (server.protocol or "").upper()
    if protocol not in {"WINRM", "SSH"}:
        return {
            svc.id: {
                "alive_status": svc.alive_status or "unknown",
                "running_status": svc.running_status or svc.status or "unknown",
                "cpu_percent": svc.cpu_percent or 0.0,
                "memory_percent": svc.memory_percent or 0.0,
                "disk_percent": svc.disk_percent or 0.0,
                "disk_mbps": svc.disk_mbps or 0.0,
                "disk_read_mbps": svc.disk_read_mbps or 0.0,
                "disk_write_mbps": svc.disk_write_mbps or 0.0,
                "network_mbps": svc.network_mbps or 0.0,
                "network_in_mbps": svc.network_in_mbps or 0.0,
                "network_out_mbps": svc.network_out_mbps or 0.0,
                "alert_status": svc.alert_status or "normal",
                "pid": svc.pid or 0,
                "ppid": svc.ppid or 0,
                "path": svc.path or "",
                "start_time": svc.start_time or "",
                "cmdline": svc.cmdline or "",
                "username": svc.username or "",
            }
            for svc in services
        }

    agent = _connect_agent(server)
    if agent is None:
        return {
            svc.id: {
                "alive_status": "unknown",
                "running_status": "unknown",
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "disk_percent": 0.0,
                "disk_mbps": 0.0,
                "disk_read_mbps": 0.0,
                "disk_write_mbps": 0.0,
                "network_mbps": 0.0,
                "network_in_mbps": 0.0,
                "network_out_mbps": 0.0,
                "alert_status": "warning",
                "pid": 0,
                "ppid": 0,
                "path": "",
                "start_time": "",
                "cmdline": "",
                "username": "",
            }
            for svc in services
        }

    try:
        if protocol == "WINRM":
            port_results = _winrm_check_ports(agent, services)
            proc_results = _winrm_check_processes(agent, services)
        else:
            port_results = _ssh_check_ports(agent, services)
            proc_results = _ssh_check_processes(agent, services)

        disk_pct = _server_disk_percent(server)

        results: Dict[int, Dict] = {}
        for svc in services:
            has_port = svc.port and svc.port > 0

            proc = proc_results.get(svc.id, {})
            alive = "running" if proc.get("alive") else "stopped"

            if has_port:
                running = port_results.get(svc.id, "unknown")
            else:
                running = alive

            results[svc.id] = {
                "alive_status": alive,
                "running_status": running,
                "cpu_percent": proc.get("cpu", 0.0),
                "memory_percent": proc.get("mem", 0.0),
                "disk_percent": disk_pct,
                "disk_mbps": 0.0,
                "disk_read_mbps": 0.0,
                "disk_write_mbps": 0.0,
                "network_mbps": 0.0,
                "network_in_mbps": 0.0,
                "network_out_mbps": 0.0,
                "alert_status": _alert_status(alive, running),
                "pid": int(proc.get("pid", 0) or 0),
                "ppid": 0,
                "path": proc.get("path", ""),
                "start_time": "",
                "cmdline": "",
                "username": "",
            }
        return results
    finally:
        agent.close()


def check_single_service(server, service) -> Dict:
    """Convenience wrapper to check a single service."""
    return check_services_for_server(server, [service]).get(service.id, {
        "alive_status": "unknown",
        "running_status": "unknown",
        "cpu_percent": 0.0,
        "memory_percent": 0.0,
        "disk_percent": 0.0,
        "disk_mbps": 0.0,
        "disk_read_mbps": 0.0,
        "disk_write_mbps": 0.0,
        "network_mbps": 0.0,
        "network_in_mbps": 0.0,
        "network_out_mbps": 0.0,
        "alert_status": "warning",
        "pid": 0,
        "ppid": 0,
        "path": "",
        "start_time": "",
        "cmdline": "",
        "username": "",
    })




def terminate_service(server, service, mode: str = "graceful") -> dict:
    """Terminate a remote process by PID or image/process name.

    mode: "graceful" (exit gracefully) or "force" (force kill).
    Returns {"success": bool, "message": str}.
    """
    protocol = (server.protocol or "").upper()
    if protocol not in {"WINRM", "SSH"}:
        return {"success": False, "message": f"协议 {server.protocol} 不支持远程终止进程"}

    agent = _connect_agent(server)
    if agent is None:
        return {"success": False, "message": "无法连接到远程主机"}

    try:
        if protocol == "WINRM":
            return _winrm_terminate(agent, service, mode)
        return _ssh_terminate(agent, service, mode)
    finally:
        agent.close()


def _winrm_terminate(agent, service, mode: str) -> dict:
    pid = safe_int(service.pid, 0) or 0
    # 进程名进命令行前必须校验：早期版本直接 f-string 拼进 PowerShell 单引号串，
    # 名称里带引号就能闭合字符串执行任意命令（见 services/remote_safety.py）。
    name = safe_image(service.image_name or service.process_name or "")
    force = mode == "force"

    if pid <= 0 and not name:
        return {"success": False, "message": "没有 PID 或进程名，无法定位进程"}

    if pid > 0:
        arg = f"/PID {pid}"
    else:
        arg = f'/IM "{name}"'
    if force:
        arg += " /F"

    ps = (
        f"$arg = {ps_quote(arg)}; "
        "$out = cmd /c \"taskkill $arg\" 2>&1; "
        "$code = $LASTEXITCODE; "
        "Write-Output \"exit:$code`:$out\""
    )
    out = agent._run_winrm(ps)

    if out.startswith("exit:"):
        parts = out.split(":", 2)
        code = parts[1].strip() if len(parts) > 1 else "1"
        msg = parts[2].strip() if len(parts) > 2 else out
    else:
        lowered = out.lower()
        success_hints = ("成功", "success", "terminated", "已终止")
        code = "0" if any(h in lowered for h in success_hints) else "1"
        msg = out

    success = code == "0"
    label = "强制终止" if force else "退出进程"
    return {
        "success": success,
        "message": f"{label}{'成功' if success else '失败'}" + (f"：{msg}" if msg else ""),
    }


def _ssh_terminate(agent, service, mode: str) -> dict:
    pid = safe_int(service.pid, 0) or 0
    name = safe_image(service.image_name or service.process_name or "")
    force = mode == "force"
    sig = "-9" if force else "-15"

    if pid > 0:
        cmd = f"kill {sig} {pid} && echo ok || echo failed"
    elif name:
        # pkill 走 sh -c，进程名里的引号/分号/管道必须转义（shlex.quote）
        cmd = f"pkill {sig} {sh_quote(name)} && echo ok || echo failed"
    else:
        return {"success": False, "message": "没有 PID 或进程名，无法定位进程"}

    out = agent._run_ssh(cmd)
    success = out.strip().endswith("ok")
    label = "强制终止" if force else "退出进程"
    return {
        "success": success,
        "message": f"{label}{'成功' if success else '失败'}",
    }
