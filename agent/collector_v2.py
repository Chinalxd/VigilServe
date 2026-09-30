"""Non-intrusive agent collector v2.

Only uses read-only OS APIs (psutil, /proc on Linux) and avoids:
- spawning subprocesses
- WMI / registry queries
- reading EXE version info
- injecting hooks or drivers

Provides system-level metrics plus per-process metrics for monitored
services (CPU %, memory %, disk write MB/s, network Mbps, PID, path).
"""

from __future__ import annotations

import os
import re
import sys
import time
import socket
import ctypes
import platform
from datetime import datetime, timezone

import psutil

try:
    import cpuinfo
except Exception:  # pragma: no cover
    cpuinfo = None




_CPU_MODEL_CACHE: str | None = None

_CPUID_CODE_RE = re.compile(
    r"^(?:Intel|AMD|ARM|Hygon|Centaur|Unknown)\s*\d*\s+Family\s+\d+", re.IGNORECASE
)


def _cpu_model_from_registry() -> str:
    """从 Windows 注册表取 CPU 品牌型号（一个键值，毫秒级，无需子进程）。"""
    if not sys.platform.startswith("win"):
        return ""
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "ProcessorNameString")
        return " ".join(str(value or "").split())
    except Exception:  # noqa: BLE001 拿不到就交给下一级来源
        return ""


def _get_cpu_model() -> str:
    """Return a human-friendly CPU model name.

    来源优先级：Windows 注册表 ProcessorNameString > py-cpuinfo brand_raw >
    platform.processor()。注册表一项就能给出真实型号（如
    "12th Gen Intel(R) Core(TM) i5-12400F"），而 platform.processor() 在
    Windows 上永远只是 CPUID 代号，只作最后兜底。
    """
    global _CPU_MODEL_CACHE
    if _CPU_MODEL_CACHE is not None:
        return _CPU_MODEL_CACHE

    name = _cpu_model_from_registry()

    if not name and cpuinfo is not None:
        try:
            info = cpuinfo.get_cpu_info()
            name = " ".join((info.get("brand_raw") or info.get("brand") or "").split())
        except Exception:
            name = ""

    if not name or _CPUID_CODE_RE.match(name):
        fallback = " ".join((platform.processor() or "").split())
        if fallback and not _CPUID_CODE_RE.match(fallback):
            name = fallback
        elif not name:
            name = fallback or "Unknown"

    _CPU_MODEL_CACHE = name
    return name


def _normalize_name(name: str) -> str:
    return (name or "").lower().replace(".exe", "").strip()


def _has_visible_window(pid: int) -> bool:
    """Return True if the process owns at least one visible top-level window.

    Only implemented for Windows. On Linux the function always returns False
    because a reliable visible-window check would require a running X session
    and is not portable across headless servers.
    """
    if not sys.platform.startswith("win"):
        return False
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        target = int(pid)
        found = [False]

        def check_window(hwnd, _extra):
            if found[0]:
                return False
            if not user32.IsWindowVisible(hwnd):
                return True
            # Skip child windows; only consider top-level windows.
            if user32.GetParent(hwnd):
                return True
            wnd_pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wnd_pid))
            if wnd_pid.value == target:
                found[0] = True
                return False
            return True

        EnumWindowsProc = ctypes.WINFUNCTYPE(
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
        )
        user32.EnumWindows(EnumWindowsProc(check_window), 0)
        return found[0]
    except Exception:
        return False


def _compute_app_instance_id(image_name: str, path: str, cmdline: str) -> str:
    """Compute a stable application-instance key for process grouping.

    The same executable file can host many unrelated applications (e.g.
    java.exe -jar app1.jar vs app2.jar, python.exe script1.py vs script2.py,
    svchost.exe -k ServiceGroup1 vs -k ServiceGroup2). This key separates those
    instances so the UI only folds processes that really belong together.
    """
    import re

    image = (image_name or "").lower().strip()
    cmd = (cmdline or "").strip()
    exe_path = (path or "").lower().strip()

    def _extract_arg(pattern, default=None):
        m = re.search(pattern, cmd, re.IGNORECASE)
        if m:
            return m.group(1).strip().strip('"')
        return default

    if image in ("java.exe", "javaw.exe"):
        jar = _extract_arg(r"-jar\s+(\S+)")
        if jar:
            return f"{image}|jar:{jar.lower()}"
        for token in cmd.split():
            low = token.lower()
            if low.endswith(".jar") or low.endswith(".war"):
                return f"{image}|jar:{low}"
        return f"{image}|cmd:{cmd}" if cmd else image

    if image in ("python.exe", "pythonw.exe", "python3.exe"):
        script = _extract_arg(r"\s(\S+\.py)\s")
        if script:
            return f"{image}|script:{script.lower()}"
        for token in cmd.split():
            low = token.lower()
            if low.endswith(".py"):
                return f"{image}|script:{low}"
        return f"{image}|cmd:{cmd}" if cmd else image

    if image in ("node.exe", "nodejs.exe"):
        script = _extract_arg(r"\s(\S+\.(?:js|mjs|cjs))\s")
        if script:
            return f"{image}|script:{script.lower()}"
        for token in cmd.split():
            low = token.lower()
            if low.endswith((".js", ".mjs", ".cjs")):
                return f"{image}|script:{low}"
        return f"{image}|cmd:{cmd}" if cmd else image

    if image == "dotnet.exe":
        dll = _extract_arg(r"(\S+\.dll)")
        if dll:
            return f"{image}|dll:{dll.lower()}"
        return f"{image}|cmd:{cmd}" if cmd else image

    if image == "svchost.exe":
        group = _extract_arg(r"-k\s+(\S+)")
        if group:
            return f"svchost.exe|group:{group.lower()}"
        return "svchost.exe|group:default"

    if exe_path:
        return f"{exe_path}\\{image}".lower()
    return image


def _file_description(path: str) -> str | None:
    """Read Windows PE FileDescription without external dependencies.

    Uses version.dll via ctypes so the agent stays non-intrusive and does not
    need pywin32 installed.
    """
    if not path or not sys.platform.startswith("win"):
        return None
    try:
        version = ctypes.windll.version
        size = version.GetFileVersionInfoSizeW(path, None)
        if size == 0:
            return None
        buf = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(path, 0, size, buf):
            return None
        ulen = ctypes.c_uint(0)
        ptr = ctypes.c_void_p(0)
        if not version.VerQueryValueW(buf, r"\VarFileInfo\Translation", ctypes.byref(ptr), ctypes.byref(ulen)):
            return None
        trans = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_uint32)).contents.value
        lang = trans & 0xFFFF
        codepage = (trans >> 16) & 0xFFFF
        sub_block = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\FileDescription"
        if not version.VerQueryValueW(buf, sub_block, ctypes.byref(ptr), ctypes.byref(ulen)):
            return None
        desc = ctypes.wstring_at(ptr)
        return desc.strip() or None
    except Exception:
        return None


def _proc_net_dev(pid: int) -> tuple[int, int]:
    """Read per-process network counters.

    On Linux this reads /proc/<pid>/net/dev. On Windows psutil's
    io_counters().other_bytes already includes network I/O, so callers
    should use ``net_bytes`` from :func:`_proc_io_net_bytes` instead.

    Returns (recv_bytes, sent_bytes). Falls back to (0, 0) on error.
    """
    if not sys.platform.startswith("linux"):
        return 0, 0
    path = f"/proc/{pid}/net/dev"
    try:
        recv = sent = 0
        with open(path, "r") as f:
            for line in f:
                if ":" not in line:
                    continue
                iface, data = line.split(":", 1)
                if iface.strip() in ("lo",):
                    continue
                parts = data.split()
                if len(parts) >= 9:
                    recv += int(parts[0])
                    sent += int(parts[8])
        return recv, sent
    except Exception:
        return 0, 0


def _proc_io_net_bytes(pid: int) -> int:
    """Return per-process network bytes using the best non-intrusive API.

    Windows: psutil.Process.io_counters().other_bytes includes network I/O.
    Linux: falls back to summing /proc/<pid>/net/dev.
    """
    try:
        io = psutil.Process(pid).io_counters()
        if sys.platform.startswith("win") and hasattr(io, "other_bytes"):
            return int(io.other_bytes)
    except Exception:
        pass
    recv, sent = _proc_net_dev(pid)
    return recv + sent


def _proc_io_net_bytes_split(pid: int) -> tuple[int, int, int]:
    """Return per-process network bytes split into (recv, sent, total).

    Windows only reports a single "other" counter (mostly network), so recv
    and sent cannot be reliably split; total is returned and recv/sent are 0.
    Linux reads /proc/<pid>/net/dev and returns real recv/sent counters.
    """
    try:
        io = psutil.Process(pid).io_counters()
        if sys.platform.startswith("win") and hasattr(io, "other_bytes"):
            total = int(io.other_bytes)
            return 0, 0, total
    except Exception:
        pass
    recv, sent = _proc_net_dev(pid)
    return recv, sent, recv + sent


def _pid_ports() -> dict[int, list[int]]:
    """Build pid -> listening ports mapping."""
    mapping: dict[int, list[int]] = {}
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr and conn.pid:
                mapping.setdefault(conn.pid, []).append(conn.laddr.port)
    except (psutil.AccessDenied, OSError):
        pass
    return mapping


# core_system -> OS-critical processes; view-only, never terminate.

CORE_SYSTEM_PROCS = {
    "System", "Registry", "Idle", "System Idle Process", "MemCompression",
    "csrss.exe", "smss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "svchost.exe", "winlogon.exe", "conhost.exe", "dllhost.exe",
    "systemd", "systemd-journald", "systemd-logind", "systemd-networkd",
    "systemd-resolve", "systemd-timesyncd", "kthreadd", "ksoftirqd",
    "migration", "rcu_gp", "rcu_par_gp", "watchdogd", "kworker",
    "khungtaskd", "kswapd", "init",
}

SYSTEM_SERVICE_PROCS = {
    "dwm.exe", "explorer.exe", "taskhostw.exe", "RuntimeBroker.exe",
    "WmiPrvSE.exe", "sihost.exe", "fontdrvhost.exe", "WerFault.exe",
    "Wermgr.exe", "taskmgr.exe", "powershell.exe", "cmd.exe",
    "spoolsv.exe", "msdtc.exe", "wuauclt.exe", "SearchUI.exe",
    "StartMenuExperienceHost.exe", "ShellExperienceHost.exe",
    "LockApp.exe", "LogonUI.exe", "ctfmon.exe", "audiodg.exe", "dasHost.exe",
    "wlanext.exe", "jhi_service.exe",
    "msmpeng.exe", "msmpengcp.exe", "msascui.exe", "msascuil.exe",
    "msosync.exe", "msiexec.exe",
    "SecurityHealthService.exe", "smartscreen.exe", "SearchIndexer.exe",
    "CompatTelRunner.exe", "backgroundTaskHost.exe", "MusNotifyIcon.exe",
    "ApplicationFrameHost.exe", "TextInputHost.exe", "SearchApp.exe",
    "ChsIME.exe", "UserOOBEBroker.exe", "CompPkgSrv.exe", "igfxEM.exe",
    "dbus-daemon", "NetworkManager", "cron", "crond", "rsyslogd",
    "auditd", "polkitd", "sshd", "agetty", "bash", "sh", "zsh",
}

THIRD_PARTY_SERVICE_PROCS = {
    "OneDrive.exe", "FileCoAuth.exe", "OfficeClickToRun.exe",
    "RtkAudUService64.exe", "IntelCpHDCPSvc.exe", "IntelCpHeciSvc.exe",
    "igfxCUIService.exe", "OneApp.IGCC.WinService.exe", "RstMwService.exe",
    "WavesSysSvc64.exe",
    "NisSrv.exe", "MpDefenderCoreService.exe", "SecurityHealthSystray.exe",
    "fbserver.exe", "IdocInetsrv.exe", "Mangr.exe", "nezha-agent.exe",
    "zTasker.exe", "ToDesk.exe", "WMIRegistrationService.exe",
}

SYSTEM_PROCS = CORE_SYSTEM_PROCS | SYSTEM_SERVICE_PROCS


def _is_core_system_proc(name: str) -> bool:
    if not name:
        return False
    return name.lower() in {p.lower() for p in CORE_SYSTEM_PROCS}


def _is_system_service_proc(name: str) -> bool:
    if not name:
        return False
    return name.lower() in {p.lower() for p in SYSTEM_SERVICE_PROCS}


def _is_third_party_service_proc(name: str) -> bool:
    if not name:
        return False
    n = name.lower()
    if n in {p.lower() for p in THIRD_PARTY_SERVICE_PROCS}:
        return True
    if n.endswith("service.exe") or n.endswith("svc.exe"):
        return True
    return False


def _is_system_proc(name: str) -> bool:
    """Backward-compatible: return True for any OS-owned process."""
    if not name:
        return True
    n = name.lower()
    if n in {p.lower() for p in SYSTEM_PROCS}:
        return True
    return False


def _is_service_proc(name: str) -> bool:
    """Backward-compatible: return True for third-party / background services."""
    return _is_third_party_service_proc(name)


def _is_system_path(path: str) -> bool:
    """Return True when the executable path belongs to the OS install tree."""
    if not path:
        return False
    p = path.lower().replace("\\", "/")
    system_prefixes = (
        "c:/windows", "c:/programdata", "c:/windows/system32",
        "c:/windows/syswow64", "c:/windows/sysnative",
        "/usr/sbin/", "/sbin/", "/lib/systemd/", "/usr/lib/systemd/",
        "/usr/bin/dbus-", "/usr/libexec/", "/bin/",
    )
    return any(p.startswith(prefix) for prefix in system_prefixes)


def _proc_detailed_category(name: str, path: str = "", username: str | None = None,
                            is_monitored: bool = False) -> str:
    """Classify a process into one of the four operation levels.

    Priority (highest first):
      1. core_system       - OS-critical; terminating these can crash the host.
      2. system_service    - OS-owned services/daemons.
      3. third_party_service - Installed third-party services/daemons.
      4. user_process      - Interactive user applications.
    """
    system_users = {"system", "nt authority\\system", "local service",
                    "network service", "root", "0"}
    user = (username or "").lower()

    if _is_core_system_proc(name):
        return "core_system"
    if _is_system_service_proc(name):
        return "system_service"
    if is_monitored:
        return "third_party_service"
    if _is_third_party_service_proc(name):
        return "third_party_service"
    if user and user in system_users:
        return "system_service"
    if _is_system_path(path) and user in system_users:
        return "system_service"
    return "user_process"


def _proc_category(name: str, path: str = "", username: str | None = None,
                   is_monitored: bool = False) -> str:
    """Backward-compatible three-class classification (system / service / user).

    Maps the four-level model to the legacy three-level model used by older
    server code and UI components.
    """
    detailed = _proc_detailed_category(name, path=path, username=username,
                                       is_monitored=is_monitored)
    if detailed == "core_system":
        return "system"
    if detailed == "system_service":
        return "system"
    if detailed == "third_party_service":
        return "service"
    return "user"


def _operation_level(category: str) -> str:
    """Return the operation policy for a process category."""
    return {
        "core_system": "view_only",
        "system_service": "terminate_with_confirm",
        "third_party_service": "terminate_with_confirm",
        "user_process": "full",
    }.get(category, "full")


def _operation_level_from_legacy(category: str, is_system: bool) -> str:
    """Derive operation level from legacy category/is_system fields."""
    if is_system or category == "system":
        return "view_only"
    if category == "service":
        return "terminate_with_confirm"
    return "full"


def _match_blacklist(name: str, blacklist: list[dict]) -> dict | None:
    """Return the first matching blacklist rule for a process name."""
    root = _normalize_name(name)
    if not root or not blacklist:
        return None
    for rule in blacklist:
        pattern = _normalize_name(rule.get("pattern", ""))
        if not pattern:
            continue
        match_type = (rule.get("match_type") or "contains").lower()
        if match_type == "exact" and root == pattern:
            return rule
        if match_type == "contains" and pattern in root:
            return rule
        if match_type == "startswith" and root.startswith(pattern):
            return rule
        if match_type == "endswith" and root.endswith(pattern):
            return rule
        if match_type == "regex":
            try:
                import re
                if re.search(pattern, name, re.IGNORECASE):
                    return rule
            except Exception:
                continue
    return None


def _terminate_process(pid: int | None, name: str, mode: str) -> dict:
    """Terminate a process by PID or name. Returns result dict."""
    targets = []
    pid_stale = False
    if pid and pid > 0:
        try:
            p = psutil.Process(pid)
            proc_name = p.name()
            if name and _normalize_name(proc_name) != _normalize_name(name):
                pid_stale = True
            else:
                targets.append(p)
        except psutil.NoSuchProcess:
            pid_stale = True
        except psutil.AccessDenied:
            return {"killed": [], "errors": [f"PID {pid} 访问被拒绝"], "found": 0}

    # Fall back to name matching when PID is missing/stale or name is the only hint.
    if (pid_stale or not targets) and name:
        n = _normalize_name(name)
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if _normalize_name(proc.info.get("name", "")) == n:
                    targets.append(psutil.Process(proc.info["pid"]))
            except Exception:
                continue

    killed = []
    errors = []
    for p in targets:
        try:
            if mode == "force":
                p.kill()
            else:
                p.terminate()
            killed.append(p.pid)
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            errors.append(f"PID {p.pid} 访问被拒绝（需要管理员权限）")
        except Exception as e:
            errors.append(str(e))
    return {
        "killed": killed,
        "errors": errors,
        "found": len(targets),
    }


def execute_terminate_tasks(tasks: list[dict]) -> list[dict]:
    """Execute pending terminate tasks from the server."""
    results = []
    if not tasks:
        return results
    for task in tasks:
        tid = task.get("id", "")
        pid = int(task.get("pid") or 0) or None
        name = task.get("name", "")
        mode = task.get("mode", "graceful")
        res = _terminate_process(pid, name, mode)
        results.append({
            "id": tid,
            "pid": pid,
            "name": name,
            "mode": mode,
            "success": len(res["killed"]) > 0,
            "killed": res["killed"],
            "errors": res["errors"],
        })
    return results


def enforce_blacklist(blacklist: list[dict]) -> list[dict]:
    """Find running processes matching the blacklist and force-kill them."""
    killed = []
    if not blacklist:
        return killed
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = proc.info.get("name", "")
            rule = _match_rule(name, blacklist)
            if rule:
                pid = proc.info["pid"]
                res = _terminate_process(pid, "", "force")
                if res["killed"]:
                    killed.append({
                        "pid": pid,
                        "name": name,
                        "rule_id": rule.get("id", ""),
                        "pattern": rule.get("pattern", ""),
                    })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return killed


def _match_rule(name: str, rules: list[dict]) -> dict | None:
    """Return the first matching rule for a process name/image name.

    Rules use the same fields as blacklist entries: ``pattern`` and
    ``match_type`` (contains / exact / startswith / endswith / regex).
    """
    if not name or not rules:
        return None
    root = _normalize_name(name)
    for rule in rules:
        pattern = _normalize_name(rule.get("pattern", ""))
        if not pattern:
            continue
        match_type = (rule.get("match_type") or "contains").lower()
        matched = False
        if match_type == "exact" and root == pattern:
            matched = True
        elif match_type == "contains" and pattern in root:
            matched = True
        elif match_type == "startswith" and root.startswith(pattern):
            matched = True
        elif match_type == "endswith" and root.endswith(pattern):
            matched = True
        elif match_type == "regex":
            try:
                import re
                if re.search(pattern, name, re.IGNORECASE):
                    matched = True
            except Exception:
                continue
        if matched:
            return rule
    return None


def _match_targets(proc_name: str, pid: int, pid_ports: dict, targets: list[dict]) -> dict | None:
    """Return the first matching monitored-service target for a process.

    Configured targets are checked first so existing MonitoredService records
    keep their stable service id. If no configured target matches, every
    process (including system processes) is still considered discoverable;
    filtering is applied later by the caller using whitelist/blacklist rules.
    """
    root = _normalize_name(proc_name)
    ports = pid_ports.get(pid, [])

    for t in targets:
        if t["port"] and t["port"] in ports:
            return t
        for n in t["names"]:
            if n and (root == n or root.endswith("/" + n)):
                return t
    return None




def _windows_display_version() -> tuple[str, str]:
    """Return friendly Windows name and build.revision (e.g. Windows 11, 26200.8875)."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            product = str(winreg.QueryValueEx(key, "ProductName")[0])
            build = str(winreg.QueryValueEx(key, "CurrentBuildNumber")[0])
            ubr = winreg.QueryValueEx(key, "UBR")[0]
        parts = product.split()
        if len(parts) >= 2 and parts[0] == "Windows":
            if parts[1] == "Server" and len(parts) >= 3:
                name = f"Windows Server {parts[2]}"
            else:
                name = f"Windows {parts[1]}"
                # 该字段），必须按 CurrentBuildNumber >= 22000 才能识别 Win11。
                # Server SKU 的 ProductName 是准的，不受影响。
                try:
                    if int(build) >= 22000 and name == "Windows 10":
                        name = "Windows 11"
                except ValueError:
                    pass
        else:
            name = product
        return name, f"{build}.{ubr}"
    except Exception:
        return f"Windows {platform.release()}", platform.version()


def get_os_info() -> dict:
    if sys.platform == "win32":
        os_type, os_version = _windows_display_version()
    else:
        os_type = f"{platform.system()} {platform.release()}"
        os_version = platform.version()
    return {
        "os_type": os_type,
        "os_version": os_version,
        "architecture": platform.machine(),
        "hostname": socket.gethostname(),
        "ip_address": _primary_ip(),
    }


def _primary_ip() -> str:
    """Return the best routable IPv4 address, avoiding loopback and APIPA.

    Priority:
      1. Private RFC1918 address on an interface that has traffic.
      2. Any private RFC1918 address.
      3. Any non-loopback, non-link-local routable address.
    """
    import ipaddress

    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    try:
        io = psutil.net_io_counters(pernic=True) or {}
    except Exception:
        io = {}

    candidates = []
    for name, addr_list in addrs.items():
        st = stats.get(name)
        if st and not st.isup:
            continue
        nic_io = io.get(name)
        has_traffic = nic_io is not None and (nic_io.bytes_sent + nic_io.bytes_recv) > 0
        for addr in addr_list:
            if addr.family != socket.AF_INET:
                continue
            ip = addr.address
            if not ip or ip.startswith("127.") or ip.startswith("169.254."):
                continue
            try:
                net = ipaddress.ip_network(f"{ip}/{addr.netmask}", strict=False)
            except Exception:
                continue
            candidates.append({
                "ip": ip,
                "is_private": net.is_private,
                "has_traffic": has_traffic,
            })

    for c in candidates:
        if c["is_private"] and c["has_traffic"]:
            return c["ip"]
    for c in candidates:
        if c["is_private"]:
            return c["ip"]
    if candidates:
        return candidates[0]["ip"]
    return "0.0.0.0"


def sample_system_metrics(sample_seconds: float = 1.0) -> dict:
    """Sample system CPU / memory / disk / network with one sleep.

    Non-intrusive: no shell commands, no WMI.
    """
    mem_before = psutil.virtual_memory()
    disk_before = psutil.disk_io_counters() or psutil._common.sdiskio(0, 0, 0, 0, 0, 0, 0, 0)
    net_before = psutil.net_io_counters()

    psutil.cpu_percent(interval=None)
    time.sleep(sample_seconds)

    cpu_percent = psutil.cpu_percent(interval=None)
    mem_after = psutil.virtual_memory()
    disk_after = psutil.disk_io_counters() or disk_before
    net_after = psutil.net_io_counters()

    dt = max(sample_seconds, 0.1)
    disk_read_mbps = max(0.0, (disk_after.read_bytes - disk_before.read_bytes) / (1024 * 1024) / dt)
    disk_write_mbps = max(0.0, (disk_after.write_bytes - disk_before.write_bytes) / (1024 * 1024) / dt)
    network_in_mbps = max(0.0, (net_after.bytes_recv - net_before.bytes_recv) * 8 / (1024 * 1024) / dt)
    network_out_mbps = max(0.0, (net_after.bytes_sent - net_before.bytes_sent) * 8 / (1024 * 1024) / dt)

    try:
        tcp_connections = len(psutil.net_connections(kind="tcp"))
    except (psutil.AccessDenied, OSError):
        tcp_connections = 0

    partitions = []
    for p in psutil.disk_partitions():
        if "cdrom" in (p.opts or "").lower():
            continue
        try:
            usage = psutil.disk_usage(p.mountpoint)
            partitions.append({
                "name": p.device,
                "mount": p.mountpoint,
                "fstype": p.fstype,
                "total_gb": round(usage.total / (1024 ** 3), 1),
                "used_gb": round(usage.used / (1024 ** 3), 1),
                "free_gb": round(usage.free / (1024 ** 3), 1),
                "percent": usage.percent,
            })
        except (PermissionError, FileNotFoundError):
            continue

    return {
        "cpu_cores": psutil.cpu_count(logical=True) or 0,
        "cpu_physical_cores": psutil.cpu_count(logical=False) or 0,
        "cpu_model": _get_cpu_model(),
        "cpu_percent": round(cpu_percent, 1),
        "total_memory_gb": round(mem_after.total / (1024 ** 3), 1),
        "memory_percent": round(mem_after.percent, 1),
        "memory_used_gb": round(mem_after.used / (1024 ** 3), 1),
        "disk_percent": max((d["percent"] for d in partitions), default=0),
        "disk_read_mbps": round(disk_read_mbps, 3),
        "disk_write_mbps": round(disk_write_mbps, 3),
        "network_in_mbps": round(network_in_mbps, 3),
        "network_out_mbps": round(network_out_mbps, 3),
        "tcp_connections": tcp_connections,
        "disk_partitions": partitions,
    }




def sample_process_metrics(
    monitored_services: list[dict] | None = None,
    sample_seconds: float = 1.0,
    whitelist: list[dict] | None = None,
    blacklist: list[dict] | None = None,
) -> list[dict]:
    """Collect non-intrusive metrics for **all** visible processes.

    This follows the industry-standard "full collection + whitelist/blacklist
    filtering" model. The agent enumerates every process it can see (including
    system processes) and tags each entry with a ``category`` of ``system``,
    ``user`` or ``service``. The server and UI decide what to display.

    ``monitored_services`` item: {"id": int, "name": str, "image_name": str,
                                  "process_name": str, "port": int}

    Returns metric dicts matching the backend ``MonitoredService`` fields plus
    ``category``, ``is_system``, ``detailed_category`` and ``operation_level``.
    """
    targets = []
    if monitored_services:
        for m in monitored_services:
            names = set()
            for key in ("image_name", "process_name", "name"):
                n = _normalize_name(m.get(key, ""))
                if n:
                    names.add(n)
            targets.append({
                "id": m.get("id"),
                "names": list(names),
                "port": int(m.get("port") or 0),
            })

    pid_ports = _pid_ports()
    cpu_count = psutil.cpu_count(logical=True) or 1
    now = time.time()

    snapshots: dict[int, dict] = {}
    access_denied_pids: set[int] = set()
    for proc in psutil.process_iter(["pid", "name", "exe", "status", "username"]):
        pid = proc.info["pid"]
        name = proc.info["name"] or ""
        target = _match_targets(name, pid, pid_ports, targets)

        if target is None:
            if whitelist and not _match_rule(name, whitelist):
                continue
            if _match_rule(name, blacklist or []):
                continue

        username = proc.info.get("username")
        exe = proc.info.get("exe") or ""
        path = os.path.dirname(exe) if exe else ""
        detailed_category = _proc_detailed_category(
            name, path=path, username=username, is_monitored=(target is not None)
        )
        category = _proc_category(
            name, path=path, username=username, is_monitored=(target is not None)
        )
        operation_level = _operation_level(detailed_category)

        try:
            p = psutil.Process(pid)
            try:
                exe = p.exe() or exe
                path = os.path.dirname(exe) if exe else path
            except (psutil.AccessDenied, OSError):
                pass

            with p.oneshot():
                try:
                    p.cpu_percent(interval=None)
                except (psutil.AccessDenied, OSError):
                    pass
                try:
                    mem = p.memory_percent()
                except (psutil.AccessDenied, OSError):
                    mem = 0.0
                try:
                    mem_info = p.memory_info()
                    mem_used_bytes = mem_info.rss
                except (psutil.AccessDenied, OSError):
                    mem_used_bytes = 0
                try:
                    io = p.io_counters()
                    read_bytes = io.read_bytes
                    write_bytes = io.write_bytes
                except (psutil.AccessDenied, OSError):
                    read_bytes = write_bytes = 0
                net_recv, net_sent, net_total = _proc_io_net_bytes_split(pid)
                try:
                    start_time = datetime.fromtimestamp(p.create_time(), tz=timezone.utc).isoformat()
                except (psutil.AccessDenied, OSError):
                    start_time = ""
                try:
                    cmdline = " ".join(p.cmdline() or [])
                except (psutil.AccessDenied, OSError):
                    cmdline = ""
                try:
                    ppid = p.ppid()
                except (psutil.AccessDenied, OSError):
                    ppid = 0

            display_name = _file_description(exe) or name.replace(".exe", "")
            snapshots[pid] = {
                "service_id": target["id"] if target else pid,
                "name": display_name,
                "image_name": name,
                "pid": pid,
                "port": target.get("port", 0) or 0 if target else (pid_ports.get(pid, [0]) or [0])[0],
                "path": path,
                "category": category,
                "is_system": category == "system",
                "detailed_category": detailed_category,
                "operation_level": operation_level,
                "time": now,
                "process": p,
                "access_denied": False,
                "memory_percent": mem,
                "memory_used_bytes": mem_used_bytes,
                "read_bytes": read_bytes,
                "write_bytes": write_bytes,
                "net_recv_bytes": net_recv,
                "net_sent_bytes": net_sent,
                "net_bytes": net_total,
                "start_time": start_time,
                "cmdline": cmdline,
                "username": username,
                "ppid": ppid,
                "has_visible_window": _has_visible_window(pid),
                "app_instance_id": _compute_app_instance_id(name, exe, cmdline),
            }
        except psutil.NoSuchProcess:
            continue
        except (psutil.AccessDenied, OSError):
            access_denied_pids.add(pid)
            snapshots[pid] = {
                "service_id": target["id"] if target else pid,
                "name": name.replace(".exe", ""),
                "image_name": name,
                "pid": pid,
                "port": target.get("port", 0) or 0 if target else (pid_ports.get(pid, [0]) or [0])[0],
                "path": path,
                "category": category,
                "is_system": category == "system",
                "detailed_category": detailed_category,
                "operation_level": operation_level,
                "time": now,
                "process": None,
                "access_denied": True,
                "memory_percent": 0.0,
                "memory_used_bytes": 0,
                "read_bytes": 0,
                "write_bytes": 0,
                "net_recv_bytes": 0,
                "net_sent_bytes": 0,
                "net_bytes": 0,
                "start_time": "",
                "cmdline": "",
                "username": username,
                "ppid": 0,
                "has_visible_window": False,
                "app_instance_id": _compute_app_instance_id(name, exe, ""),
            }

    if not snapshots:
        return []

    time.sleep(sample_seconds)

    results: list[dict] = []
    dt = max(sample_seconds, 0.1)
    for pid, s1 in snapshots.items():
        if s1.get("access_denied") or s1["process"] is None:
            results.append({
                "service_id": s1["service_id"],
                "name": s1["name"],
                "image_name": s1["image_name"],
                "pid": s1["pid"],
                "port": s1["port"],
                "path": s1["path"],
                "category": s1["category"],
                "is_system": s1["is_system"],
                "detailed_category": s1.get("detailed_category", s1["category"]),
                "operation_level": s1.get("operation_level", _operation_level_from_legacy(s1["category"], s1["is_system"])),
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "memory_used_mb": 0.0,
                "disk_read_mbps": 0.0,
                "disk_write_mbps": 0.0,
                "disk_mbps": 0.0,
                "network_in_mbps": 0.0,
                "network_out_mbps": 0.0,
                "network_mbps": 0.0,
                "alive_status": "running",
                "status": "running",
                "start_time": s1.get("start_time", ""),
                "cmdline": s1.get("cmdline", ""),
                "username": s1.get("username", ""),
                "ppid": s1.get("ppid", 0),
            })
            continue

        try:
            p = s1["process"]
            with p.oneshot():
                try:
                    cpu = p.cpu_percent(interval=None) / cpu_count
                    if cpu > 100.0:
                        cpu = 100.0
                except (psutil.AccessDenied, OSError):
                    cpu = 0.0
                try:
                    mem = p.memory_percent()
                except (psutil.AccessDenied, OSError):
                    mem = 0.0
                try:
                    io = p.io_counters()
                    write_delta = max(0, io.write_bytes - s1["write_bytes"])
                    read_delta = max(0, io.read_bytes - s1["read_bytes"])
                except (psutil.AccessDenied, OSError):
                    write_delta = read_delta = 0
                net_recv, net_sent, net_total = _proc_io_net_bytes_split(pid)
                net_recv_delta = max(0, net_recv - s1["net_recv_bytes"])
                net_sent_delta = max(0, net_sent - s1["net_sent_bytes"])

            disk_read_mbps = read_delta / (1024 * 1024) / dt
            disk_write_mbps = write_delta / (1024 * 1024) / dt
            disk_total_mbps = disk_read_mbps + disk_write_mbps
            network_in_mbps = net_recv_delta * 8 / (1024 * 1024) / dt
            network_out_mbps = net_sent_delta * 8 / (1024 * 1024) / dt
            network_total_mbps = (net_recv_delta + net_sent_delta) * 8 / (1024 * 1024) / dt

            results.append({
                "service_id": s1["service_id"],
                "name": s1["name"],
                "image_name": s1["image_name"],
                "pid": s1["pid"],
                "port": s1["port"],
                "path": s1["path"],
                "category": s1["category"],
                "is_system": s1["is_system"],
                "detailed_category": s1.get("detailed_category", s1["category"]),
                "operation_level": s1.get("operation_level", _operation_level_from_legacy(s1["category"], s1["is_system"])),
                "cpu_percent": round(cpu, 1),
                "memory_percent": round(mem, 2),
                "memory_used_mb": round(s1.get("memory_used_bytes", 0) / (1024 * 1024), 1),
                "disk_read_mbps": round(disk_read_mbps, 3),
                "disk_write_mbps": round(disk_write_mbps, 3),
                "disk_mbps": round(disk_total_mbps, 3),
                "network_in_mbps": round(network_in_mbps, 3),
                "network_out_mbps": round(network_out_mbps, 3),
                "network_mbps": round(network_total_mbps, 3),
                "alive_status": "running",
                "status": "running",
                "start_time": s1.get("start_time", ""),
                "cmdline": s1.get("cmdline", ""),
                "username": s1.get("username", ""),
                "ppid": s1.get("ppid", 0),
                "has_visible_window": bool(s1.get("has_visible_window", False)),
                "app_instance_id": s1.get("app_instance_id", s1["image_name"]),
            })
        except psutil.NoSuchProcess:
            continue
        except (psutil.AccessDenied, OSError):
            results.append({
                "service_id": s1["service_id"],
                "name": s1["name"],
                "image_name": s1["image_name"],
                "pid": s1["pid"],
                "port": s1["port"],
                "path": s1["path"],
                "category": s1["category"],
                "is_system": s1["is_system"],
                "detailed_category": s1.get("detailed_category", s1["category"]),
                "operation_level": s1.get("operation_level", _operation_level_from_legacy(s1["category"], s1["is_system"])),
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "memory_used_mb": 0.0,
                "disk_read_mbps": 0.0,
                "disk_write_mbps": 0.0,
                "disk_mbps": 0.0,
                "network_in_mbps": 0.0,
                "network_out_mbps": 0.0,
                "network_mbps": 0.0,
                "alive_status": "running",
                "status": "running",
                "start_time": s1.get("start_time", ""),
                "cmdline": s1.get("cmdline", ""),
                "username": s1.get("username", ""),
                "ppid": s1.get("ppid", 0),
                "has_visible_window": bool(s1.get("has_visible_window", False)),
                "app_instance_id": s1.get("app_instance_id", s1["image_name"]),
            })

    max_procs = 300
    if len(results) > max_procs:
        results.sort(
            key=lambda r: (
                0 if r.get("category") == "service" else 1,
                -(r.get("memory_percent", 0) + r.get("cpu_percent", 0)),
            )
        )
        results = results[:max_procs]

    return results


def list_all_processes() -> list[dict]:
    """Return a lightweight raw list of all visible processes.

    Used for remote diagnostics and backward compatibility. Includes PID, raw
    process name, executable path, current status, category, operation level,
    plus start time, command line, owner and parent PID. System processes are
    included so the server can build a complete snapshot.
    """
    results = []
    for proc in psutil.process_iter(["pid", "name", "exe", "status", "username"]):
        try:
            pid = proc.info["pid"]
            name = proc.info["name"] or ""
            exe = proc.info.get("exe") or ""
            path = os.path.dirname(exe) if exe else ""
            username = proc.info.get("username")
            detailed_category = _proc_detailed_category(name, path=path, username=username)
            category = _proc_category(name, path=path, username=username)
            p = psutil.Process(pid)
            try:
                start_time = datetime.fromtimestamp(p.create_time(), tz=timezone.utc).isoformat()
            except (psutil.AccessDenied, OSError):
                start_time = ""
            try:
                cmdline = " ".join(p.cmdline() or [])
            except (psutil.AccessDenied, OSError):
                cmdline = ""
            try:
                ppid = p.ppid()
            except (psutil.AccessDenied, OSError):
                ppid = 0
            results.append({
                "pid": pid,
                "name": name,
                "image_name": name,
                "path": exe,
                "status": str(proc.info.get("status") or "unknown"),
                "category": category,
                "is_system": category == "system",
                "detailed_category": detailed_category,
                "operation_level": _operation_level(detailed_category),
                "start_time": start_time,
                "cmdline": cmdline,
                "username": username,
                "ppid": ppid,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return results


def collect_all_v2(
    monitored_services: list[dict] | None = None,
    sample_seconds: float = 1.0,
    whitelist: list[dict] | None = None,
    blacklist: list[dict] | None = None,
    pending_terminate: list[dict] | None = None,
    debug_raw_processes: bool = False,
) -> dict:
    """Full non-intrusive collection payload for the agent push endpoint.

    Collects **all** visible processes (system + user + configured services),
    applies whitelist/blacklist filtering, executes server-queued terminate
    tasks and enforces the service blacklist by force-killing matching
    processes.
    """
    now = datetime.now(timezone.utc).isoformat()
    os_info = get_os_info()
    sys_metrics = sample_system_metrics(sample_seconds=sample_seconds)
    service_metrics = sample_process_metrics(
        monitored_services,
        sample_seconds=sample_seconds,
        whitelist=whitelist,
        blacklist=blacklist,
    )

    terminate_results = execute_terminate_tasks(pending_terminate or [])

    blacklist_killed = enforce_blacklist(blacklist or [])

    return {
        "timestamp": now,
        "hostname": os_info["hostname"],
        "ip_address": os_info["ip_address"],
        "os_type": os_info["os_type"],
        "os_version": os_info["os_version"],
        "architecture": os_info["architecture"],
        "cpu_model": sys_metrics["cpu_model"],
        "cpu_cores": sys_metrics["cpu_cores"],
        "cpu_physical_cores": sys_metrics["cpu_physical_cores"],
        "total_memory_gb": sys_metrics["total_memory_gb"],
        "disk_partitions": sys_metrics["disk_partitions"],
        "total_disk_gb": round(sum(d["total_gb"] for d in sys_metrics["disk_partitions"]), 1),
        "metrics": {
            "timestamp": now,
            "cpu_percent": sys_metrics["cpu_percent"],
            "memory_percent": sys_metrics["memory_percent"],
            "memory_used_gb": sys_metrics["memory_used_gb"],
            "disk_percent": sys_metrics["disk_percent"],
            "disk_used_gb": round(
                sum(d["total_gb"] for d in sys_metrics["disk_partitions"])
                * sys_metrics["disk_percent"] / 100, 1
            ) if sys_metrics["disk_partitions"] else 0,
            "network_in_mbps": sys_metrics["network_in_mbps"],
            "network_out_mbps": sys_metrics["network_out_mbps"],
            "disk_io_read_mbps": sys_metrics["disk_read_mbps"],
            "disk_io_write_mbps": sys_metrics["disk_write_mbps"],
            "tcp_connections": sys_metrics["tcp_connections"],
            "total_memory_gb": sys_metrics["total_memory_gb"],
            "cpu_cores": sys_metrics["cpu_cores"],
        },
        "service_metrics": service_metrics,
        "services": [],
        "dangerous_ports": [],
        "terminate_results": terminate_results,
        "blacklist_killed": blacklist_killed,
        "raw_processes": list_all_processes() if debug_raw_processes else None,
    }
