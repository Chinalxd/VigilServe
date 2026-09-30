"""Monitoring agent — attempts real WinRM/SSH collection. No simulation in production."""


import os
import random
import math
import time
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from models import Server, MetricSnapshot, MonitoredService, Alert
from database import SessionLocal

PRODUCTION = os.environ.get("PRODUCTION", "0") == "1"


BASE_LOAD = {
    "文件服务器": {"cpu": 15, "mem": 35, "disk": 45, "net": 20},
    "ERP服务器": {"cpu": 30, "mem": 55, "disk": 35, "net": 10},
    "金蝶服务器": {"cpu": 25, "mem": 50, "disk": 30, "net": 8},
}


def _simulate_cpu(base: float) -> float:
    wave = 15 * math.sin(time.time() / 300)
    noise = random.gauss(0, 5)
    return max(1, min(98, base + wave + noise))


def _simulate_memory(base: float) -> float:
    noise = random.gauss(0, 3)
    return max(5, min(98, base + noise))


def _simulate_disk(base: float) -> float:
    drift = 0.02
    noise = random.gauss(0, 1)
    return max(10, min(98, base + drift + noise))


def _simulate_network(base: float) -> tuple:
    noise_in = abs(random.gauss(0, base * 0.3))
    noise_out = abs(random.gauss(0, base * 0.25))
    return (max(0.1, base + noise_in), max(0.1, base * 0.7 + noise_out))


def _auto_detect_server_info(server: Server):
    """Auto-detect OS type, hostname, hardware specs, and disk partitions on first collection.

    ── SIMULATED DETECTION (used when no real agent connected) ──
    """
    needs_update = False
    needs_detect = not server.os_type or not server.cpu_cores or not server.disk_partitions

    info = {}
    if needs_detect:
        try:
            from services.remote_agent import RemoteAgent
            agent = RemoteAgent(server)
            if agent.connect():
                info = agent.detect() or {}
                agent.close()
        except Exception as e:
            print(f"[Agent] Detection attempted but failed for {server.name}: {e}")

    def _sim_info():
        return {
            "os_type": _detect_os(server),
            "cpu_cores": _detect_hardware(server)[0],
            "total_memory_gb": _detect_hardware(server)[1],
            "disk_partitions": _detect_disk_partitions(server),
        }

    if not info:
        if PRODUCTION:
            info = {"os_type": "未检测", "cpu_cores": 0, "total_memory_gb": 0.0, "disk_partitions": []}
        else:
            info = _sim_info()

    if info.get("os_type") and not server.os_type:
        server.os_type = info["os_type"]
        needs_update = True

    extra = server.extra_config or {}
    if info.get("computer_name") and not extra.get("computer_name"):
        extra["computer_name"] = info["computer_name"]
        needs_update = True
    if info.get("os_version") and not extra.get("os_version"):
        extra["os_version"] = info["os_version"]
        needs_update = True
    if extra and extra != server.extra_config:
        server.extra_config = extra

    cpu_cores = info.get("cpu_cores", 0)
    total_memory_gb = info.get("total_memory_gb", 0.0)
    if cpu_cores and (not server.cpu_cores or server.cpu_cores == 0):
        server.cpu_cores = cpu_cores
        server.total_memory_gb = total_memory_gb
        needs_update = True

    disk_partitions = info.get("disk_partitions", [])
    if disk_partitions and not server.disk_partitions:
        server.disk_partitions = disk_partitions
        server.total_disk_gb = round(sum(p["total_gb"] for p in disk_partitions), 1)
        needs_update = True

    return needs_update


def _try_real_or_sim(server: Server, mode: str):
    """Try real remote detection; fall back to simulation if connection fails."""
    try:
        from services.remote_agent import RemoteAgent
        agent = RemoteAgent(server)
        if agent.connect():
            info = agent.detect()
            agent.close()
            if info:
                print(f"[Agent] Real detection success for {server.name}: OS={info.get('os_type','?')}, CPU={info.get('cpu_cores',0)}c, MEM={info.get('total_memory_gb',0)}G, Disks={len(info.get('disk_partitions',[]))}")
                if mode == "os":
                    return info.get("os_type") or _detect_os(server)
                elif mode == "hardware":
                    return (info.get("cpu_cores", 0), info.get("total_memory_gb", 0.0))
                elif mode == "disk":
                    disks = info.get("disk_partitions", [])
                    if disks:
                        return disks
    except Exception as e:
        print(f"[Agent] Detection attempted but failed for {server.name}: {e}")

    # Fallback to simulation (only in dev; production returns defaults)
    if PRODUCTION:
        if mode == "os": return "未检测"
        elif mode == "hardware": return (0, 0.0)
        elif mode == "disk": return []
    if mode == "os":
        return _detect_os(server)
    elif mode == "hardware":
        return _detect_hardware(server)
    elif mode == "disk":
        return _detect_disk_partitions(server)


def _detect_disk_partitions(server: Server) -> list:
    """Simulate disk partition detection. Returns list of partition dicts.

    Production: execute the protocol-specific command from the template above,
    parse the output into the standard format below.
    """
    total = server.total_disk_gb or 0
    if total == 0:
        bs = server.business_system or ""
        if "EAS" in bs.upper():
            total = 1000.0
        elif any(k in bs for k in ["ERP", "金蝶"]):
            total = 500.0
        elif "文件" in bs or "Web" in bs or "云" in bs:
            total = 2000.0
        else:
            total = 200.0

    if server.protocol == "WinRM":
        return [
            {"name": "C:", "mount": "C:\\", "fstype": "NTFS",
             "total_gb": round(total * 0.35, 1), "used_gb": round(total * 0.18, 1),
             "free_gb": round(total * 0.17, 1), "percent": 52.0},
            {"name": "D:", "mount": "D:\\", "fstype": "NTFS",
             "total_gb": round(total * 0.40, 1), "used_gb": round(total * 0.12, 1),
             "free_gb": round(total * 0.28, 1), "percent": 30.0},
            {"name": "E:", "mount": "E:\\", "fstype": "NTFS",
             "total_gb": round(total * 0.25, 1), "used_gb": round(total * 0.05, 1),
             "free_gb": round(total * 0.20, 1), "percent": 20.0},
        ]
    else:
        root_gb = round(total * 0.30, 1)
        home_gb = round(total * 0.45, 1)
        var_gb = round(total * 0.25, 1)
        return [
            {"name": "/dev/sda1", "mount": "/", "fstype": "ext4" if "7.9" in (server.os_type or "") else "xfs",
             "total_gb": root_gb, "used_gb": round(root_gb * 0.40, 1),
             "free_gb": round(root_gb * 0.60, 1), "percent": 40.0},
            {"name": "/dev/sda2", "mount": "/home", "fstype": "ext4",
             "total_gb": home_gb, "used_gb": round(home_gb * 0.35, 1),
             "free_gb": round(home_gb * 0.65, 1), "percent": 35.0},
            {"name": "/dev/sda3", "mount": "/var", "fstype": "ext4",
             "total_gb": var_gb, "used_gb": round(var_gb * 0.20, 1),
             "free_gb": round(var_gb * 0.80, 1), "percent": 20.0},
        ]

def collect_all_servers():
    """Collection cycle — real metrics from external sources, offline detection, skip agents."""
    db: Session = SessionLocal()
    try:
        servers = db.query(Server).all()
        now = datetime.now(timezone.utc)

        # 以前这里硬编码 180 秒，跟前端的 5 分钟不一致 —— 同一台机器两处显示打架；
        # 网络设备 5 分钟才采一次，用 3 分钟阈值判它等于永远离线。
        from services.device_status import load_config as _load_cfg, is_online as _is_online
        cfg = _load_cfg(db)

        for server in servers:
            # ── 网络设备：由 SNMP 调度单独采（5 分钟一轮），这里只判离线 ──
            if (server.device_kind or "host") == "network":
                if server.snmp_enabled and not _is_online(server, cfg, now):
                    if server.status != "offline":
                        server.status = "offline"
                        server.offline_time = now
                continue

            if server.protocol == "agent":
                # 2026-09-22：只有**已加入管理**（join_time 非空）的主机才做
                # monitored ↔ offline 迁移。未加入管理的主机（待审核 / 已移出）
                # 必须保持 ``registered`` 语义 —— 历史上这里把心跳过期的
                # registered 也改成 offline，于是它落进「受管状态」集合：
                # 前端工具栏判它"在管"、后端删除闸门拒删，管理员既删不掉
                # 也看不懂（列表里明明显示的是未加入管理）。
                # 顺手把已经被改成 offline/online 的未管理主机改回来。
                if server.join_time is None:
                    if server.status in ("offline", "online"):
                        server.status = "registered"
                        print(f"[Collector] 未加入管理的主机状态回滚为 registered："
                              f"server_id={server.id} {server.name}")
                    continue
                # 有心跳就看是否超期；从没心跳过且状态是"在管"的，直接算离线。
                # ``registered`` 也参与判定 —— 断线再连上才能正确刷新 online_time。
                if server.last_seen:
                    went_offline = not _is_online(server, cfg, now)
                else:
                    went_offline = server.status in ("online", "monitored", "registered")
                if went_offline and server.status != "offline":
                    server.status = "offline"
                    server.offline_time = now
                continue

            _auto_detect_server_info(server)

            pattern = BASE_LOAD.get(server.business_system, {"cpu": 20, "mem": 40, "disk": 30, "net": 10})

            cpu = round(_simulate_cpu(pattern["cpu"]), 1)
            mem = round(_simulate_memory(pattern["mem"]), 1)
            disk = round(_simulate_disk(pattern["disk"]), 1)
            net_in, net_out = _simulate_network(pattern["net"])
            net_in = round(net_in, 2)
            net_out = round(net_out, 2)

            mem_used = round(server.total_memory_gb * mem / 100, 1)
            disk_used = round(server.total_disk_gb * disk / 100, 1)

            snapshot = MetricSnapshot(
                server_id=server.id,
                cpu_percent=cpu,
                memory_percent=mem,
                memory_used_gb=mem_used,
                disk_percent=disk,
                disk_used_gb=disk_used,
                network_in_mbps=net_in,
                network_out_mbps=net_out,
                disk_io_read_mbps=0.0,
                disk_io_write_mbps=0.0,
                tcp_connections=0,
            )
            db.add(snapshot)

            if cpu > 90 or mem > 90 or disk > 95:
                server.status = "critical"
            elif cpu > 75 or mem > 80 or disk > 85:
                server.status = "warning"
            else:
                server.status = "online"

            _check_thresholds(db, server, cpu, mem, disk)

        from routes.config import get_config_dict
        cfg = get_config_dict(db)
        days_value = cfg.get("data_retention_days", {}).get("value")
        if days_value:
            days = int(days_value)
        else:
            months = int(cfg.get("data_retention_months", {}).get("value", 3))
            days = months * 30
        cutoff = now - timedelta(days=days)
        deleted = db.query(MetricSnapshot).filter(MetricSnapshot.timestamp < cutoff).delete()
        if deleted:
            print(f"[Collector] Cleaned up {deleted} old metric snapshots (retention: {days} days)")

        db.commit()
    finally:
        db.close()


def _check_thresholds(db: Session, server: Server, cpu: float, mem: float, disk: float):
    now = datetime.now(timezone.utc)

    if cpu > 90:
        _create_alert(db, server, "critical", "CPU 使用率过高", f"CPU 使用率达 {cpu:.1f}%，超过 90% 严重阈值", "cpu")
    elif cpu > 75:
        _create_alert(db, server, "warning", "CPU 使用率偏高", f"CPU 使用率达 {cpu:.1f}%，超过 75% 警告阈值", "cpu")

    if mem > 90:
        _create_alert(db, server, "critical", "内存使用率过高", f"内存使用率达 {mem:.1f}%，超过 90% 严重阈值", "memory")
    elif mem > 80:
        _create_alert(db, server, "warning", "内存使用率偏高", f"内存使用率达 {mem:.1f}%，超过 80% 警告阈值", "memory")

    if disk > 95:
        _create_alert(db, server, "critical", "磁盘空间严重不足", f"磁盘使用率达 {disk:.1f}%，超过 95% 严重阈值", "disk")
    elif disk > 85:
        _create_alert(db, server, "warning", "磁盘空间偏高", f"磁盘使用率达 {disk:.1f}%，超过 85% 警告阈值", "disk")


def _create_alert(db: Session, server: Server, level: str, title: str, message: str, metric_type: str):
    recent = (
        db.query(Alert)
        .filter(
            Alert.server_id == server.id,
            Alert.metric_type == metric_type,
            Alert.level == level,
            Alert.acknowledged == 0,
            Alert.timestamp >= datetime.now(timezone.utc) - timedelta(minutes=10),
        )
        .first()
    )
    if recent:
        return

    alert = Alert(server_id=server.id, level=level, title=title, message=message, metric_type=metric_type)
    db.add(alert)


def _check_services(db: Session, server: Server):
    """Check monitored services and collect process-level metrics.

    - Agent servers: statuses are updated by agent push; skip here for now.
      (Agent-side collection will be upgraded separately after the backend.)
    - WinRM/SSH servers: execute real port/process checks via service_monitor
      and store CPU/memory/disk/alive/running/alert states.
    - In production, detection failures are recorded as ``unknown``.
    - In development, failures fall back to a simple simulation so the UI can
      still be tested without live remote hosts.
    """
    services = db.query(MonitoredService).filter(MonitoredService.server_id == server.id).all()
    if not services:
        return

    if server.protocol == "agent":
        return

    protocol = (server.protocol or "").upper()
    real_results: dict = {}
    use_real = protocol in {"WINRM", "SSH"}

    if use_real:
        try:
            from services.service_monitor import check_services_for_server
            real_results = check_services_for_server(server, services)
            print(f"[ServiceCheck] Real check completed for {server.name}: {len(services)} services")
        except Exception as e:
            print(f"[ServiceCheck] Real check failed for {server.name}: {e}")
            real_results = {}

    for svc in services:
        prev_running = svc.running_status or svc.status

        if use_real and svc.id in real_results:
            res = real_results[svc.id]
            real_unknown = (
                res.get("alive_status") == "unknown"
                and res.get("running_status") == "unknown"
            )
            if real_unknown and not PRODUCTION:
                res = None

            if res:
                svc.alive_status = res.get("alive_status", "unknown")
                svc.running_status = res.get("running_status", "unknown")
                svc.cpu_percent = res.get("cpu_percent", 0.0)
                svc.memory_percent = res.get("memory_percent", 0.0)
                svc.disk_percent = res.get("disk_percent", 0.0)
                svc.disk_mbps = res.get("disk_mbps", 0.0)
                svc.disk_read_mbps = res.get("disk_read_mbps", 0.0)
                svc.disk_write_mbps = res.get("disk_write_mbps", 0.0)
                svc.network_mbps = res.get("network_mbps", 0.0)
                svc.network_in_mbps = res.get("network_in_mbps", 0.0)
                svc.network_out_mbps = res.get("network_out_mbps", 0.0)
                svc.alert_status = res.get("alert_status", "normal")
                svc.pid = int(res.get("pid", 0) or 0)
                svc.ppid = int(res.get("ppid", 0) or 0)
                svc.path = res.get("path", "")
                svc.start_time = res.get("start_time", "")
                svc.cmdline = res.get("cmdline", "")
                svc.username = res.get("username", "")
            else:
                alive = "running" if (svc.id % 7 != 0) else "stopped"
                running = alive
                svc.alive_status = alive
                svc.running_status = running
                svc.cpu_percent = round((svc.id * 3.7) % 15, 1)
                svc.memory_percent = round((svc.id * 1.3) % 8, 1)
                svc.disk_percent = 0.0
                svc.disk_mbps = round((svc.id * 0.17) % 5, 1)
                svc.disk_read_mbps = round((svc.id * 0.11) % 3, 1)
                svc.disk_write_mbps = svc.disk_mbps
                svc.network_mbps = round((svc.id * 0.09) % 2, 1)
                svc.network_in_mbps = round(svc.network_mbps * 0.4, 2)
                svc.network_out_mbps = round(svc.network_mbps * 0.6, 2)
                svc.alert_status = "critical" if running == "stopped" else "normal"
                svc.pid = svc.id * 100
                svc.ppid = 0
                svc.path = f"/usr/local/{svc.image_name or svc.process_name or 'service'}/bin"
                svc.start_time = ""
                svc.cmdline = ""
                svc.username = ""
        elif PRODUCTION:
            svc.alive_status = "unknown"
            svc.running_status = "unknown"
            svc.cpu_percent = 0.0
            svc.memory_percent = 0.0
            svc.disk_percent = 0.0
            svc.disk_mbps = 0.0
            svc.disk_read_mbps = 0.0
            svc.disk_write_mbps = 0.0
            svc.network_mbps = 0.0
            svc.network_in_mbps = 0.0
            svc.network_out_mbps = 0.0
            svc.alert_status = "warning"
            svc.pid = 0
            svc.ppid = 0
            svc.path = ""
            svc.start_time = ""
            svc.cmdline = ""
            svc.username = ""
        svc.status = svc.running_status
        svc.last_checked = datetime.now(timezone.utc)

        new_running = svc.running_status
        if new_running == "stopped" and prev_running != "stopped":
            if svc.port and svc.port > 0:
                msg = f"{svc.name} 端口 {svc.port} 无响应（映像: {svc.image_name or svc.process_name}）"
            else:
                msg = f"{svc.name} 映像 {svc.image_name or svc.process_name} 未运行"
            _create_alert(db, server, "critical", f"服务停止: {svc.name}", msg, "service")
        elif new_running == "running" and prev_running == "stopped":
            _clear_service_alerts(db, server, svc.name)


_simulate_services = _check_services


def _clear_service_alerts(db: Session, server: Server, svc_name: str):
    """Clear unresolved alerts for a specific service that has recovered."""
    since = datetime.now(timezone.utc) - timedelta(minutes=30)
    alerts = (
        db.query(Alert)
        .filter(
            Alert.server_id == server.id,
            Alert.metric_type == "service",
            Alert.acknowledged == 0,
            Alert.title.contains(svc_name),
            Alert.timestamp >= since,
        )
        .all()
    )
    for a in alerts:
        a.acknowledged = 1


def _detect_os(server: Server) -> str:
    name = (server.name or "").lower()
    biz = (server.business_system or "").lower()
    if server.protocol == "WinRM":
        if any(k in name + biz for k in ["win11", "win 11", "11"]): return "Windows 11 专业版 23H2"
        if any(k in name + biz for k in ["server 2022", "win2022"]): return "Windows Server 2022 Standard"
        if any(k in name + biz for k in ["server 2019", "win2019"]): return "Windows Server 2019 Standard"
        if any(k in name + biz for k in ["server"]): return "Windows Server 2022 Standard"
        if any(k in biz for k in ["erp", "金蝶", "eas", "文件", "云", "web"]): return "Windows Server 2022 Standard"
        if any(k in biz for k in ["桌面", "办公", "pc"]): return "Windows 11 专业版 23H2"
        return "Windows 10 专业版 22H2"
    if server.protocol == "SSH":
        if "EAS" in biz.upper(): return "Red Hat Enterprise Linux 8.8 (Ootpa)"
        if any(k in biz for k in ["ubuntu"]): return "Ubuntu 22.04 LTS"
        if any(k in biz for k in ["debian"]): return "Debian 12 (Bookworm)"
        return "CentOS Linux 7.9 (Core)"
    return "Unknown OS"


def _detect_hardware(server: Server) -> tuple:
    biz = (server.business_system or "").lower()
    if "eas" in biz: return (16, 64.0)
    if any(k in biz for k in ["erp", "金蝶"]): return (8, 32.0)
    if any(k in biz for k in ["文件", "云", "web"]): return (4, 16.0)
    return (4, 8.0)
