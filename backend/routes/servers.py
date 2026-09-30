"""Server CRUD API routes."""
import logging
from fastapi import APIRouter, Depends, HTTPException, Header, Body, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
import requests as _requests
from database import get_db
from models import Server, MetricSnapshot, MonitoredService, Alert
from services.service_monitor import terminate_service
from services.secret_store import encrypt_secret
from services import web_auto_login
from services import target_guard
from services.client_ip import get_client_ip
from services.audit_logger import log_operation
from routes.auth import (has_perm, allowed_server_ids,
                         can_manage_server, require_login, require_admin_full,
                         require_perm)
from sqlalchemy.orm.attributes import flag_modified
from datetime import datetime, timezone

logger = logging.getLogger("backend")

router = APIRouter(prefix="/api/servers", tags=["servers"])

# 接口回显主机口令时的占位符。前端把它原样回传表示"不修改"，
PASSWORD_MASK = "******"


def _require_user(authorization: Optional[str], db: Session) -> dict:
    """解析当前登录用户；未登录或会话已失效一律 401。

    早期实现未登录时返回空 dict，导致两类问题：
      1. 读类接口里 `if user:` 才收敛可见范围 —— 匿名请求直接拿到全部主机；
      2. 写类接口落到 RBAC 上返回 403，语义混淆（其实是没登录，不是没权限）。
    现在统一在这里截断：未登录 = 401（实体逻辑见 routes.auth.require_login）。
    """
    return require_login(authorization, db)


def _require_user_for_server(authorization: Optional[str], db: Session, server_id) -> dict:
    """登录校验 + **主机归属校验**（2026-09-22 安全审计 P0-1）。

    历史问题：本文件 38 个路由里有 30 个是 `/{server_id}/...` 形态，但只用
    `_require_user()` 校验了"已登录"，没校验"这台主机在不在当前角色的管理范围内"。
    结果：任意一个低权限（viewer）账号只要遍历 server_id，就能读取/修改全网主机的
    IP、SSH/SNMP/WEB 凭据，还能对任意主机执行采集、连接、重启等操作（IDOR）。

    其它路由文件（`file_explorer` / `host_info` / `rdp` / `network_web` / `agent_update`）
    早就做了这一步，本文件是遗漏。现在凡是路径里带 `{server_id}` 的路由一律走这个函数。

    管理员恒通过（见 `routes.auth.can_manage_server`），所以对管理员角色的行为**完全不变**。
    """
    user = require_login(authorization, db)
    if not can_manage_server(db, user, server_id):
        raise HTTPException(status_code=403, detail="无权操作该主机")
    return user


def _ts(dt):
    """Serialize naive UTC datetime as ISO with Z suffix."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        from datetime import timezone
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


class ServerCreate(BaseModel):
    name: str
    ip_address: str
    network_env: str = "内网"
    business_system: str = ""
    protocol: str = "SSH"
    connection_port: int = 22
    username: str = ""
    password: str = ""
    description: str = ""
    extra_config: Optional[dict] = None


class ServerUpdate(BaseModel):
    name: Optional[str] = None
    ip_address: Optional[str] = None
    network_env: Optional[str] = None
    business_system: Optional[str] = None
    protocol: Optional[str] = None
    connection_port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    description: Optional[str] = None
    extra_config: Optional[dict] = None
    # S5：SNMPv3（网络设备），两个口令跟主机口令一个规矩：掩码 = 不修改
    snmp_enabled: Optional[int] = None
    snmp_version: Optional[str] = None
    snmp_port: Optional[int] = None
    snmp_username: Optional[str] = None
    snmp_security_level: Optional[str] = None
    snmp_auth_proto: Optional[str] = None
    snmp_priv_proto: Optional[str] = None
    snmp_auth_password: Optional[str] = None
    snmp_priv_password: Optional[str] = None
    snmp_context: Optional[str] = None
    # 方案 B：网络设备资产信息（自动识别后可人工纠错）+ 单台采集周期
    device_vendor: Optional[str] = None
    device_model: Optional[str] = None
    device_category: Optional[str] = None
    collect_interval_sec: Optional[int] = None
    # 方案 B：网络设备命令行凭据（WEB终端登录设备用），口令同样「掩码 = 不修改」
    cli_protocol: Optional[str] = None
    cli_port: Optional[int] = None
    cli_username: Optional[str] = None
    cli_password: Optional[str] = None
    cli_enable_password: Optional[str] = None
    web_protocol: Optional[str] = None
    web_port: Optional[int] = None
    web_auto_login: Optional[int] = None
    web_username: Optional[str] = None
    web_password: Optional[str] = None


@router.get("/")
def list_servers(
    include_pending: bool = False,
    kind: Optional[str] = None,
    # 断开的网络设备默认不出现在侧边栏主机列表里（网络设备页签自己会带上它）
    include_disconnected: bool = False,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    query = db.query(Server)
    if not include_pending:
        # Hide only "registered" agent servers (awaiting approval)
        query = query.filter(
            ~(Server.protocol == "agent") | (Server.status != "registered")
        )
    if kind in ("host", "network"):
        query = query.filter(Server.device_kind == kind)
    if not include_disconnected:
        # 已断开的网络设备：档案还留着，但不属于"当前在管"，侧边栏不该出现
        query = query.filter(
            ~((Server.device_kind == "network") & (Server.status == "disconnected"))
        )
    servers = query.order_by(Server.sort_order, Server.id).all()

    # 按角色可管理主机收敛可见范围（_require_user 已保证调用者必须登录）
    user = _require_user(authorization, db)
    allowed = set(allowed_server_ids(db, user, [s.id for s in servers]))
    servers = [s for s in servers if s.id in allowed]

    # 设备身份（S1）：一次性把这批主机的 AgentKey 取出来，避免在循环里逐条查。
    _pending_keys: dict = {}
    _pending_nodes: dict = {}
    _pending_states: dict = {}
    _pending_fps: dict = {}
    try:
        from models import AgentKey

        ids = [s.id for s in servers]
        if ids:
            for row in db.query(AgentKey).filter(AgentKey.server_id.in_(ids)).all():
                _pending_nodes[row.server_id] = row.node_id or ""
                _pending_states[row.server_id] = row.identity_state or ""
                # S4：公钥指纹与配对码并排显示。配对码短、好念，适合快速比对；
                # 指纹由 Agent 端私钥决定，**复制配置目录也带不走**，适合怀疑被顶替时核对。
                _pending_fps[row.server_id] = row.key_fingerprint or ""
                # 登记过公钥之后配对码已经没有意义了，不再往下吐。
                # 例外：被吊销的主机要重新准入，它的公钥虽然还留着（用于审计，
                # 且吊销是靠服务端拒绝名单生效），但配对码必须重新可见，
                # 否则管理员没法核对"重来的这台"是不是同一台机器。
                # 2026-09-28：判据原来是 `not row.client_cert`。方案 A（1.1.51）
                # 之后 `client_cert` 再无写入点，前半段恒真，列表接口于是对**所有**
                # 主机都吐配对码（已准入的本不该吐）。改用 `pub_key`。
                _pending_keys[row.server_id] = (
                    row.pairing_code
                    if (not (row.pub_key or "").strip()
                        or row.revoked
                        or (row.identity_state or "") == "revoked")
                    else ""
                )
    except Exception as e:  # noqa: BLE001
        logger.warning(f"读取设备身份失败（不影响列表主体）：{e}")

    # 配置只读一次，别在循环里反复查库。
    try:
        from services.device_status import load_config, collect_period, is_online

        _cfg = load_config(db)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"读取运行参数失败，在线判定退化为离线：{e}")
        _cfg = {}

        def collect_period(_s, _c):  # noqa: F811
            return 60

        def is_online(_s, _c):  # noqa: F811
            return False

    # 端口数：一次分组查询拿全部，别在循环里逐台 count（列表接口是高频调用）
    if_counts = {}
    try:
        from sqlalchemy import func
        from models import NetworkInterface

        if_counts = dict(
            db.query(NetworkInterface.server_id, func.count(NetworkInterface.id))
            .group_by(NetworkInterface.server_id)
            .all()
        )
    except Exception as e:  # noqa: BLE001
        logger.warning(f"统计端口数失败（列表里该列显示 0）：{e}")

    def _snmp_extra(srv) -> dict:
        """extra_config['snmp'] 的安全取值（老数据里可能不是 dict）。"""
        e = srv.extra_config or {}
        if not isinstance(e, dict):
            return {}
        v = e.get("snmp")
        return v if isinstance(v, dict) else {}

    result = []
    for s in servers:
        latest_metric = (
            db.query(MetricSnapshot)
            .filter(MetricSnapshot.server_id == s.id)
            .order_by(MetricSnapshot.timestamp.desc())
            .first()
        )
        alert_count = (
            db.query(Alert)
            .filter(Alert.server_id == s.id, Alert.acknowledged == 0)
            .count()
        )
        extra = s.extra_config or {}
        if not isinstance(extra, dict):
            extra = {}
        result.append({
            "id": s.id,
            "name": s.name,
            "ip_address": s.ip_address,
            "os_type": s.os_type or "",
            "network_env": s.network_env,
            "business_system": s.business_system or "",
            "protocol": s.protocol or "SSH",
            "connection_port": s.connection_port or 22,
            "status": s.status,
            "device_kind": s.device_kind or "host",
            "device_vendor": s.device_vendor or "",
            "device_model": s.device_model or "",
            "device_category": s.device_category or "",
            "collect_period_sec": collect_period(s, _cfg),
            "is_online": is_online(s, _cfg),
            "interface_count": int(if_counts.get(s.id, 0)),
            # 最近一次 SNMP 采集（网络设备列表的"最后采集"列；主机一直是空）
            "last_collect_at": _snmp_extra(s).get("last_attempt_at", ""),
            "last_collect_error": _snmp_extra(s).get("error", ""),
            "cpu_cores": s.cpu_cores,
            "total_memory_gb": s.total_memory_gb,
            "total_disk_gb": s.total_disk_gb,
            "description": s.description,
            "last_seen": _ts(s.last_seen),
            "join_time": _ts(s.join_time),
            "online_time": _ts(s.online_time),
            "offline_time": _ts(s.offline_time),
            "agent_version": extra.get("agent_version", ""),
            "install_path": s.install_path or "",
            "latest_metric": {
                "cpu_percent": latest_metric.cpu_percent if latest_metric else 0,
                "memory_percent": latest_metric.memory_percent if latest_metric else 0,
                "disk_percent": latest_metric.disk_percent if latest_metric else 0,
                "network_in_mbps": latest_metric.network_in_mbps if latest_metric else 0,
                "network_out_mbps": latest_metric.network_out_mbps if latest_metric else 0,
                "disk_io_read_mbps": latest_metric.disk_io_read_mbps if latest_metric else 0,
                "disk_io_write_mbps": latest_metric.disk_io_write_mbps if latest_metric else 0,
                "tcp_connections": latest_metric.tcp_connections if latest_metric else 0,
                "timestamp": latest_metric.timestamp.isoformat() if latest_metric else None,
            },
            "unacknowledged_alerts": alert_count,
            # S0：主机名与已有记录撞车（不同来源 IP），注册管理页要据此显示警告。
            "name_conflict": bool(extra.get("name_conflict_with")),
            # S1：设备身份。配对码只在还没发证时给前端，证发完立即抹掉（见 routes/agent
            # 的 enroll 返回体），避免它在网络上长期漂着被人拿来骗审核。
            "pairing_code": _pending_keys.get(s.id, ""),
            "node_id": _pending_nodes.get(s.id, ""),
            "identity_state": _pending_states.get(s.id, ""),
            "key_fingerprint": _pending_fps.get(s.id, ""),
        })
    return result


@router.get("/{server_id}")
def get_server_detail(
    server_id: int,
    request: Request,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """Return static/fixed server info only.

    Dynamic metrics and service lists are split into dedicated endpoints so
    the host detail page frame can render immediately.
    """
    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")

    # 主机口令一律只给掩码，管理员也不例外（安全审计 P0：Server.password 明文）。
    # 早期版本管理员能读到明文，等于"任意一个管理员账号 = 全部主机的管理员口令"；
    # 现在库里是 Fernet 密文，接口也不再回显，改口令请在表单里重新输入。
    user = _require_user_for_server(authorization, db, server_id)
    password_out = PASSWORD_MASK if s.password else ""

    extra = s.extra_config or {}
    if not isinstance(extra, dict):
        extra = {}
    lightweight_extra = {k: v for k, v in extra.items() if k != "pending_services"}

    return JSONResponse(
        content={
            "id": s.id,
            "name": s.name,
            "ip_address": s.ip_address,
            "os_type": s.os_type or "",
            "protocol": s.protocol or "SSH",
            "connection_port": s.connection_port or 22,
            "device_kind": s.device_kind or "host",
            "device_vendor": s.device_vendor or "",
            "device_model": s.device_model or "",
            "device_category": s.device_category or "",
            "collect_interval_sec": s.collect_interval_sec or 0,
            "username": s.username or "",
            "password": password_out,
            "has_password": bool(s.password),
            "status": s.status,
            "cpu_cores": s.cpu_cores or 0,
            "total_memory_gb": s.total_memory_gb or 0,
            "total_disk_gb": s.total_disk_gb or 0,
            "disk_partitions": s.disk_partitions or [],
            "description": s.description,
            "extra_config": lightweight_extra,
            "install_path": s.install_path or "",
            "last_seen": _ts(s.last_seen),
            "join_time": _ts(s.join_time),
            "online_time": _ts(s.online_time),
            "offline_time": _ts(s.offline_time),
            # S5：SNMPv3 配置（网络设备）。两个口令跟主机口令一个规矩，一律只给
            # 掩码；`has_*` 让前端知道"这台已经存过口令了"，页面就不逼着管理员重输。
            "snmp": {
                "enabled": bool(s.snmp_enabled),
                "version": s.snmp_version or "3",
                "port": s.snmp_port or 161,
                "username": s.snmp_username or "",
                "security_level": s.snmp_security_level or "authPriv",
                "auth_proto": s.snmp_auth_proto or "SHA",
                "priv_proto": s.snmp_priv_proto or "AES",
                "context": s.snmp_context or "",
                "auth_password": PASSWORD_MASK if s.snmp_auth_password else "",
                "priv_password": PASSWORD_MASK if s.snmp_priv_password else "",
                "has_auth_password": bool(s.snmp_auth_password),
                "has_priv_password": bool(s.snmp_priv_password),
            },
            # 方案 B：网络设备命令行凭据（WEB终端登录用）。同样只给掩码。
            "cli": {
                "protocol": s.cli_protocol or "ssh",
                "port": int(s.cli_port or 22),
                "username": s.cli_username or "",
                "password": PASSWORD_MASK if s.cli_password else "",
                "enable_password": PASSWORD_MASK if s.cli_enable_password else "",
                "has_password": bool(s.cli_password),
                "has_enable_password": bool(s.cli_enable_password),
            },
            # 方案 B：网络设备 WEB 管理入口（「WEB管理」页签从这里拿地址与端口）
            # 2026-09-21 起这里还带上账号口令自动填充的配置：账号 + 口令掩码 + 开关，
            # 以及"这台设备的厂商我们认不认得"（认不出就不提供自动填充）。
            "web": {
                "protocol": (s.web_protocol or "https").lower(),
                "port": int(s.web_port or 443),
                "host": s.ip_address or "",
                "auto_login": bool(int(s.web_auto_login or 0)),
                "username": s.web_username or "",
                "password": PASSWORD_MASK if s.web_password else "",
                "has_password": bool(s.web_password),
                "auto_login_supported": web_auto_login.supported(s),
            },
        },
        # 2026-09-22 去掉 `Cache-Control: private, max-age=300`：这个头会让浏览器在
        # 5 分钟内**直接复用旧响应**（连条件请求都不发），改完后端接口却看不到变化，
        # 排障时极容易被误导成「改动没生效/需要重启」。不设缓存头即回到浏览器默认策略。
    )


@router.get("/{server_id}/metrics")
def get_server_metrics(server_id: int, authorization: Optional[str] = Header(None),
                       db: Session = Depends(get_db)):
    """Return the latest dynamic metric snapshot for a server."""
    _require_user_for_server(authorization, db, server_id)
    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")

    latest = (
        db.query(MetricSnapshot)
        .filter(MetricSnapshot.server_id == server_id)
        .order_by(MetricSnapshot.timestamp.desc())
        .first()
    )

    return {
        "cpu_percent": latest.cpu_percent if latest else 0,
        "memory_percent": latest.memory_percent if latest else 0,
        "memory_used_gb": latest.memory_used_gb if latest else 0,
        "disk_percent": latest.disk_percent if latest else 0,
        "disk_used_gb": latest.disk_used_gb if latest else 0,
        "network_in_mbps": latest.network_in_mbps if latest else 0,
        "network_out_mbps": latest.network_out_mbps if latest else 0,
        "disk_io_read_mbps": latest.disk_io_read_mbps if latest else 0,
        "disk_io_write_mbps": latest.disk_io_write_mbps if latest else 0,
        "tcp_connections": latest.tcp_connections if latest else 0,
        "timestamp": latest.timestamp.isoformat() if latest else None,
    }


@router.get("/{server_id}/services")
def get_server_services(server_id: int, authorization: Optional[str] = Header(None),
                        db: Session = Depends(get_db)):
    """Return the configured monitored services for a server."""
    _require_user_for_server(authorization, db, server_id)
    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")

    services = db.query(MonitoredService).filter(MonitoredService.server_id == server_id).all()
    return [
        {
            "id": svc.id,
            "name": svc.name,
            "image_name": svc.image_name or svc.process_name or "",
            "port": svc.port or 0,
            "process_name": svc.process_name,
            "cpu_percent": svc.cpu_percent or 0.0,
            "memory_percent": svc.memory_percent or 0.0,
            "disk_percent": svc.disk_percent or 0.0,
            "disk_mbps": svc.disk_mbps or 0.0,
            "disk_read_mbps": svc.disk_read_mbps or 0.0,
            "disk_write_mbps": svc.disk_write_mbps or 0.0,
            "network_mbps": svc.network_mbps or 0.0,
            "network_in_mbps": svc.network_in_mbps or 0.0,
            "network_out_mbps": svc.network_out_mbps or 0.0,
            "alive_status": svc.alive_status or svc.status or "unknown",
            "alert_status": svc.alert_status or "normal",
            "running_status": svc.running_status or svc.status or "unknown",
            "pid": svc.pid or 0,
            "ppid": svc.ppid or 0,
            "path": svc.path or "",
            "start_time": svc.start_time or "",
            "cmdline": svc.cmdline or "",
            "username": svc.username or "",
            "has_visible_window": bool(svc.has_visible_window),
            "app_instance_id": svc.app_instance_id or svc.image_name or svc.process_name or "",
            "status": svc.status,
            "last_checked": svc.last_checked.isoformat() if svc.last_checked else None,
            "description": svc.description,
        }
        for svc in services
    ]


@router.post("/")
def create_server(data: ServerCreate, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = _require_user(authorization, db)
    # 第二轮复查 R-4：以前只有"已登录"，任何账号都能往资产表里塞一台主机
    # （任意 IP + 用户名 + 口令）。新增主机属于主机管理的写操作，挂
    # `sys/register/edit`（页面名「编辑主机」），这是 sys/register 页现有的写权限点，
    # 不新造权限点，免得老角色的权限配置出现未知项。管理员恒通过（has_perm）。
    require_perm(db, user, "sys", "register", "edit", detail="无权限新增主机")
    now = datetime.now(timezone.utc)
    s = Server(
        name=data.name,
        ip_address=data.ip_address,
        os_type="",
        network_env=data.network_env,
        business_system=data.business_system,
        protocol=data.protocol,
        connection_port=data.connection_port,
        username=data.username,
        password=encrypt_secret(data.password),
        cpu_cores=0,
        total_memory_gb=0.0,
        total_disk_gb=0.0,
        description=data.description,
        extra_config=data.extra_config or {},
    )
    db.add(s)
    db.commit()
    db.refresh(s)

    log_operation(
        db,
        category="server",
        action="create",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="server",
        target_id=str(s.id),
        message=f"用户 {user.get('username', '未知')} 新增主机 {s.name}（{s.ip_address}）",
        details={"name": s.name, "ip_address": s.ip_address, "protocol": s.protocol},
    )

    _create_default_services(db, s)
    # 新加入管理的主机自动归入「默认分组」（分组模块内部兜异常，不影响建主机）
    try:
        from routes.host_groups import add_to_default_group
        add_to_default_group(db, s.id)
    except Exception:  # noqa: BLE001
        pass
    return {"id": s.id, "name": s.name, "message": "Server created"}


# 必须注册在 `PUT /{server_id}` **之前**：FastAPI 按注册顺序匹配，放在后面的话
# （第二轮复查 R-12）。移动它不会改变其它路由的匹配结果。
@router.put("/reorder")
def reorder_servers(data: dict, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    """Accept {server_id: sort_order, ...} and reorder.

    Sidebar layout changes are restricted to administrators so low-privilege
    viewers cannot silently re-order the management view.
    """
    # 以前这里查的是 `sys/servers/edit`，权限点注册表里**根本没有**这一项
    # （sys 下只有 dashboard/register/host_groups/agent_update/network_devices/
    # logs/settings），对非管理员恒为 False。效果碰巧等于"仅管理员"，但意图是错的
    # 真要给某个角色开放这个操作时会永远配不上。改成显式管理员校验。
    user = require_admin_full(authorization, db)
    servers = db.query(Server).all()
    for s in servers:
        if str(s.id) in data:
            s.sort_order = int(data[str(s.id)])
    db.commit()
    return {"message": "Reordered"}


@router.put("/{server_id}")
def update_server(server_id: int, data: ServerUpdate, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = _require_user_for_server(authorization, db, server_id)
    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")

    old_business = s.business_system
    update_data = data.model_dump(exclude_unset=True)
    changed = {}

    # 口令特殊处理：空串或掩码占位符 = 不修改（前端编辑时回显的就是掩码，且不再
    # 回发明文，所以"没动过"和"清空"从前端已经分不出来了，一律按"不修改"处理，
    # 避免误把已保存的凭据抹掉）。真要改就存成 Fernet 密文，审计只记"改过"。
    if "password" in update_data:
        new_pw = (update_data.pop("password") or "").strip()
        if new_pw and new_pw != PASSWORD_MASK:
            s.password = encrypt_secret(new_pw)
            changed["password"] = {"old": PASSWORD_MASK, "new": PASSWORD_MASK}

    # S5：SNMPv3 的两个口令同样只进不出，掩码 = 不修改，改了就存 Fernet 密文。
    # 审计里也只记"改过"，绝不把明文写进日志（日志页面任何管理员都看得到）。
    for _field in ("snmp_auth_password", "snmp_priv_password",
                   "cli_password", "cli_enable_password", "web_password"):
        if _field in update_data:
            _new = (update_data.pop(_field) or "").strip()
            if _new and _new != PASSWORD_MASK:
                setattr(s, _field, encrypt_secret(_new))
                changed[_field] = {"old": PASSWORD_MASK, "new": PASSWORD_MASK}

    for field, value in update_data.items():
        if field != "extra_config":
            old = getattr(s, field)
            if old != value:
                changed[field] = {"old": old, "new": value}
            setattr(s, field, value)
    if "extra_config" in update_data:
        changed["extra_config"] = {"old": s.extra_config, "new": update_data["extra_config"]}
        s.extra_config = update_data["extra_config"]

    # 2026-09-21：SNMPv3 凭据完整性校验，背景见 snmp_collector.py 顶部「采集熔断」。
    # authPriv（既鉴权又加密）却没填加密口令 采集时必定解密失败；而华为/华三这类设备
    # 会把每次失败记一次"登录失败"并临时锁定源 IP，本机的 IP 就被反复锁（真机实证
    # 被锁了 34 轮）。所以在**保存这一层**直接拦下，不让残缺凭据进库。
    # 必须放在 db.commit() 之前：抛异常时前面的 setattr 只改了内存对象，不会落库。
    if int(s.snmp_enabled or 0) == 1:
        _level = str(s.snmp_security_level or "authPriv").lower()
        if not (s.snmp_username or "").strip():
            raise HTTPException(status_code=400, detail="开启了 SNMP 采集，但没有填 SNMPv3 用户名")
        if _level in ("authnopriv", "authpriv") and not (s.snmp_auth_password or "").strip():
            raise HTTPException(
                status_code=400,
                detail=f"SNMP 安全级别是 {s.snmp_security_level}（需要鉴权），但没有填鉴权口令",
            )
        if _level == "authpriv" and not (s.snmp_priv_password or "").strip():
            raise HTTPException(
                status_code=400,
                detail="SNMP 安全级别选了 authPriv（鉴权+加密），但没有填加密口令 —— "
                       "这样采集必定解密失败，设备会把本机 IP 反复锁死。"
                       "请补齐加密口令，或把安全级别改成 authNoPriv。",
            )

    db.commit()
    db.refresh(s)

    log_operation(
        db,
        category="server",
        action="update",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="server",
        target_id=str(s.id),
        message=f"用户 {user.get('username', '未知')} 编辑主机 {s.name}",
        details={"changed": changed},
    )

    new_business = update_data.get("business_system")
    if new_business and new_business != old_business:
        old_services = db.query(MonitoredService).filter(MonitoredService.server_id == server_id).all()
        for svc in old_services:
            db.delete(svc)
        _create_default_services(db, s)

    return {"id": s.id, "name": s.name, "message": "Server updated"}


@router.delete("/{server_id}")
def delete_server(server_id: int, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = _require_user_for_server(authorization, db, server_id)
    # 2026-09-22：删除主机收紧为两道闸门（对齐注册管理页 canRemove），
    # ① 权限：与「移出管理」同一颗权限点（sys.register.edit.delete）
    if not has_perm(db, user, "sys", "register", "edit", "delete"):
        raise HTTPException(status_code=403, detail="无权限删除主机")
    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    # ② 受管中的主机必须先移出管理，在管数据（监控历史 / 服务 / 告警）
    # 全挂在记录上，误删不可逆。先移出（退回待审核）确认不要了再删。
    # 判据用 join_time（加入管理时写入、移出时清空，enroll 也用它），
    # 不用 status 集合：未加入管理的主机历史上可能被采集调度误标成
    # offline，那样会落进「受管状态」里，管理员就删不掉了（2026-09-22 修）。
    if s.join_time is not None:
        raise HTTPException(
            status_code=400,
            detail="该主机仍在管理中，请先「移出管理」再删除",
        )
    # 重新注册回来，变成「删了又出现」。先在目标主机退出/卸载 Agent，
    # 等它离线后再删。判定口径与列表页一致（services/device_status.py）。
    try:
        from services.device_status import load_config, is_online

        if is_online(s, load_config(db)):
            raise HTTPException(
                status_code=400,
                detail="该主机的 Agent 仍在心跳（在线），删除后它会自动重新注册。"
                       "请先在目标主机退出或卸载 Agent，等它离线后再删除。",
            )
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001 判定失败不拦删除
        logger.warning(f"在线判定失败，跳过心跳检查 server_id={server_id}：{e}")
    name = s.name
    ip = s.ip_address
    # 主机删除后，分组里的成员行必须一并清掉，否则留下指向不存在主机的孤儿行
    removed_groups = []
    try:
        from models import HostGroupMember
        rows = db.query(HostGroupMember).filter(HostGroupMember.server_id == server_id).all()
        removed_groups = [r.group_id for r in rows]
        for r in rows:
            db.delete(r)
    except Exception:  # noqa: BLE001
        pass
    # 同理，这台主机的**设备身份**（node_id / 证书 / 配对码）也必须一起删掉，
    # 否则库里会留下一批指向不存在主机的孤儿身份行，它们带着 client_cert，
    # 既不出现在任何列表里，又占着 node_id 的唯一性，将来同名设备入户时容易
    # 撞出莫名其妙的问题（S4 冒烟里实测到：删主机后 agent_keys 仍残留 2 行）。
    removed_identity = ""
    try:
        from models import AgentKey

        _k = db.query(AgentKey).filter(AgentKey.server_id == server_id).first()
        if _k is not None:
            removed_identity = _k.node_id or ""
            db.delete(_k)
    except Exception:  # noqa: BLE001
        pass
    # 方案 B：网络设备的端口表同理（删交换机后留一堆孤儿端口行，没人看得到）
    removed_interfaces = 0
    try:
        from models import NetworkInterface

        removed_interfaces = db.query(NetworkInterface).filter(
            NetworkInterface.server_id == server_id
        ).delete(synchronize_session=False)
    except Exception:  # noqa: BLE001
        pass
    # S5：SSH 主机密钥钉扎记录同理，留着也会占着 server_id 的唯一性
    removed_host_key = False
    try:
        from models import SSHHostKey

        _hk = db.query(SSHHostKey).filter(SSHHostKey.server_id == server_id).first()
        if _hk is not None:
            removed_host_key = True
            db.delete(_hk)
    except Exception:  # noqa: BLE001
        pass
    db.delete(s)
    db.commit()
    log_operation(
        db,
        category="server",
        action="delete",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="server",
        target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 删除主机 {name}（{ip}）",
        details={"name": name, "ip_address": ip, "removed_from_groups": removed_groups,
                 "removed_identity_node": removed_identity,
                 "removed_ssh_host_key": removed_host_key,
                 "removed_interfaces": removed_interfaces},
    )
    return {"message": f"Server '{name}' deleted"}


@router.put("/{server_id}/acknowledge-alerts")
def acknowledge_alerts(server_id: int, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = _require_user_for_server(authorization, db, server_id)
    server = db.query(Server).filter(Server.id == server_id).first()
    name = server.name if server else str(server_id)
    deleted = db.query(Alert).filter(Alert.server_id == server_id).delete()
    db.commit()
    log_operation(
        db,
        category="alert",
        action="acknowledge_all",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="server",
        target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 确认主机 {name} 的全部告警（{deleted} 条）",
        details={"server_name": name, "count": deleted},
    )
    return {"message": f"Cleared {deleted} alerts"}


@router.post("/{server_id}/services")
def add_service(server_id: int, data: dict, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = _require_user_for_server(authorization, db, server_id)
    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    image_name = data.get("image_name") or data.get("process_name", "")
    svc = MonitoredService(
        server_id=server_id,
        name=data.get("name", ""),
        image_name=image_name,
        path=data.get("path", ""),
        port=data.get("port", 0),
        process_name=data.get("process_name", ""),
        description=data.get("description", ""),
        status="unknown",
    )
    db.add(svc)
    db.commit()
    db.refresh(svc)
    log_operation(
        db,
        category="service",
        action="create",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="server",
        target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 为主机 {s.name} 添加监控服务 {svc.name}",
        details={"service_name": svc.name, "server_name": s.name},
    )
    return {"id": svc.id, "name": svc.name, "message": "Service added"}


@router.put("/{server_id}/services/{service_id}")
def update_service(server_id: int, service_id: int, data: dict, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = _require_user_for_server(authorization, db, server_id)
    svc = db.query(MonitoredService).filter(
        MonitoredService.id == service_id,
        MonitoredService.server_id == server_id,
    ).first()
    if not svc:
        raise HTTPException(status_code=404, detail="Service not found")
    server = db.query(Server).filter(Server.id == server_id).first()
    changes = {}
    for k in ["description", "name", "image_name", "path", "process_name"]:
        if k in data and getattr(svc, k) != data[k]:
            changes[k] = {"old": getattr(svc, k), "new": data[k]}
            setattr(svc, k, data[k])
    if "port" in data and svc.port != int(data["port"] or 0):
        changes["port"] = {"old": svc.port, "new": int(data["port"] or 0)}
        svc.port = int(data["port"] or 0)
    db.commit()
    if changes:
        log_operation(
            db,
            category="service",
            action="update",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            target_type="service",
            target_id=str(service_id),
            message=f"用户 {user.get('username', '未知')} 更新主机 {server.name if server else server_id} 的服务 {svc.name}",
            details={"changes": changes, "server_name": server.name if server else ""},
        )
    return {"id": svc.id, "message": "Service updated"}


@router.delete("/{server_id}/services/{service_id}")
def delete_service(server_id: int, service_id: int, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = _require_user_for_server(authorization, db, server_id)
    svc = db.query(MonitoredService).filter(
        MonitoredService.id == service_id,
        MonitoredService.server_id == server_id,
    ).first()
    if not svc:
        raise HTTPException(status_code=404, detail="Service not found")
    server = db.query(Server).filter(Server.id == server_id).first()
    name = svc.name
    db.delete(svc)
    db.commit()
    log_operation(
        db,
        category="service",
        action="delete",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="service",
        target_id=str(service_id),
        message=f"用户 {user.get('username', '未知')} 删除主机 {server.name if server else server_id} 的服务 {name}",
        details={"service_name": name, "server_name": server.name if server else ""},
    )
    return {"message": "Service deleted"}


@router.delete("/{server_id}/alerts/{alert_id}")
def dismiss_alert(server_id: int, alert_id: int, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = _require_user_for_server(authorization, db, server_id)
    alert = db.query(Alert).filter(
        Alert.id == alert_id,
        Alert.server_id == server_id,
    ).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    server = db.query(Server).filter(Server.id == server_id).first()
    title = alert.title
    db.delete(alert)
    db.commit()
    log_operation(
        db,
        category="alert",
        action="dismiss",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="alert",
        target_id=str(alert_id),
        message=f"用户 {user.get('username', '未知')} 消除主机 {server.name if server else server_id} 的告警：{title}",
        details={"alert_title": title, "server_name": server.name if server else ""},
    )
    return {"message": "Alert dismissed"}


def _apply_status_change(db, server, new_status: str) -> str:
    """把一台主机切到 `new_status`，返回旧状态。

    单台改状态和批量改状态**必须走同一份逻辑** —— 否则两条路径迟早会长歪
    （比如一边洗吊销标记、另一边忘了洗）。审计与「归入默认分组」留在调用方，
    因为批量操作的审计要写清是批量。
    """
    old_status = server.status
    server.status = new_status
    now = datetime.now(timezone.utc)
    if new_status == "monitored":
        server.join_time = now
        # 2026-09-23：`online_time` **刻意一个字都不动**。
        # `join_time` = 管理员把它纳入管理的时刻（人工动作）；
        # `online_time` = 主机**真正上线**的时刻（机器事实）。
        # 两者是独立语义：加入管理并没有让主机上线，所以这里不能写；
        # 移出管理也没有让主机下线，所以下面那条分支也不能清。
        # `online_time` 的唯一写入方是采集侧
        # - Agent 主机：`routes/agent.py::_record_agent_online`，收到心跳时写；
        # 「掉线 再上线」会经过 offline 状态，那时才会刷新它。
        # - 网络设备：`services/snmp_collector.py` 采集成功且状态从
        # offline/unknown 翻回来时写；新建/重连走各自的设备接口。
        # 也就是说：**移出与加入管理都不该改动上线时间**（用户明确要求）。
        server.offline_time = None
        # S2：重新加入管理 = 重新准入。被吊销过的主机在这里洗掉吊销标记，
        # 否则 enroll 会永远以「该设备已被吊销，不允许签发」拒绝它（routes/agent.py）。
        try:
            from models import AgentKey

            _k = db.query(AgentKey).filter(AgentKey.server_id == server.id).first()
            if _k is not None and _k.revoked:
                _k.revoked = 0
                _k.revoked_at = None
                _k.revoked_reason = ""
                _k.identity_state = "approved"
        except Exception as e:  # noqa: BLE001
            logger.warning(f"重新准入时清除吊销标记失败 server_id={server.id}: {e}")
    elif new_status == "registered":
        server.join_time = None
        # `online_time` **刻意保留**（2026-09-23 用户要求）：移出管理只是
        # 管理员不再把它纳入管理，主机并没有下线，把上线时间抹掉等于
        # 丢掉这段事实。它的生命周期只跟随"真正上线/掉线"，与管理动作无关。
        server.offline_time = None
    db.commit()
    if server.status == "monitored":
        try:
            from routes.host_groups import add_to_default_group
            add_to_default_group(db, server.id)
        except Exception:  # noqa: BLE001
            pass
    return old_status


@router.post("/bulk-status")
def bulk_update_server_status(
    data: dict,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """S4：批量「加入管理」/「移出管理」。

    只放开这两个值 —— 批量操作一旦允许任意状态，一次误点就能把一批主机改成
    谁也想不到的状态。删除 / 吊销这种不可逆动作一律不做批量。
    """
    user = _require_user(authorization, db)
    if not has_perm(db, user, "sys", "register", "edit", "approve"):
        raise HTTPException(status_code=403, detail="无权限变更主机管理状态")

    new_status = str(data.get("status") or "").strip()
    if new_status not in ("monitored", "registered"):
        raise HTTPException(status_code=400, detail="批量操作仅支持 monitored / registered")

    raw_ids = data.get("ids") or []
    try:
        ids = [int(i) for i in raw_ids]
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="ids 必须是整数数组")
    if not ids:
        raise HTTPException(status_code=400, detail="请先选择主机")

    done, skipped, names = 0, 0, []
    for sid in ids:
        server = db.query(Server).filter(Server.id == sid).first()
        if not server:
            skipped += 1
            continue
        # 已经是目标状态的不用再动，否则「加入管理」会把 join_time 又刷一遍，
        # 审计里也会多出一堆无意义的变更记录。
        if server.status == new_status:
            skipped += 1
            continue
        old = _apply_status_change(db, server, new_status)
        log_operation(
            db,
            category="server",
            action="bulk_status_change",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            target_type="server",
            target_id=str(sid),
            message=(
                f"用户 {user.get('username', '未知')} 批量将主机 {server.name} "
                f"状态由 {old} 改为 {new_status}"
            ),
            details={"old_status": old, "new_status": new_status,
                     "server_name": server.name, "bulk": True, "batch_size": len(ids)},
        )
        done += 1
        names.append(server.name)

    return {
        "updated": done,
        "skipped": skipped,
        "status": new_status,
        "names": names[:20],
        "message": f"已{('加入' if new_status == 'monitored' else '移出')}管理 {done} 台",
    }


@router.put("/{server_id}/status")
def update_server_status(
    server_id: int,
    data: dict,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """Update server status (e.g., change from 'registered' to 'monitored').

    Approval / removal actions are restricted to administrators only.
    """
    user = _require_user_for_server(authorization, db, server_id)
    if not has_perm(db, user, "sys", "register", "edit", "approve"):
        raise HTTPException(status_code=403, detail="无权限变更主机管理状态")
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    old_status = server.status
    if "status" in data:
        # 这里只补这一台的审计（批量那条路径自己写 bulk_status_change）。
        old_status = _apply_status_change(db, server, data["status"])
        log_operation(
            db,
            category="server",
            action="status_change",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            target_type="server",
            target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 将主机 {server.name} 状态由 {old_status} 改为 {data['status']}",
            details={"old_status": old_status, "new_status": data["status"], "server_name": server.name},
        )
    return {"status": server.status, "message": "Status updated"}


@router.get("/{server_id}/ssh-host-key")
def get_ssh_host_key(
    server_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """S5：查看该主机的 SSH 主机密钥钉扎状态（指纹 / 是否待确认 / 当前策略）。"""
    user = _require_user_for_server(authorization, db, server_id)
    if not has_perm(db, user, "sys", "register", "view"):
        raise HTTPException(status_code=403, detail="无权限查看 SSH 主机密钥")
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    from services import ssh_pinning as pin

    return pin.get_pin(db, server_id)


@router.post("/{server_id}/ssh-host-key/repin")
def repin_ssh_host_key(
    server_id: int,
    data: dict = None,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """S5：确认新指纹 —— 密钥变更只有在管理员确认后才转正。

    body 可带 `{"fingerprint": "SHA256:..."}`，给了就必须与 pending 一致，
    防止页面显示的和实际确认的不是同一个（点错按钮 / 并发改过）。
    """
    user = _require_user_for_server(authorization, db, server_id)
    if not has_perm(db, user, "sys", "register", "edit", "approve"):
        raise HTTPException(status_code=403, detail="无权限确认 SSH 主机密钥")
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    from services import ssh_pinning as pin

    try:
        result = pin.repin_host_key(db, server_id, (data or {}).get("fingerprint") or "")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@router.delete("/{server_id}/ssh-host-key")
def unpin_ssh_host_key(
    server_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """S5：清除钉扎记录 —— 下次连接重新走首连流程（设备重装后常用）。"""
    user = _require_user_for_server(authorization, db, server_id)
    if not has_perm(db, user, "sys", "register", "edit", "approve"):
        raise HTTPException(status_code=403, detail="无权限清除 SSH 主机密钥")
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    from services import ssh_pinning as pin

    pin.unpin_host_key(db, server_id)
    return {"message": "已清除 SSH 主机密钥钉扎记录"}


def _snmp_is_paused(snmp_info: dict) -> bool:
    """extra_config['snmp'] 是否还在熔断中（截止时间没到才算）。"""
    from services.snmp_collector import snmp_pause_state
    paused, _until = snmp_pause_state(snmp_info or {})
    return bool(paused)


@router.get("/{server_id}/network-interfaces")
def list_network_interfaces(
    server_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """S5：该设备 SNMP 采回来的端口表快照（IF-MIB）+ 设备信息。

    端口表只存"当前"这一份（不存历史），历史走 MetricSnapshot 的汇总流量。
    """
    from services.device_status import device_kind_of

    user = _require_user_for_server(authorization, db, server_id)
    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    # 网络设备走「系统信息」页签进这条接口，角色不一定有 host/network 权限点，
    # 只要有 host/info 也算合法（同一份数据，两个入口）。
    _is_net = device_kind_of(s) == "network"
    if not has_perm(db, user, "host", "network", "view") and not (
        _is_net and has_perm(db, user, "host", "info", "view")
    ):
        raise HTTPException(status_code=403, detail="无权限查看网络端口")

    from models import NetworkInterface

    rows = (
        db.query(NetworkInterface)
        .filter(NetworkInterface.server_id == server_id)
        .order_by(NetworkInterface.if_index)
        .all()
    )
    extra = s.extra_config or {}
    if not isinstance(extra, dict):
        extra = {}
    snmp_info = extra.get("snmp") or {}
    if not isinstance(snmp_info, dict):
        snmp_info = {}

    # 方案 B：资产信息（新增时 SNMP 自动识别，可人工纠错）+ CLI 凭据（只给是否填过）
    from services.device_status import collect_period as _period, load_config as _load_cfg
    from services.device_profile import CATEGORY_LABELS as _CAT
    _cfg = _load_cfg(db)

    has_cli_pw = bool(s.cli_password)
    has_cli_enable = bool(s.cli_enable_password)

    return {
        "snmp_enabled": bool(s.snmp_enabled),
        "asset": {
            "device_kind": s.device_kind or "host",
            "device_vendor": s.device_vendor or "",
            "device_model": s.device_model or "",
            "device_category": s.device_category or "",
            "device_category_label": _CAT.get(s.device_category or "", "其他设备"),
            "collect_period_sec": _period(s, _cfg),
            "status": s.status or "",
            "name": s.name,
            "ip_address": s.ip_address,
            "description": s.description or "",
        },
        "cli": {
            "cli_protocol": s.cli_protocol or "ssh",
            "cli_port": int(s.cli_port or 22),
            "cli_username": s.cli_username or "",
            "has_password": has_cli_pw,
            "has_enable_password": has_cli_enable,
        },
        "device": {
            "sys_descr": snmp_info.get("sys_descr", ""),
            "sys_name": snmp_info.get("sys_name", ""),
            "sys_location": snmp_info.get("sys_location", ""),
            "sys_object_id": snmp_info.get("sys_object_id", ""),
            "uptime_seconds": snmp_info.get("uptime_seconds", 0),
            "interface_count": snmp_info.get("interface_count", 0),
            "last_attempt_at": snmp_info.get("last_attempt_at", ""),
            "ok": snmp_info.get("ok"),
            "error": snmp_info.get("error", ""),
            "consecutive_failures": snmp_info.get("consecutive_failures", 0),
            # 采集熔断（2026-09-21 加）：paused=True 时采集器一个包都不发，
            # 前端要把「已暂停」摆出来，并给一个「恢复采集」的入口。
            "paused": _snmp_is_paused(snmp_info),
            "paused_until": snmp_info.get("paused_until") or "",
            "pause_reason": snmp_info.get("pause_reason", ""),
            # Linux / NAS 才有：存储池、磁盘健康、内存缓存分项（2026-09-21 加）
            "nas": snmp_info.get("nas"),
            # 硬件健康：温度 / 电源 / 风扇 / 整机功率（2026-09-21 加）
            "env": snmp_info.get("env"),
            # ICMP 延迟 / 丢包：和 SNMP 并列的第二条存活证据（2026-09-21 加）
            "icmp": snmp_info.get("icmp"),
        },
        "interfaces": [
            {
                "if_index": r.if_index,
                "if_name": r.if_name or "",
                "if_descr": r.if_descr or "",
                "if_alias": r.if_alias or "",
                "if_type": r.if_type or "",
                "if_speed_mbps": r.if_speed_mbps or 0,
                "admin_status": r.admin_status or "",
                "oper_status": r.oper_status or "",
                "in_octets": r.in_octets or 0,
                "out_octets": r.out_octets or 0,
                "in_errors": r.in_errors or 0,
                "out_errors": r.out_errors or 0,
                # 单端口速率：没有基线时库里是 NULL，**别用 `or 0` 压成 0**，
                # 前端要靠 null 区分"这口真没流量"和"还没算出速率"（2026-09-21）。
                "in_rate_mbps": r.in_rate_mbps,
                "out_rate_mbps": r.out_rate_mbps,
                "updated_at": _ts(r.updated_at),
            }
            for r in rows
        ],
    }


@router.get("/{server_id}/network/logs")
def list_network_device_logs(
    server_id: int,
    limit: int = 300,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """方案 B：网络设备的「事件日志」。

    三条流按时间倒序合并，来源用 `source` 字段区分，前端按来源给不同颜色：
      · **设备（device）** —— 2026-09-21 加：设备**内部**的运行日志（华为 logbuffer /
        trapbuffer），走「路线 A：只读 SSH 轮询」拉回来的。只发 display 命令，
        不改设备任何配置。设备日志只活在内存里（环形缓冲、重启即丢），拉回来存档
        才有得回溯。
      · 告警（Alert）—— 采集失败、端口 DOWN、指标越线
      · 审计（OperationLog）—— 新增 / 连接 / 断开 / 改凭据 / 编辑资产 / 命令行登录

 「设备主动推 syslog（UDP 514）/ SNMP Trap（UDP 162）」仍然没做 —— 那是路线
    B / C，需要动设备配置并且在服务端起监听，和这里的"服务端主动去拉"是两回事。
    """
    from models import Alert, DeviceLogEntry, OperationLog
    from services.device_status import device_kind_of
    # 设备日志的级别码 级别名（EMERG / ERROR / WARN …），前端 hover 时显示
    from services.network_log_collector import LEVEL_CODE_NAMES

    user = _require_user_for_server(authorization, db, server_id)
    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    # 入口是「事件日志」页签：有 host/events 权限，或者是网络设备且有 host/info 权限
    _is_net = device_kind_of(s) == "network"
    if not has_perm(db, user, "host", "events", "view") and not (
        _is_net and has_perm(db, user, "host", "info", "view")
    ):
        raise HTTPException(status_code=403, detail="无权限查看设备日志")

    limit = max(1, min(int(limit or 300), 1000))

    items = []

    dev_rows = (
        db.query(DeviceLogEntry)
        .filter(DeviceLogEntry.server_id == server_id)
        .order_by(DeviceLogEntry.id.desc())
        .limit(limit)
        .all()
    )
    for d in dev_rows:
        items.append({
            "source": "device",
            "id": d.id,
            # 展示时间以**设备自己的时间**为准（occurred_at），不是入库时间
            # 设备常常没配 NTP，和服务端时钟差得很远，用入库时间会看不出事情的先后。
            "timestamp": _ts(d.occurred_at) or _ts(d.collected_at),
            "device_time": d.device_time or "",
            "level": d.level or "info",
            "level_name": LEVEL_CODE_NAMES.get(d.level_code, ""),
            "category": d.module or "",
            "action": d.mnemonic or "",
            "title": d.message or d.raw or "",
            "message": d.raw or d.message or "",
            "username": "",
            "source_kind": d.source or "",
        })

    alerts = (
        db.query(Alert)
        .filter(Alert.server_id == server_id)
        .order_by(Alert.timestamp.desc())
        .limit(limit)
        .all()
    )
    for a in alerts:
        items.append({
            "source": "alert",
            "id": a.id,
            "timestamp": _ts(a.timestamp),
            "level": a.level or "info",
            "category": "告警",
            "action": a.metric_type or "alert",
            "title": a.title or "",
            "message": a.message or "",
            "acknowledged": bool(a.acknowledged),
        })

    # 审计：只认 target = 这台设备。
    # 不能按 IP 兜底捞：SQLite 会复用被删行的 rowid，同一台设备删掉再建会拿到
    # 同一个 id，历史审计里那些"同一个 id 的上一任"就会串进新设备的日志里（实测
    # 出现过"删除主机 XXX"和当前在线设备并排显示）。所以
    # ② 再加一道 created_at 时间下限，id 复用时上一任的记录必然早于本任创建时间。
    # 新增设备弹窗那一步还没有 id（`network_device_*` 记在 IP 上），本来也不属于
    # 任何一台已存在的设备，不进这里是对的。
    floor = s.created_at
    if floor is not None and floor.tzinfo is None:
        floor = floor.replace(tzinfo=timezone.utc)
    q = db.query(OperationLog).filter(
        OperationLog.target_type == "server",
        OperationLog.target_id == str(server_id),
    )
    if floor is not None:
        # 不留宽限窗口：本设备的「新增」审计写在 commit 之后，必然 >= created_at，
        # 所以下限取 created_at 本身就是精确的。留宽限反而会让"删掉立刻重建"时
        # 上一任最后几秒的记录漏进来（实测 120 秒宽限就被测出来了）。
        q = q.filter(OperationLog.timestamp >= floor)
    logs = q.order_by(OperationLog.timestamp.desc()).limit(limit).all()
    for lg in logs:
        items.append({
            "source": "audit",
            "id": lg.id,
            "timestamp": _ts(lg.timestamp),
            "level": lg.level or "info",
            "category": lg.category or "system",
            "action": lg.action or "",
            "title": lg.message or "",
            "message": lg.message or "",
            "username": lg.username or "",
            "status": lg.status or "success",
        })

    # 采集失败不落 Alert（连续 3 次才告警），但管理员排查时最想看的就是它
    extra = s.extra_config or {}
    snmp_info = (extra.get("snmp") or {}) if isinstance(extra, dict) else {}
    collect_state = {
        "last_attempt_at": snmp_info.get("last_attempt_at", ""),
        "ok": snmp_info.get("ok"),
        "error": snmp_info.get("error", ""),
        "consecutive_failures": snmp_info.get("consecutive_failures", 0),
        "interface_count": snmp_info.get("interface_count", 0),
        # 2026-09-21：采集器可能因连续认证失败进入熔断，前端要把它摆出来
        "paused": _snmp_is_paused(snmp_info),
        "paused_until": snmp_info.get("paused_until") or "",
    }

    # 设备内部日志的采集状态（与 SNMP 采集是两条独立的链路）
    from services.network_log_collector import collect_plan as _dl_plan
    dev_state = (extra.get("device_logs") or {}) if isinstance(extra, dict) else {}
    _plan = _dl_plan(s)
    # 「不支持」= 这类设备本身没有可轮询的 CLI 日志源（NAS 的日志是文件），
    # 和「支持但这次拉失败了」是两回事，前端要分开说，不能都报"失败"。
    _unsupported = bool(dev_state.get("unsupported")) or not _plan["supported"]
    device_log_state = {
        "last_attempt_at": dev_state.get("last_attempt_at", ""),
        "ok": dev_state.get("ok"),
        "error": dev_state.get("error", ""),
        "total": int(dev_state.get("total", 0)),
        "inserted": int(dev_state.get("inserted", 0)),
        # supported 保留旧语义（=这台设备能采内部日志），但判断依据改成
        # 「厂商有没有命令集」而不是「有没有填 CLU 凭据」，早先写成
        # `bool(s.cli_username)`，于是"命令集没适配"和"凭据没填"混成一个原因。
        "supported": bool(_plan["supported"]),
        "unsupported": _unsupported,
        "reason": _plan["reason"] or dev_state.get("error", ""),
        "need_credentials": bool(_plan["supported"]) and not bool(s.cli_username),
    }

    items.sort(key=lambda x: (x["timestamp"] or ""), reverse=True)
    return {
        "items": items[:limit],
        "total": len(items[:limit]),
        "collect": collect_state,
        "device_logs": device_log_state,
        "note": (
            "「设备」是设备内部的运行日志，服务端通过只读 SSH 轮询（display logbuffer / "
            "trapbuffer）拉回存档 —— 设备缓冲区是环形的，重启即丢，不主动拉就查不到。"
            "「告警 / 审计」是服务端自己记的。设备主动推送的 syslog / SNMP Trap 接收是后续项。"
        ),
    }


@router.post("/{server_id}/network/device-logs/collect")
def collect_network_device_logs_now(
    server_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """2026-09-21：立刻用只读 SSH 拉一次设备内部日志（路线 A）。

    只发 `screen-length 0 temporary` + `display logbuffer` / `display trapbuffer`，
    **不改设备任何配置**。需要该设备已配好 CLI 登录凭据。
    """
    from services import network_log_collector as nlc
    from services.device_status import device_kind_of

    user = _require_user_for_server(authorization, db, server_id)
    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    if device_kind_of(s) != "network":
        raise HTTPException(status_code=400, detail="只有网络设备才有内部运行日志")
    if not has_perm(db, user, "host", "events", "view") and not (
        has_perm(db, user, "host", "info", "view")
    ):
        raise HTTPException(status_code=403, detail="无权限查看设备日志")
    if not has_perm(db, user, "host", "network", "edit", "collect"):
        raise HTTPException(status_code=403, detail="无权限执行设备日志采集")

    res = nlc.collect_device_logs(db, s)
    nlc.record_state(db, s, res)

    log_operation(
        db,
        category="server",
        action="device_log_collect",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="server",
        target_id=str(s.id),
        message=f"用户 {user.get('username', '未知')} 拉取 {s.name} 的设备内部日志："
                f"{'成功，新增 ' + str(res.get('inserted', 0)) + ' 条' if res.get('ok') else ('不支持：' + str(res.get('error', '')) if res.get('unsupported') else '失败')}",
        details={"ok": bool(res.get("ok")), "error": res.get("error", ""),
                 "unsupported": bool(res.get("unsupported")),
                 "inserted": int(res.get("inserted") or 0)},
    )
    return res


@router.post("/{server_id}/network/cli/test")
def test_network_cli(
    server_id: int,
    data: dict = Body(None),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """方案 B：测试网络设备的命令行（SSH / Telnet）能不能登录。

    带 body = 用表单里还没保存的值试（编辑弹窗用）；不带 body = 用库里已存的凭据试。
    """
    from services.device_status import device_kind_of

    user = _require_user_for_server(authorization, db, server_id)
    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    if device_kind_of(s) != "network":
        raise HTTPException(status_code=400, detail="只有网络设备才能配置命令行凭据")
    # 命令行凭据归「主机管理 - 网络设备」管：至少要能看，且有 edit 才行。
    # 这里不用 _device_perm()（它缺权限直接 403），因为已经确认过 404/400 了。
    if not has_perm(db, user, "sys", "network_devices", "view"):
        raise HTTPException(status_code=403, detail="无权限访问网络设备管理")
    if not has_perm(db, user, "sys", "network_devices", "edit", "edit"):
        raise HTTPException(status_code=403, detail="无权限配置网络设备命令行")

    from services import network_cli as cli

    body = data or {}
    # 用一份浅拷贝去试连，避免把没保存的值写进 ORM 对象（失败了就回滚不了）
    probe = _CliProbe(s, body)
    try:
        sess = cli.open_cli_session(probe, cols=80, rows=24, db=db, timeout=12)
    except cli.CliError as e:
        log_operation(
            db, category="server", action="network_device_cli_test", level="warning",
            status="failed",
            username=user.get("username", ""), user_id=user.get("user_id"),
            target_type="server", target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 测试 {s.name} 命令行连接失败：{e}",
            details={"ok": False, "error": str(e)},
        )
        return {"ok": False, "error": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}

    banner = b""
    try:
        # 读两下拿点登录后的回显（提示符 / banner），证明真的进去了
        for _ in range(6):
            chunk = sess.recv(4096)
            if chunk:
                banner += chunk
            else:
                break
    except Exception:  # noqa: BLE001
        pass
    sess.close()

    log_operation(
        db, category="server", action="network_device_cli_test",
        username=user.get("username", ""), user_id=user.get("user_id"),
        target_type="server", target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 测试 {s.name} 命令行连接成功",
        details={"ok": True, "target": cli.cli_credential_hint(probe)},
    )
    return {
        "ok": True,
        "error": "",
        "target": cli.cli_credential_hint(probe),
        "banner": banner.decode("utf-8", errors="replace")[:500],
    }


class _CliProbe:
    """试连用的临时对象：本体是 Server，但 CLI 字段可以被表单值覆盖。"""

    def __init__(self, server, body: dict):
        self._s = server
        self._body = body or {}
        self.id = server.id
        self.ip_address = str(self._body.get("ip_address") or server.ip_address)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        body = self.__dict__.get("_body", {})
        if name in body and body[name] not in (None, ""):
            return body[name]
        return getattr(self._s, name)

    @property
    def cli_password_plain(self) -> str:
        v = self._body.get("cli_password")
        if v and v != PASSWORD_MASK:
            return str(v)
        return self._s.cli_password_plain

    @property
    def cli_enable_password_plain(self) -> str:
        v = self._body.get("cli_enable_password")
        if v and v != PASSWORD_MASK:
            return str(v)
        return self._s.cli_enable_password_plain


@router.post("/{server_id}/snmp/collect")
def collect_snmp_now(
    server_id: int,
    data: dict = None,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """S5：立刻采一次。

    不带 body = 用库里存的凭据采，结果落库（端口表 + 指标）；
    带 body = 「测试连接」：用页面表单里还没保存的值试一次，**不落库**，
    省得凭据没填对先把库里的端口表清空了。
    """
    user = _require_user_for_server(authorization, db, server_id)
    if not has_perm(db, user, "host", "network", "edit", "collect"):
        raise HTTPException(status_code=403, detail="无权限执行 SNMP 采集")
    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")

    from services import snmp_collector as snmp

    overrides = data or {}
    if overrides:
        res = snmp.collect_snmp_device(snmp.build_probe(s, overrides))
        action = "snmp_test"
    else:
        res = snmp.collect_and_store(db, s)
        action = "snmp_collect"

    log_operation(
        db,
        category="server",
        action=action,
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="server",
        target_id=str(s.id),
        message=f"用户 {user.get('username', '未知')} 对 {s.name} 执行 SNMP "
                f"{'连接测试' if overrides else '采集'}：{'成功' if res.get('ok') else '失败'}",
        details={"ok": bool(res.get("ok")), "error": res.get("error", ""),
                 "if_count": len(res.get("interfaces", []) or []),
                 "test_only": bool(overrides)},
    )
    return {
        "ok": bool(res.get("ok")),
        "error": res.get("error", ""),
        # 要不要提示"IP 不通 / 端口被挡"那一类网络原因，设备已经明确回了错时
        # 再提示网络原因会把人带偏。见 services/snmp_collector.py 的 error_kind()。
        "error_kind": res.get("kind", ""),
        "sys_descr": res.get("sys_descr", ""),
        "sys_name": res.get("sys_name", ""),
        "uptime": res.get("uptime", 0),
        "cpu_percent": res.get("cpu_percent"),
        "memory_percent": res.get("memory_percent"),
        "interface_count": len(res.get("interfaces", []) or []),
        "network_in_mbps": res.get("network_in_mbps"),
        "network_out_mbps": res.get("network_out_mbps"),
        # 测试模式不落库，前端自己拿这份直接渲染（库里可能还是空的）
        "interfaces": res.get("interfaces", []) or [],
    }


@router.post("/{server_id}/snmp/resume")
def resume_snmp_collect(
    server_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """2026-09-21：手动解除「采集熔断」。

    熔断是采集器自己踩的刹车（连续认证失败后停采，免得一直把本机 IP 锁死）。
    管理员改好设备侧 / 本侧的 SNMPv3 凭据后点这里恢复，下一轮调度就会重新发包。

 **只清熔断，不自动采一次** —— 手动恢复往往是在改凭据的途中，立刻采多半又是一发
    失败。等下一个调度周期（5 分钟）自然重试，反而更安全。
    """
    user = _require_user_for_server(authorization, db, server_id)
    if not has_perm(db, user, "host", "network", "edit", "collect"):
        raise HTTPException(status_code=403, detail="无权限执行 SNMP 采集")
    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")

    extra = dict(s.extra_config or {})
    snmp_info = dict(extra.get("snmp") or {})
    was_paused = bool(snmp_info.get("paused_until"))
    snmp_info["paused_until"] = None
    snmp_info["pause_reason"] = ""
    # **不清零 pause_count**：它是"这台被熔断过几次"的记录，决定下次熔断罚多久。
    # 只有真正采通才会归零（见 snmp_collector.collect_and_store 的成功分支）。
    snmp_info["consecutive_failures"] = 0
    extra["snmp"] = snmp_info
    s.extra_config = extra
    db.commit()

    log_operation(
        db,
        category="server",
        action="snmp_resume",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="server",
        target_id=str(s.id),
        message=f"用户 {user.get('username', '未知')} 解除 {s.name} 的 SNMP 采集熔断",
        details={"was_paused": was_paused},
    )
    return {"ok": True, "was_paused": was_paused}


# ══ 方案 B：网络设备（交换机 / 路由器 / 防火墙）══════════════════════════
# 装不上 Agent 的设备走这一套：录入时填 IP + SNMPv3 凭据 试连（顺带识别
# 厂商 / 型号 / 类别） 存档。设备仍然落在 servers 表里，靠 device_kind 区分，
# 仪表盘 / 告警 / 分组 / 审计全部复用主机那套，不新建平行体系。


def _device_perm(db, user, op: str = None) -> None:
    """网络设备管理的权限校验（统一入口，缺权限直接 403）。

    op=None 只校验"能看"，传了 op 再校验对应写操作。
    """
    if not has_perm(db, user, "sys", "network_devices", "view"):
        raise HTTPException(status_code=403, detail="无权限访问网络设备管理")
    if op and not has_perm(db, user, "sys", "network_devices", "edit", op):
        raise HTTPException(status_code=403, detail=f"无权限执行「{op}」操作")


def _unique_server_name(db: Session, name: str) -> str:
    """name 在 servers 上唯一，撞了就加 -2 / -3 后缀（同型号多台是常态）。"""
    base = name
    i = 2
    while db.query(Server).filter(Server.name == name).first() is not None:
        name = f"{base}-{i}"
        i += 1
    return name


@router.post("/network-devices/probe")
def probe_network_device(
    data: dict = Body(...),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """测试连接（**不落库**）：拿页面表单里还没保存的凭据试一次。

    新增设备弹窗的「测试连接」按钮走这里 —— 凭据可能还没填对，绝不能先把库
    里的端口表清掉。识别结果一并返回，管理员保存前就能看到认出的是什么设备。
    """
    user = _require_user(authorization, db)
    _device_perm(db, user, "collect")

    from services import snmp_collector as snmp
    from services import device_profile as profile

    ip = str((data or {}).get("ip_address") or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="请填写设备 IP")
    # 第二轮复查 R-5（SSRF）：拿到地址先过守卫再连，以前只校验调用者有没有
    # 权限点，不校验目标，等于把服务端当成扫内网的跳板（典型目标
    # 169.254.169.254 云元数据）。详见 services/target_guard.py。
    _ok, _why = target_guard.check(ip)
    if not _ok:
        raise HTTPException(status_code=400, detail=_why)

    res = snmp.collect_snmp_device(
        snmp.build_probe_from_values(ip, (data or {}).get("snmp") or {})
    )
    info = profile.profile_from_snmp(res)

    # 编辑已有设备时前端会带上 server_id，这样这条记录能挂到该设备的「事件日志」上。
    # 不带 server_id（新增弹窗）时只能按 IP 记：那时设备还没入库，没有 id 可用。
    _sid = str((data or {}).get("server_id") or "").strip()
    _t_type, _t_id = ("server", _sid) if _sid.isdigit() else ("ip", ip)
    log_operation(
        db, category="server", action="network_device_probe",
        username=user.get("username", ""), user_id=user.get("user_id"),
        target_type=_t_type, target_id=_t_id,
        message=f"用户 {user.get('username', '未知')} 测试网络设备 {ip} 连接："
                f"{'成功' if res.get('ok') else '失败'}",
        details={"ok": bool(res.get("ok")), "error": res.get("error", ""),
                 "ip": ip, "identified": info},
    )

    return {
        "ok": bool(res.get("ok")),
        "error": res.get("error", ""),
        # 同上：给新增设备弹窗的失败框用，决定要不要挂"常见原因：IP 不通 / 端口被挡"。
        "error_kind": res.get("kind", ""),
        "sys_descr": res.get("sys_descr", ""),
        "sys_name": res.get("sys_name", ""),
        "sys_location": res.get("sys_location", ""),
        "uptime": res.get("uptime", 0),
        "cpu_percent": res.get("cpu_percent"),
        "memory_percent": res.get("memory_percent"),
        "interface_count": len(res.get("interfaces", []) or []),
        "vendor": info.get("vendor", ""),
        "model": info.get("model", ""),
        "category": info.get("category", "other"),
        "category_label": info.get("category_label", "其他设备"),
    }


@router.post("/network-devices")
def create_network_device(
    data: dict = Body(...),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """新增网络设备：先试连，通了才入库并立刻采一次。

    「先试连再存」是刻意的 —— 存一台连不通的设备，列表里会多一行永远离线的
    记录，管理员还得回头删。连不通就直接 400 并把设备的报错原样带回去。
    """
    user = _require_user(authorization, db)
    _device_perm(db, user, "add")

    from services import snmp_collector as snmp
    from services import device_profile as profile

    body = data or {}
    ip = str(body.get("ip_address") or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="请填写设备 IP")
    # 第二轮复查 R-5（SSRF）：同上，新增设备试连前也要先过守卫。
    _ok, _why = target_guard.check(ip)
    if not _ok:
        raise HTTPException(status_code=400, detail=_why)
    snmp_cfg = body.get("snmp") or {}
    if not str(snmp_cfg.get("snmp_username") or "").strip():
        raise HTTPException(status_code=400, detail="请填写 SNMPv3 用户名")

    res = snmp.collect_snmp_device(snmp.build_probe_from_values(ip, snmp_cfg))
    if not res.get("ok"):
        log_operation(
            db, category="server", action="network_device_add_failed", level="warning",
            status="failed",
            username=user.get("username", ""), user_id=user.get("user_id"),
            target_type="ip", target_id=ip,
            message=f"用户 {user.get('username', '未知')} 新增网络设备 {ip} 失败：{res.get('error', '')}",
            details={"ip": ip, "error": res.get("error", "")},
        )
        raise HTTPException(
            status_code=400,
            detail=f"连接失败：{res.get('error') or '设备无响应'}（已放弃保存）",
        )

    info = profile.profile_from_snmp(res)
    name = str(body.get("name") or "").strip() or str(res.get("sys_name") or "").strip()
    if not name:
        label = info.get("category_label") or "网络设备"
        vendor = info.get("vendor") or ""
        name = f"{vendor}{label}-{ip}" if vendor else f"{label}-{ip}"
    name = _unique_server_name(db, name)

    now = datetime.now(timezone.utc)

    def _num(key, default):
        try:
            return int(snmp_cfg.get(key) or default)
        except Exception:  # noqa: BLE001
            return default

    # WEB 管理入口（「WEB管理」页签）。地址固定用上面的管理 IP，只让管理员定协议和端口。
    web_cfg = body.get("web") or {}
    web_proto = str(web_cfg.get("web_protocol") or "").strip().lower() or "https"
    if web_proto not in ("http", "https"):
        raise HTTPException(status_code=400, detail="WEB 管理协议只能是 http 或 https")
    try:
        web_port = int(web_cfg.get("web_port") or 443)
    except Exception:  # noqa: BLE001
        web_port = 443
    if not (1 <= web_port <= 65535):
        raise HTTPException(status_code=400, detail="WEB 管理端口需在 1 ~ 65535 之间")

    s = Server(
        name=name,
        ip_address=ip,
        os_type="",
        network_env=str(body.get("network_env") or "内网"),
        business_system=str(body.get("business_system") or ""),
        # 网络设备从"主动连上去采"的主机循环里排除掉（见 services/collector.py）
        protocol="snmp",
        device_kind="network",
        device_vendor=info.get("vendor", ""),
        device_model=info.get("model", ""),
        device_category=info.get("category") or "other",
        description=str(body.get("description") or ""),
        snmp_enabled=1,
        snmp_version="3",
        snmp_port=_num("snmp_port", 161),
        snmp_username=str(snmp_cfg.get("snmp_username") or ""),
        snmp_security_level=str(snmp_cfg.get("snmp_security_level") or "authPriv"),
        snmp_auth_proto=str(snmp_cfg.get("snmp_auth_proto") or "SHA"),
        snmp_priv_proto=str(snmp_cfg.get("snmp_priv_proto") or "AES"),
        snmp_context=str(snmp_cfg.get("snmp_context") or ""),
        snmp_auth_password=encrypt_secret(str(snmp_cfg.get("snmp_auth_password") or "")),
        snmp_priv_password=encrypt_secret(str(snmp_cfg.get("snmp_priv_password") or "")),
        web_protocol=web_proto,
        web_port=web_port,
        status="monitored",
        last_seen=now,
        join_time=now,
        online_time=now,
    )
    db.add(s)
    db.commit()
    db.refresh(s)

    # 立刻采一次：端口表 / 首条指标马上就有，不用等下一个 5 分钟周期
    try:
        snmp.collect_and_store(db, s)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"新增设备 {name} 首次采集失败（不影响入库）：{e}")

    log_operation(
        db, category="server", action="network_device_add",
        username=user.get("username", ""), user_id=user.get("user_id"),
        target_type="server", target_id=str(s.id),
        message=f"用户 {user.get('username', '未知')} 新增网络设备 {name}（{ip}）",
        details={"ip": ip, "vendor": info.get("vendor", ""),
                 "model": info.get("model", ""),
                 "category": info.get("category", ""),
                 "if_count": len(res.get("interfaces", []) or [])},
    )
    return {
        "id": s.id,
        "name": s.name,
        "ip_address": s.ip_address,
        "device_vendor": s.device_vendor,
        "device_model": s.device_model,
        "device_category": s.device_category,
        "interface_count": len(res.get("interfaces", []) or []),
    }


@router.post("/{server_id}/network/connect")
def connect_network_device(
    server_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """连接：启用 SNMP 采集，并把它放回侧边栏主机列表（status → monitored）。"""
    user = _require_user_for_server(authorization, db, server_id)
    _device_perm(db, user, "connect")

    from services import snmp_collector as snmp

    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    if (s.device_kind or "host") != "network":
        raise HTTPException(status_code=400, detail="该主机不是网络设备，请用主机管理操作")

    now = datetime.now(timezone.utc)
    s.snmp_enabled = 1
    s.status = "monitored"
    if not s.join_time:
        s.join_time = now
    s.online_time = now
    s.offline_time = None
    db.commit()

    res = snmp.collect_and_store(db, s)
    log_operation(
        db, category="server", action="network_device_connect",
        username=user.get("username", ""), user_id=user.get("user_id"),
        target_type="server", target_id=str(s.id),
        message=f"用户 {user.get('username', '未知')} 连接网络设备 {s.name}："
                f"{'成功' if res.get('ok') else '失败'}",
        details={"ok": bool(res.get("ok")), "error": res.get("error", "")},
    )
    return {
        "ok": bool(res.get("ok")),
        "error": res.get("error", ""),
        "status": s.status,
        "interface_count": len(res.get("interfaces", []) or []),
    }


@router.post("/{server_id}/network/disconnect")
def disconnect_network_device(
    server_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """断开：停采集、移出侧边栏主机列表（status → disconnected），但**保留档案**。

    断开 ≠ 删除。凭据、分组关系、历史指标都留着，管理员再点「连接」就能回到
    原样 —— 换下来的交换机、临时下电的防火墙不该在列表里消失。
    """
    user = _require_user_for_server(authorization, db, server_id)
    _device_perm(db, user, "connect")

    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    if (s.device_kind or "host") != "network":
        raise HTTPException(status_code=400, detail="该主机不是网络设备，请用主机管理操作")

    now = datetime.now(timezone.utc)
    s.snmp_enabled = 0
    s.status = "disconnected"
    s.offline_time = now
    db.commit()

    # 端口表清掉：断开后留在列表里的旧端口会被误当成设备当前状态
    removed = 0
    try:
        from models import NetworkInterface

        removed = db.query(NetworkInterface).filter(
            NetworkInterface.server_id == server_id
        ).delete(synchronize_session=False)
        db.commit()
    except Exception as e:  # noqa: BLE001
        logger.warning(f"清理 {s.name} 端口表失败：{e}")

    log_operation(
        db, category="server", action="network_device_disconnect",
        username=user.get("username", ""), user_id=user.get("user_id"),
        target_type="server", target_id=str(s.id),
        message=f"用户 {user.get('username', '未知')} 断开网络设备 {s.name}",
        details={"removed_interfaces": removed},
    )
    return {"ok": True, "status": s.status, "removed_interfaces": removed}


@router.post("/{server_id}/revoke-cert")
def revoke_server_cert(
    server_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """吊销该主机的设备身份 —— 已登记的设备公钥作废。

    吊销后：
      - 该设备的所有签名请求立刻被拒（routes/agent.py `_authenticate` 查 `key.revoked`）；
      - 重新登记公钥同样被拦（`/enroll` 的 `key.revoked` 分支）。

    重新接入的唯一路径：管理员先「移出管理」再「加入管理」，`update_server_status`
    会把吊销标记洗掉并把身份状态回到 `approved` —— 即强制再走一次人工准入。

    刻意**保留** `pub_key`：审计上要留得住"这台设备当初登记的是哪把公钥"。
    吊销靠 `revoked` 标记生效，留着公钥不会让它重新被认可。

    同时重新生成配对码：吊销后这台机器要重新准入，管理员必须能拿新码去和
    Agent 面板上显示的那串核对（`list_servers` 对 revoked 的行会照常下发配对码）。
    """
    user = _require_user_for_server(authorization, db, server_id)
    if not has_perm(db, user, "sys", "register", "edit", "approve"):
        raise HTTPException(status_code=403, detail="无权限吊销设备身份")
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    from models import AgentKey

    key = db.query(AgentKey).filter(AgentKey.server_id == server_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="该主机没有设备身份记录")
    if key.revoked:
        return {"status": "already_revoked", "node_id": key.node_id or ""}

    from services import agent_identity as aid

    now = datetime.now(timezone.utc)
    key.revoked = 1
    key.revoked_at = now
    key.revoked_reason = "管理员吊销"
    key.identity_state = "revoked"
    key.pairing_code = aid.new_pairing_code()
    db.commit()

    log_operation(
        db,
        category="server",
        action="revoke_cert",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="server",
        target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 吊销了主机 {server.name} 的设备身份",
        details={"server_name": server.name, "node_id": key.node_id or ""},
    )
    return {"status": "revoked", "node_id": key.node_id or ""}


@router.post("/{server_id}/rotate-agent-token")
def rotate_agent_token(
    server_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """2026-09-23 开源加固 ⑤：轮换该主机的静态 Agent token。

    轮换前这把 token 从注册那一刻起永不改变、也没有任何接口能让它失效 ——
    `agent_config.json` 泄露一次，这台机器就能被永久冒充，唯一的补救是删库重来。

    轮换后：
      - 旧 token 进入**宽限期**（默认 24 小时），期间仍被接受，好让跑在外的
        Agent 靠心跳把新 token 领走（心跳响应里带 `token`）；
      - 宽限期一过，旧 token 彻底作废。

 方案 A 下这把 token **只用于服务端回调本机 9998**（下行）；设备上行认证
      走的是私钥签名，不受轮换影响。轮换换的是那把下行钥匙。
    """
    user = _require_user_for_server(authorization, db, server_id)
    if not has_perm(db, user, "sys", "register", "edit", "approve"):
        raise HTTPException(status_code=403, detail="无权限轮换主机凭据")
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    from models import AgentKey
    from services.agent_auth import rotate_agent_secret, ROTATE_GRACE_SECONDS

    key = db.query(AgentKey).filter(AgentKey.server_id == server_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="该主机没有设备身份记录")
    if key.revoked:
        raise HTTPException(status_code=400, detail="该设备已被吊销，请先重新准入再轮换")

    new_token = rotate_agent_secret(key, ROTATE_GRACE_SECONDS)
    db.commit()

    log_operation(
        db,
        category="server",
        action="rotate_agent_token",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="server",
        target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 轮换主机 {server.name} 的 Agent 静态 token",
        details={"server_name": server.name,
                 "prev_valid_until": str(key.secret_key_prev_until or ""),
                 "grace_seconds": ROTATE_GRACE_SECONDS},
    )
    # 新 token **不回给浏览器**：它是一台主机的长期凭据，落进浏览器缓存 /
    # HTTP 日志等于又制造一份副本。真正需要它的是那台 Agent，由它自己用心跳来领。
    return {"status": "rotated",
            "prev_valid_until": key.secret_key_prev_until.isoformat()
            if key.secret_key_prev_until else "",
            "grace_seconds": ROTATE_GRACE_SECONDS}


@router.post("/{server_id}/reset-agent-baseline")
def reset_agent_baseline(
    server_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """2026-09-23：「重新登记」该主机的 Agent 完整性基线。

    开源加固 ⑥ 让 Agent 自报代码指纹、服务端跟基线比，对不上就记
    `agent_tamper_suspected`。但**指纹变了不一定是被改造** —— 也可能是我们自己
    的合法变更：同一版本号重新打了包、Agent 侧修了 bug 重发、构建工具升级导致
    产物字节变化。这些情况下版本号没变、指纹变了，于是每台机器每 5 秒刷一条
    "疑似被改造"（实测 3 台主机半小时各刷了 30+ 条），很快就把审计日志淹掉、
    也没人再信这个告警了。

    这个接口就是给管理员一个"承认现在这份代码是官方的"的开关：
    清掉基线和篡改标记，下一次心跳会走"首次登记"分支，把**当前**指纹记为新基线。

 它是个**信任动作**，不是取证动作：调用前请确认这批 Agent 确实是你自己发的包。
    真怀疑某台机器被改造时，别点它 —— 点了等于替攻击者把痕迹擦掉。
    """
    user = _require_user_for_server(authorization, db, server_id)
    if not has_perm(db, user, "sys", "register", "edit", "approve"):
        raise HTTPException(status_code=403, detail="无权限重新登记完整性基线")
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    from models import AgentKey

    key = db.query(AgentKey).filter(AgentKey.server_id == server_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="该主机没有设备身份记录")

    old_digest = key.self_digest or ""
    old_tamper = key.tamper_at

    key.self_digest = ""
    key.self_digest_version = ""
    key.self_digest_at = None
    key.tamper_at = None
    key.tamper_detail = ""
    db.commit()

    log_operation(
        db,
        category="server",
        action="reset_agent_baseline",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="server",
        target_id=str(server_id),
        message=(f"用户 {user.get('username', '未知')} 重新登记主机 {server.name} "
                 f"的 Agent 完整性基线（原基线 {(old_digest or '无')[:12]}…"
                 f"{'；原篡改标记已清除' if old_tamper else ''}）"),
        details={"server_name": server.name,
                 "old_digest": old_digest,
                 "old_tamper_at": str(old_tamper or "")},
    )
    return {"status": "baseline_reset",
            "server_id": server_id,
            "old_digest": old_digest,
            "had_tamper_flag": old_tamper is not None}


class PowerAction(BaseModel):
    action: str


@router.post("/{server_id}/power")
def power_control(
    server_id: int,
    action: PowerAction,
    request: Request,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """Forward restart/shutdown command to the Agent on the target host."""
    user = _require_user(authorization, db)
    if not has_perm(db, user, "host", "status", "edit", "power"):
        raise HTTPException(status_code=403, detail="无权限执行重启/关机操作")
    if not can_manage_server(db, user, server_id):
        raise HTTPException(status_code=403, detail="该主机不在当前角色的管理范围内")
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    if server.protocol != "agent":
        raise HTTPException(status_code=400, detail="仅支持通过 Agent 协议管理的主机")

    act = action.action.lower()
    if act not in ("restart", "shutdown"):
        raise HTTPException(status_code=400, detail="action must be 'restart' or 'shutdown'")

    port = server.agent_port or 9998
    url = f"https://{server.ip_address}:{port}/power"

    # 2026-09-23 动态审计 D-1：原来这里无条件采信 X-Forwarded-For（客户端可伪造），
    # 规则统一到 services/client_ip.py，默认只认直连 IP。
    client_ip = get_client_ip(request)

    try:
        from services.agent_auth import agent_headers, agent_ca_verify
        resp = _requests.post(url, json={"action": act}, timeout=15,
                              headers=agent_headers(server),
                              verify=agent_ca_verify())  # P1-1：CA 校验 Agent 服务器证书
    except _requests.ConnectionError:
        raise HTTPException(status_code=503, detail=f"无法连接到 Agent {server.ip_address}:{port}")
    except _requests.Timeout:
        raise HTTPException(status_code=504, detail="Agent 响应超时")

    label = "重启" if act == "restart" else "关机"
    status = "success" if resp.ok else "failed"
    log_operation(
        db,
        category="server",
        action="power_control",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        ip_address=client_ip,
        target_type="server",
        target_id=str(server_id),
        status=status,
        message=f"用户 {user.get('username', '未知')} 对主机 {server.name} 执行 {label} 操作",
        details={"action": act, "server_name": server.name, "agent_ip": server.ip_address, "agent_port": port, "response_status": resp.status_code},
    )

    if not resp.ok:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text
        raise HTTPException(status_code=resp.status_code, detail=detail)

    return resp.json()


@router.post("/{server_id}/trigger-collect")
def trigger_server_collect(server_id: int, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    """Notify the agent to perform an immediate data collection."""
    user = _require_user_for_server(authorization, db, server_id)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    stored = server.extra_config or {}
    if not isinstance(stored, dict):
        stored = {}
    from datetime import timezone
    stored["trigger_collect_at"] = datetime.now(timezone.utc).isoformat()
    server.extra_config = stored
    db.commit()
    log_operation(
        db,
        category="server",
        action="trigger_collect",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="server",
        target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 触发主机 {server.name} 立即采集",
        details={"server_name": server.name},
    )
    return {"status": "ok", "message": "已通知 Agent 立即采集", "server_id": server.id}


@router.get("/{server_id}/pending-services")
def get_pending_services(server_id: int, authorization: Optional[str] = Header(None),
                         db: Session = Depends(get_db)):
    """Return the agent-pushed pending services list for the service monitor.

    This is split from get_server_detail because the list can be very large
    (hundreds of processes) and would slow down every host detail request.
    """
    _require_user_for_server(authorization, db, server_id)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    extra = server.extra_config or {}
    if not isinstance(extra, dict):
        extra = {}
    return {
        "pending_services": extra.get("pending_services") or [],
        "dangerous_ports": extra.get("dangerous_ports") or [],
        "service_filter": extra.get("service_filter") or None,
        "service_blacklist": extra.get("service_blacklist") or [],
        "service_whitelist": extra.get("service_whitelist") or [],
    }


@router.get("/{server_id}/agent-commands")
def get_agent_commands(server_id: int, authorization: Optional[str] = Header(None),
                       db: Session = Depends(get_db)):
    """Return queued agent commands and recent execution results.

    Used by the frontend to show whether an operation sent to the agent was
    received and executed successfully.
    """
    _require_user_for_server(authorization, db, server_id)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    extra = server.extra_config or {}
    if not isinstance(extra, dict):
        extra = {}
    return {
        "pending_terminate": extra.get("pending_terminate") or [],
        "last_terminate_results": extra.get("last_terminate_results") or [],
        "trigger_collect_at": extra.get("trigger_collect_at"),
    }


@router.post("/{server_id}/debug-processes")
def toggle_debug_processes(
    server_id: int,
    payload: dict = Body(default={}),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """Toggle raw process list debugging for agent-protocol servers.

    When enabled, the agent includes the full raw process list in its next
    push. This is useful to verify whether a process is visible to psutil.
    """
    user = _require_user_for_server(authorization, db, server_id)
    if not (bool(user.get("is_admin")) or user.get("role") == "admin"):
        raise HTTPException(status_code=403, detail="仅管理员可启用进程调试模式")
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    if server.protocol != "agent":
        raise HTTPException(status_code=400, detail="仅支持 Agent 协议主机")

    extra = server.extra_config or {}
    if not isinstance(extra, dict):
        extra = {}
    enabled = bool(payload.get("enabled", not extra.get("debug_push_processes")))
    extra["debug_push_processes"] = enabled
    from datetime import timezone
    extra["trigger_collect_at"] = datetime.now(timezone.utc).isoformat()
    server.extra_config = extra
    flag_modified(server, "extra_config")
    db.commit()

    log_operation(
        db,
        category="server",
        action="debug_processes",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="server",
        target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 设置主机 {server.name} 进程调试模式为 {'开启' if enabled else '关闭'}",
        details={"server_name": server.name, "enabled": enabled},
    )
    return {
        "status": "ok",
        "enabled": enabled,
        "message": f"已{'开启' if enabled else '关闭'}进程调试模式，下次 Agent 推送将包含完整进程列表",
        "server_id": server.id,
    }


@router.get("/{server_id}/raw-processes")
def get_raw_processes(server_id: int, authorization: Optional[str] = Header(None),
                      db: Session = Depends(get_db)):
    """Return the last raw process list received from an agent-protocol server."""
    _require_user_for_server(authorization, db, server_id)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    extra = server.extra_config or {}
    if not isinstance(extra, dict):
        extra = {}
    return {
        "enabled": bool(extra.get("debug_push_processes")),
        "count": extra.get("raw_processes_count", 0),
        "updated_at": extra.get("raw_processes_updated_at"),
        "processes": extra.get("raw_processes") or [],
    }


@router.post("/{server_id}/check-services")
def check_server_services(server_id: int, authorization: Optional[str] = Header(None),
                          db: Session = Depends(get_db)):
    """Manually trigger a real service status check for a server."""
    _require_user_for_server(authorization, db, server_id)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    services = db.query(MonitoredService).filter(MonitoredService.server_id == server_id).all()
    if not services:
        return {"checked": 0, "message": "No monitored services", "results": {}}

    from services.collector import _check_services

    _check_services(db, server)
    db.commit()

    results = {
        str(svc.id): {
            "name": svc.name,
            "image_name": svc.image_name or svc.process_name or "",
            "port": svc.port,
            "process_name": svc.process_name,
            "cpu_percent": svc.cpu_percent or 0.0,
            "memory_percent": svc.memory_percent or 0.0,
            "disk_percent": svc.disk_percent or 0.0,
            "disk_mbps": svc.disk_mbps or 0.0,
            "disk_read_mbps": svc.disk_read_mbps or 0.0,
            "disk_write_mbps": svc.disk_write_mbps or 0.0,
            "network_mbps": svc.network_mbps or 0.0,
            "network_in_mbps": svc.network_in_mbps or 0.0,
            "network_out_mbps": svc.network_out_mbps or 0.0,
            "alive_status": svc.alive_status or svc.status or "unknown",
            "alert_status": svc.alert_status or "normal",
            "running_status": svc.running_status or svc.status or "unknown",
            "pid": svc.pid or 0,
            "ppid": svc.ppid or 0,
            "path": svc.path or "",
            "start_time": svc.start_time or "",
            "cmdline": svc.cmdline or "",
            "username": svc.username or "",
            "status": svc.status,
            "last_checked": svc.last_checked.isoformat() if svc.last_checked else None,
        }
        for svc in services
    }
    return {"checked": len(services), "message": "Service check completed", "results": results}


@router.post("/{server_id}/services/{service_id}/terminate")
def terminate_server_service(
    server_id: int,
    service_id: str,
    data: dict,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """Terminate a remote process backing a monitored service.

    Body: {"mode": "graceful" | "force"}  (default: graceful)
    """
    user = _require_user(authorization, db)
    if not has_perm(db, user, "host", "services", "edit", "terminate"):
        raise HTTPException(status_code=403, detail="无权限终止主机进程")
    if not can_manage_server(db, user, server_id):
        raise HTTPException(status_code=403, detail="该主机不在当前角色的管理范围内")
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    mode = (data.get("mode") or "graceful").lower()
    if mode not in {"graceful", "force"}:
        raise HTTPException(status_code=400, detail="mode 必须是 graceful 或 force")

    protocol = (server.protocol or "").upper()

    if protocol == "AGENT":
        extra = server.extra_config or {}
        if not isinstance(extra, dict):
            extra = {}

        pending_services = extra.get("pending_services") or []
        matched_pending = next(
            (p for p in pending_services if str(p.get("id")) == str(service_id)),
            None,
        )

        svc = None
        if service_id.isdigit():
            svc = db.query(MonitoredService).filter(
                MonitoredService.id == int(service_id),
                MonitoredService.server_id == server_id,
            ).first()

        if not svc and not matched_pending:
            raise HTTPException(status_code=404, detail="Service not found")

        # Enforce four-level operation policy. Core system processes are never
        # allowed to be terminated, even if the caller somehow reached here.
        op_level = (
            matched_pending.get("operation_level")
            if matched_pending
            else "terminate_with_confirm"
        )
        if op_level == "view_only":
            raise HTTPException(status_code=403, detail="核心系统进程禁止操作")

        pending = extra.get("pending_terminate") or []
        if not isinstance(pending, list):
            pending = []

        pid = int(matched_pending.get("pid") if matched_pending else (svc.pid if svc else 0) or 0)
        name = (
            (matched_pending.get("image_name") or matched_pending.get("process_name") or matched_pending.get("name") or "")
            if matched_pending
            else (svc.image_name or svc.process_name or svc.name or "")
        )

        pending.append({
            "id": f"term_{datetime.now(timezone.utc).timestamp()}",
            "service_id": str(service_id),
            "pid": pid,
            "name": name,
            "mode": mode,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        extra["pending_terminate"] = pending
        extra["trigger_collect_at"] = datetime.now(timezone.utc).isoformat()
        server.extra_config = extra
        flag_modified(server, "extra_config")
        db.commit()
        label = "强制终止" if mode == "force" else "退出进程"
        log_operation(
            db,
            category="service",
            action="terminate",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            target_type="service",
            target_id=str(service_id),
            message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 上执行{label}：{name or service_id}",
            details={"mode": mode, "service_name": name, "server_name": server.name, "pid": pid},
        )
        return {
            "success": True,
            "command_id": pending[-1]["id"],
            "message": f"已通知 Agent 执行{label}：{name or service_id}",
        }

    svc = db.query(MonitoredService).filter(
        MonitoredService.id == int(service_id) if service_id.isdigit() else -1,
        MonitoredService.server_id == server_id,
    ).first()
    if not svc:
        raise HTTPException(status_code=404, detail="Service not found")

    result = terminate_service(server, svc, mode)
    if result.get("success"):
        log_operation(
            db,
            category="service",
            action="terminate",
            level="info",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            target_type="service",
            target_id=str(service_id),
            message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 上{('强制终止' if mode == 'force' else '退出进程')}成功：{svc.name}",
            details={"mode": mode, "service_name": svc.name, "server_name": server.name, "result": result},
        )
        return {"success": True, "message": result.get("message", "操作成功")}

    log_operation(
        db,
        category="service",
        action="terminate",
        level="error",
        status="failed",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="service",
        target_id=str(service_id),
        message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 上{('强制终止' if mode == 'force' else '退出进程')}失败：{svc.name}，{result.get('message', '未知错误')}",
        details={"mode": mode, "service_name": svc.name, "server_name": server.name, "result": result},
    )
    raise HTTPException(status_code=502, detail=result.get("message", "终止进程失败"))


@router.post("/{server_id}/detect")
def detect_server(server_id: int, authorization: Optional[str] = Header(None),
                  db: Session = Depends(get_db)):
    """Re-detect server info (OS, hardware, disks) using real remote commands."""
    _require_user_for_server(authorization, db, server_id)
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    server.os_type = ""
    server.cpu_cores = 0
    server.total_memory_gb = 0
    server.disk_partitions = []
    db.commit()

    try:
        from services.remote_agent import RemoteAgent
        agent = RemoteAgent(server)
        if agent.connect():
            info = agent.detect()
            agent.close()
            if info:
                server.os_type = info.get("os_type") or ""
                server.cpu_cores = info.get("cpu_cores") or 0
                server.total_memory_gb = info.get("total_memory_gb") or 0.0
                disks = info.get("disk_partitions") or []
                if disks:
                    server.disk_partitions = disks
                    server.total_disk_gb = round(sum(p["total_gb"] for p in disks), 1)
                db.commit()
                db.refresh(server)
                print(f"[Detect] Real detection success for {server.name}: OS={server.os_type}, CPU={server.cpu_cores}, MEM={server.total_memory_gb}, Disks={len(disks)}")
    except Exception as e:
        print(f"[Detect] Detection failed for {server.name}: {e}")

    if not server.os_type or not server.cpu_cores:
        from services.collector import _detect_os, _detect_hardware, _detect_disk_partitions
        if not server.os_type:
            server.os_type = _detect_os(server)
        if not server.cpu_cores:
            spec = _detect_hardware(server)
            server.cpu_cores = spec[0]
            server.total_memory_gb = spec[1] if not server.total_memory_gb else server.total_memory_gb
        if not server.disk_partitions:
            server.disk_partitions = _detect_disk_partitions(server)
            server.total_disk_gb = round(sum(p["total_gb"] for p in server.disk_partitions), 1)
        db.commit()
        db.refresh(server)

    return {
        "os_type": server.os_type or "",
        "cpu_cores": server.cpu_cores or 0,
        "total_memory_gb": server.total_memory_gb or 0,
        "disk_partitions": server.disk_partitions or [],
    }


def _create_default_services(db: Session, server: Server):
    """Create default monitored services based on business system type.

    Port checks take precedence; process_name is used only when port is 0.
    Entries match common Windows services where possible.
    """
    is_win = (server.protocol or "").upper() == "WINRM" or "windows" in (server.os_type or "").lower()

    service_map = {
        "文件服务器": [
            {"name": "SMB文件共享", "port": 445, "process_name": "svchost", "description": "SMB/CIFS 文件共享服务"},
            {"name": "FTP服务", "port": 21, "process_name": "ftpsvc", "description": "FTP 文件传输服务"},
        ],
        "ERP服务器": [
            {"name": "ERP应用服务", "port": 8080, "process_name": "java", "description": "ERP 核心应用"},
            {"name": "ERP数据库", "port": 3306, "process_name": "mysqld" if not is_win else "mysqld", "description": "ERP 数据库服务"},
        ],
        "金蝶服务器": [
            {"name": "金蝶中间件", "port": 6888, "process_name": "kdsvrmgr", "description": "金蝶中间件服务"},
            {"name": "SQL Server数据库", "port": 1433, "process_name": "sqlservr", "description": "金蝶数据库服务"},
        ],
        "金蝶EAS": [
            {"name": "EAS应用服务", "port": 6888, "process_name": "java", "description": "金蝶 EAS 应用服务"},
            {"name": "SQL Server数据库", "port": 1433, "process_name": "sqlservr", "description": "EAS 数据库服务"},
        ],
        "Web服务器": [
            {"name": "HTTP服务", "port": 80, "process_name": "nginx" if not is_win else "inetinfo", "description": "HTTP Web 服务"},
            {"name": "HTTPS服务", "port": 443, "process_name": "nginx" if not is_win else "inetinfo", "description": "HTTPS Web 服务"},
        ],
        "数据库服务器": [
            {"name": "SQL Server数据库", "port": 1433, "process_name": "sqlservr", "description": "SQL Server 数据库"},
            {"name": "MySQL数据库", "port": 3306, "process_name": "mysqld", "description": "MySQL 数据库"},
            {"name": "PostgreSQL数据库", "port": 5432, "process_name": "postgres", "description": "PostgreSQL 数据库"},
            {"name": "Redis缓存", "port": 6379, "process_name": "redis-server", "description": "Redis 缓存服务"},
        ],
        "多可档案": [
            {"name": "多可档案服务", "port": 80, "process_name": "docollect", "description": "多可档案系统主服务"},
        ],
        "域控服务器": [
            {"name": "DNS服务", "port": 53, "process_name": "dns", "description": "DNS 域名解析服务"},
            {"name": "Active Directory", "port": 389, "process_name": "lsass", "description": "AD 域认证服务"},
        ],
    }

    services = service_map.get(server.business_system, [])
    for svc in services:
        proc = svc.get("process_name", "")
        ms = MonitoredService(
            server_id=server.id,
            name=svc["name"],
            image_name=proc,
            port=svc["port"],
            process_name=proc,
            status="unknown",
            description=svc["description"],
        )
        db.add(ms)
    db.commit()
