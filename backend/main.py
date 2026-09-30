"""Main FastAPI application — VigilServe server monitoring platform.

Production mode: set env PRODUCTION=1 to serve frontend from ../frontend/dist
and disable all simulated data. All metrics come from real WinRM/SSH.
"""
import json
import os
import sys
import time
import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(Path(__file__).with_name('backend.log'), encoding='utf-8', mode='a'),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger('backend')

try:
    from winpty import PtyProcess as WinPtyProcess
except Exception:
    WinPtyProcess = None

from typing import Optional
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Depends, Header
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.staticfiles import StaticFiles
from apscheduler.schedulers.background import BackgroundScheduler

from database import init_db, SessionLocal, get_db
from models import Server, MetricSnapshot, Alert, MonitoredService, OperationLog, GlobalConfig, AgentUpdateTask
from services.collector import collect_all_servers
from services.collector import _check_services
from services.audit_logger import log_operation
from services.client_ip import get_client_ip
from services import net_guard
from routes.auth import get_current_user_full, has_perm, can_manage_server, seed_admin
# 🚨 2026-09-23：`meshcentral` 路由已**整体下线**（用户拍板删除）。
from routes import servers, metrics, dashboard, auth, config, agent, file_explorer, logs, agent_update, roles, host_groups, host_info, rdp as rdp_routes, tls as tls_routes, security, network_web, traps

PRODUCTION = os.environ.get("PRODUCTION", "0") == "1"



class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket, subprotocol: str | None = None):
        """接受连接。subprotocol 用于回显客户端请求的子协议（安全加固阶段 3）。"""
        try:
            await ws.accept(subprotocol=subprotocol)
        except TypeError:
            await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        msg = json.dumps(data, default=str)
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except Exception:
                pass


manager = ConnectionManager()



_last_service_check = 0.0


def _retention_days(cfg: dict, key: str, old_key: str, default: int = 30) -> int:
    """Read retention in days, falling back to old month-based key * 30."""
    value = cfg.get(key, {}).get("value")
    if value:
        try:
            return int(value)
        except ValueError:
            pass
    old_value = cfg.get(old_key, {}).get("value")
    if old_value:
        try:
            return int(old_value) * 30
        except ValueError:
            pass
    return default


def cleanup_old_logs():
    """Purge alert and operation logs older than the configured retention."""
    db = SessionLocal()
    try:
        from routes.config import get_config_dict

        cfg = get_config_dict(db)
        alert_days = _retention_days(cfg, "alert_log_retention_days", "alert_log_retention_months", 30)
        op_days = _retention_days(cfg, "operation_log_retention_days", "operation_log_retention_months", 30)
        now = datetime.now(timezone.utc)

        alert_cutoff = now - timedelta(days=alert_days)
        op_cutoff = now - timedelta(days=op_days)

        alert_deleted = db.query(Alert).filter(Alert.timestamp < alert_cutoff).delete(synchronize_session=False)
        op_deleted = db.query(OperationLog).filter(OperationLog.timestamp < op_cutoff).delete(synchronize_session=False)
        db.commit()
        if alert_deleted or op_deleted:
            logger.info(f"[LogCleanup] purged alert={alert_deleted} operation={op_deleted} older than retention")
    except Exception as e:
        logger.exception(f"[LogCleanup] failed: {e}")
    finally:
        db.close()


def reclaim_lost_certificates():
    """S4：每天回收一次失联主机的设备证书（评估文档 §4.3）。

    证书到期 ≠ 失效 —— 只要那份 node.key 还在，离职/报废的机器就能一直续期。
    人工盯不住「谁三个月没心跳了」，交给定时任务兜底。天数由 `cert_reclaim_days`
    配置（默认 90，0 = 关闭）。
    """
    db = SessionLocal()
    try:
        from services.cert_reclaim import reclaim_lost_certificates as _reclaim

        res = _reclaim(db)
        if res.get("disabled"):
            logger.info("[CertReclaim] 已关闭（cert_reclaim_days=0）")
        elif res.get("reclaimed"):
            logger.warning(
                f"[CertReclaim] 自动吊销 {res['reclaimed']} 台失联主机"
                f"（阈值 {res['days']} 天，检查 {res['checked']} 台）"
            )
        else:
            logger.info(f"[CertReclaim] 无需回收（检查 {res.get('checked', 0)} 台）")
    except Exception as e:  # noqa: BLE001
        logger.exception(f"[CertReclaim] failed: {e}")
    finally:
        db.close()


def collect_snmp_devices():
    """S5：SNMPv3 采集网络设备（交换机 / 路由器 / 防火墙）。

    只采 `snmp_enabled=1` 的主机。pysnmp 7 是全异步 API，`services/snmp_collector.py`
    内部用 `asyncio.run()` 包了一层 —— 跑在 APScheduler 的线程里，不会碰到
    FastAPI 的事件循环。
    """
    db = SessionLocal()
    try:
        from services.snmp_collector import collect_all_snmp_devices as _collect

        res = _collect(db)
        if res.get("checked"):
            level = logger.warning if res.get("failed") else logger.info
            # skipped = 熔断中（连续认证失败后主动停采），不是故障，单独报出来
            extra = f"，熔断暂停 {res['skipped']}" if res.get("skipped") else ""
            level(
                f"[SNMP] 采集 {res['checked']} 台：成功 {res['ok']}，失败 {res['failed']}{extra}"
            )
    except Exception as e:  # noqa: BLE001
        logger.exception(f"[SNMP] failed: {e}")
    finally:
        db.close()


def collect_network_device_logs():
    """路线 A：只读 SSH 轮询，把网络设备内部的运行日志拉回服务端存档（2026-09-21）。

    为什么单开一个任务而不是塞进 SNMP 那轮：两条链路**凭据不同**（SNMPv3 vs CLI）、
    **协议不同**（UDP 161 vs SSH 22）、失败原因也完全不同。混在一起的话，
    一个挂了会把另一个的"上次采集时间"一起带歪，排查时根本分不清是谁的问题。

    只发 display 命令，不改设备配置；没配 CLI 凭据的设备会被直接跳过。
    """
    db = SessionLocal()
    try:
        from services.network_log_collector import collect_all_device_logs as _collect

        res = _collect(db)
        if res.get("checked"):
            level = logger.warning if res.get("failed") else logger.info
            level(
                f"[DeviceLog] 采集 {res['checked']} 台：成功 {res['ok']}，失败 {res['failed']}，"
                f"新增 {res['inserted']} 条（重复 {res['skipped']}）"
            )
            for e in (res.get("errors") or [])[:5]:
                logger.warning(f"[DeviceLog] {e}")
    except Exception as e:  # noqa: BLE001
        logger.exception(f"[DeviceLog] failed: {e}")
    finally:
        db.close()


def check_all_services():
    """Dedicated service status check cycle for non-agent servers.

    Runs on its own interval (service_check_interval) so service monitoring
    is independent of the metric collection cycle.
    """
    global _last_service_check

    db = SessionLocal()
    try:
        from routes.config import get_config_dict

        cfg = get_config_dict(db)
        interval = int(cfg.get("service_check_interval", {}).get("value", 60))
        if interval < 10:
            interval = 60

        now = time.time()
        if now - _last_service_check < interval:
            return
        _last_service_check = now

        # 方案 B：网络设备（protocol=snmp）没有进程/服务可查 —— 它们的"服务"是
        # 端口状态，由 SNMP 采集负责。这里拿 WinRM/SSH 去连交换机会白白超时。
        servers = db.query(Server).filter(
            Server.protocol != "agent", Server.protocol != "snmp"
        ).all()
        checked = 0
        for server in servers:
            services = (
                db.query(MonitoredService)
                .filter(MonitoredService.server_id == server.id)
                .all()
            )
            if not services:
                continue
            try:
                _check_services(db, server)
                checked += len(services)
            except Exception as e:
                logger.exception(f"[ServiceScheduler] Failed to check {server.name}: {e}")
        db.commit()
        logger.info(f"[ServiceScheduler] Checked {checked} service(s) across {len(servers)} server(s)")
    finally:
        db.close()




@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    _seed_demo_data()
    # 2026-09-24：默认管理员账号改为**启动时就建**。
    # 之前 seed_admin 只挂在 POST /api/auth/login 里（`routes/auth.py`），
    # 结果新装完 users 表是空的、backend/data 也是空的，必须先在登录页提交一次
    # 才会建号 —— 而登录页又必须先有口令才能登，形成死循环；离线重置工具还会
    # 提示"重启服务端会自动建 admin"，这句话当时其实是错的。现在启动即建号，
    # 初始随机口令随即落盘到 backend/data/initial_admin_password.txt。
    try:
        _db = SessionLocal()
        try:
            seed_admin(_db)
        finally:
            _db.close()
    except Exception as exc:  # noqa: BLE001  建号失败不能拖垮整个启动
        logger.exception(f"[auth] 启动时初始化默认管理员账号失败：{exc}")

    scheduler = BackgroundScheduler()
    scheduler.add_job(collect_all_servers, "interval", seconds=60, id="collector", max_instances=3)
    scheduler.add_job(check_all_services, "interval", seconds=60, id="service_monitor", max_instances=3)
    scheduler.add_job(cleanup_old_logs, "cron", hour=2, minute=30, id="log_cleanup")
    # S4：失联主机的证书自动回收，每天 03:15 跑一次（错开日志清理）
    scheduler.add_job(reclaim_lost_certificates, "cron", hour=3, minute=15, id="cert_reclaim")
    # S5：SNMP 网络设备采集。交换机不需要像服务器那样 60 秒刷一次，
    # 5 分钟足够看端口流量趋势，还能大幅减少对设备的轮询压力。
    scheduler.add_job(collect_snmp_devices, "interval", seconds=300, id="snmp_collector", max_instances=1)
    # 路线 A：网络设备内部日志（只读 SSH 轮询）。设备缓冲区是环形的、重启即丢，
    # 15 分钟拉一次足够兜住；再密只会白白增加设备的 SSH 会话压力。
    scheduler.add_job(
        collect_network_device_logs, "interval", seconds=900,
        id="device_log_collector", max_instances=1,
    )
    scheduler.start()
    logger.info("[Scheduler] Collector started, running every 60s.")
    logger.info("[Scheduler] Service monitor started, running every 60s.")
    logger.info("[Scheduler] Log cleanup scheduled daily at 02:30.")
    cleanup_old_logs()

    # 主机信息「按需采集」：TTL 缓存的后台巡检线程（系统信息 / 应用列表 5 分钟续采一次）
    try:
        from services import host_info_async
        host_info_async.start()
    except Exception as e:  # noqa: BLE001  巡检线程起不来也不能拖垮启动
        logger.warning(f"[host_info_async] 启动失败（按需采集退化为每次实时拉取）：{e}")

    async def push_loop():
        while True:
            await asyncio.sleep(5)
            if manager.active:
                db = SessionLocal()
                try:
                    servers = db.query(Server).order_by(Server.id).all()
                    data = []
                    for s in servers:
                        latest = (
                            db.query(MetricSnapshot)
                            .filter(MetricSnapshot.server_id == s.id)
                            .order_by(MetricSnapshot.timestamp.desc())
                            .first()
                        )
                        alerts = (
                            db.query(Alert)
                            .filter(Alert.server_id == s.id, Alert.acknowledged == 0)
                            .count()
                        )
                        data.append({
                            "id": s.id,
                            "name": s.name,
                            "status": s.status,
                            "cpu_percent": latest.cpu_percent if latest else 0,
                            "memory_percent": latest.memory_percent if latest else 0,
                            "disk_percent": latest.disk_percent if latest else 0,
                            "network_in_mbps": latest.network_in_mbps if latest else 0,
                            "network_out_mbps": latest.network_out_mbps if latest else 0,
                            "disk_io_read_mbps": latest.disk_io_read_mbps if latest else 0,
                            "disk_io_write_mbps": latest.disk_io_write_mbps if latest else 0,
                            "tcp_connections": latest.tcp_connections if latest else 0,
                            "alerts": alerts,
                        })
                    await manager.broadcast({"type": "metrics_update", "servers": data})
                finally:
                    db.close()

    task = asyncio.create_task(push_loop())

    yield

    scheduler.shutdown(wait=False)
    task.cancel()



# 生产环境关闭交互式 API 文档（P1-5）：/docs、/redoc、/openapi.json 会向
# 未认证访问者完整暴露全部接口路径、参数与数据结构，给攻击者省去侦察步骤。
_prod_docs = dict(docs_url=None, redoc_url=None, openapi_url=None) if PRODUCTION else {}

app = FastAPI(
    title="VigilServe",
    description="VigilServe - 服务器运维与监控平台",
    version="1.1.65",
    lifespan=lifespan,
    **_prod_docs,
)

# Allow same-origin traffic only. The frontend is served from this same
_env_origins = os.environ.get("VIGILSERVE_ALLOWED_ORIGINS", "").strip()
if _env_origins:
    _origins = [o.strip() for o in _env_origins.split(",") if o.strip()]
else:
    _origins = []  # empty list = same-origin only
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=500)

# 「WEB管理」反向代理的跨源预检：必须**最后**挂（最外层）才拦得住上面的 CORSMiddleware。
# 沙箱 iframe 的源是 null，不在 _origins 白名单里，预检会被回 400 → 设备页 XHR 全挂。
network_web.install_preflight(app)

# ── 全局安全响应头（交付审查补漏）────────────────────────────────────
# 刻意**不加** Content-Security-Policy：WEB 管理的代理链路靠往设备页面里注入内联
# 会把整条链路打死。要上 CSP 得先把那段脚本改成外链文件，属于独立改造项。
_SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"SAMEORIGIN"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    # 关掉浏览器里早已废弃的 XSS auditor —— 留着它反而会被用来制造误报/信息泄露
    (b"x-xss-protection", b"0"),
    # 本系统用不到这些设备能力，明确关掉，免得被嵌进来的第三方页面顺手申请
    (b"permissions-policy", b"geolocation=(), payment=(), usb=(), midi=()"),
]
# HSTS 只在确实是 HTTPS 时下发；明文访问不下发，避免把"以后必须 https"误记进浏览器
_HSTS_HEADER = (b"strict-transport-security", b"max-age=31536000; includeSubDomains")


class SecurityHeadersMiddleware:
    """给每个 HTTP 响应补一层基础安全头（响应里已经有的不覆盖）。"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        extra = list(_SECURITY_HEADERS)
        if scope.get("scheme") == "https":
            extra.append(_HSTS_HEADER)

        async def _send(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                names = {k.lower() for k, _ in headers}
                for k, v in extra:
                    if k.lower() not in names:
                        headers.append((k, v))
            await send(message)

        await self.app(scope, receive, _send)


# 挂在 network_web 的预检中间件**之后** = 更外层，于是那条短路的 OPTIONS 应答
# 同样带得上安全头。
app.add_middleware(SecurityHeadersMiddleware)

# 来源白名单（2026-09-23 动态审计 D-2）：**挂得最晚 = 最外层**，先于 CORS、
# 先于安全头中间件生效 —— 不在 VIGILSERVE_ALLOWED_CIDRS 里的来源连跨源预检
# 都过不去。没配该环境变量时完全不介入（零开销），现有部署行为不变。
# 否则等于把白名单交给客户端自己填。
app.add_middleware(net_guard.make_source_guard_middleware())

app.include_router(servers.router)
app.include_router(metrics.router)
app.include_router(dashboard.router)
app.include_router(auth.router)
app.include_router(config.router)
app.include_router(agent.router, prefix="/api/agent", tags=["agent"])
app.include_router(file_explorer.router)
app.include_router(logs.router)
app.include_router(agent_update.router)
# （meshcentral.router 已于 2026-09-23 随该集成整体下线移除）
app.include_router(roles.router)
app.include_router(host_groups.router)
app.include_router(host_info.router)
app.include_router(rdp_routes.router)
app.include_router(tls_routes.router)
app.include_router(security.router)
# 方案 B：网络设备「WEB管理」页签 —— 服务端反向代理到设备自带的 Web 管理界面
app.include_router(network_web.router)
app.include_router(traps.router)


@app.get("/api/version", tags=["system"])
def get_server_version(authorization: Optional[str] = Header(None),
                       db: Session = Depends(get_db)):
    """返回服务端版本号（`app.version`，即本文件里的 FastAPI(version=...)）。

    侧边栏左下角的 vX.Y.Z 从这里读，前端不再写死 —— 以前写死成 v1.1.35，
    服务端升到 1.1.42 界面还显示旧号，容易误导排障。
    按「新增接口默认要求登录」的约定，这里同样要求有效会话。
    """
    from routes.auth import require_login
    require_login(authorization, db)
    return {"version": app.version}

from services import tls as _tls_mod  # noqa: E402  （__main__ 启动时用来准备证书）




@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """实时指标推送。安全加固阶段 3：必须带登录令牌（子协议传递）。

    以前这个端点谁都能连，等于把全网主机的 CPU/内存/磁盘曲线广播给匿名者。
    """
    try:
        from services.ws_auth import token_from_ws as _tk
        token = _tk(ws)
    except Exception:  # noqa: BLE001
        token = ws.query_params.get("token") or ""

    db = next(get_db())
    try:
        # WebSocket 握手里抛 HTTPException 只会变成一条 500 日志，连接语义还丢了，
        # 所以这里关掉强制改密、自己按 close code 拒绝（4403 = 待改密）。
        user = get_current_user_full(
            f"Bearer {token}", db, enforce_password_reset=False) if token else {}
    finally:
        db.close()
    if not user.get("user_id"):
        logger.warning("[/ws] 拒绝：未携带有效登录令牌")
        await ws.close(code=4401)
        return
    if user.get("must_reset_password"):
        logger.warning("[/ws] 拒绝：账号仍在使用初始口令，必须先修改密码")
        await ws.close(code=4403)
        return

    # 注意：accept 由 manager.connect 内部完成，这里不能重复 accept
    # （重复 accept 会抛 RuntimeError 并让 uvicorn 记一条 ASGI 异常）。
    # 子协议要回显客户端发过的那个，否则 Chrome 会直接断连。
    try:
        from services.ws_auth import selected_subprotocol as _sel
        _sub = _sel(ws)
    except Exception:  # noqa: BLE001
        _sub = None
    await manager.connect(ws, subprotocol=_sub)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)



import subprocess as _subprocess  # noqa: E402
import sys as _sys  # noqa: E402


TERMINAL_PROCS = {}


def _get_windows_version() -> str:
    """Get the actual Windows version string. Output of `ver` is GBK-encoded."""
    try:
        if _sys.platform == "win32":
            v = _sys.getwindowsversion()
            return f"Microsoft Windows [版本 {v.major}.{v.minor}.{v.build}]"
    except Exception:
        pass
    try:
        out = _subprocess.check_output(['cmd', '/c', 'ver'], timeout=3)
        return out.decode('cp936', errors='replace').strip()
    except Exception:
        return "Microsoft Windows [版本 X.X]"


async def _proxy_terminal_to_agent(ws, server_id: int, server: "Server"):
    """Connect to the Agent's terminal WebSocket and relay bytes bidirectionally."""
    try:
        import websockets as _websockets
    except ImportError:
        await ws.send_bytes(b'\r\n\x1b[31mwebsockets library not installed\x1b[0m')
        return

    agent_ip = server.ip_address
    agent_port = server.agent_port or 9998
    agent_url = f"wss://{agent_ip}:{agent_port}/ws/terminal"
    logger.info(f"[Terminal {server_id}] Connecting to agent {agent_url}")

    # 安全加固阶段 1：Agent 9998 的 WS 端点同样要 X-Auth-Token
    try:
        from services.agent_auth import agent_headers
        _agent_hdrs = agent_headers(server)
    except Exception:  # noqa: BLE001
        _agent_hdrs = {}

    # P1-1：反向通道 TLS —— wss + 本地 CA 校验 Agent 服务器证书
    try:
        from services.agent_auth import agent_ssl_context
        _agent_ssl = agent_ssl_context()
    except Exception:  # noqa: BLE001
        _agent_ssl = None

    try:
        async with _websockets.connect(agent_url, ping_interval=None,
                                       additional_headers=_agent_hdrs,
                                       ssl=_agent_ssl) as agent_ws:
            logger.info(f"[Terminal {server_id}] Agent connected")

            async def forward_to_frontend():
                """Read from agent, write to frontend preserving frame type."""
                try:
                    while True:
                        data = await agent_ws.recv()
                        if isinstance(data, bytes):
                            await ws.send_bytes(data)
                        else:
                            await ws.send_text(data)
                except Exception:
                    pass

            async def forward_to_agent():
                """Read from frontend, write to agent (both bytes and text)."""
                try:
                    while True:
                        msg = await ws.receive()
                        if msg.get("type") != "websocket.receive":
                            continue
                        if "text" in msg and msg["text"] is not None:
                            await agent_ws.send(msg["text"])
                        elif "bytes" in msg and msg["bytes"] is not None:
                            await agent_ws.send(msg["bytes"])
                except Exception as e:
                    logger.exception(f"[Terminal {server_id}] forward_to_agent error: {e}")

            done, pending = await asyncio.wait(
                [asyncio.create_task(forward_to_frontend()),
                 asyncio.create_task(forward_to_agent())],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for t in pending:
                t.cancel()

    except Exception as e:
        logger.exception(f"[Terminal {server_id}] Agent connection failed: {e}")
        try:
            await ws.send_bytes(f'\r\n\x1b[31m无法连接 Agent ({agent_ip}): {e}\x1b[0m'.encode())
        except Exception:
            pass


def _log_terminal_event(
    server_id: int,
    server_name: str,
    action: str,
    username: str,
    user_id: int | None,
    ip_address: str = "",
):
    """Record terminal connection/disconnection in the audit log."""
    db = SessionLocal()
    try:
        log_operation(
            db,
            category="terminal",
            action=action,
            level="info",
            username=username or "",
            user_id=user_id,
            ip_address=ip_address,
            target_type="server",
            target_id=str(server_id),
            message=f"用户 {username or '未知'} {('连接' if action == 'connect' else '断开')}主机 {server_name} 的终端",
            details={"server_name": server_name, "server_id": server_id},
        )
    except Exception as e:
        logger.warning(f"[Terminal {server_id}] audit log failed: {e}")
    finally:
        db.close()


@app.websocket("/ws/terminal/{server_id}")
async def terminal_endpoint(ws: WebSocket, server_id: int):
    """WebSocket terminal: spawn local cmd.exe or proxy to Agent."""

    # 先鉴权再 accept：未授权的连接不给任何回显（安全加固阶段 3）

    # 2026-09-23 动态审计 D-1：原来无条件采信 X-Forwarded-For（客户端可伪造），
    # 规则统一到 services/client_ip.py —— 默认只认直连 IP。
    client_ip = get_client_ip(ws)

    db = next(get_db())
    # 安全加固阶段 3：token 走 WebSocket 子协议（不再出现在 URL / 日志 / Referer）
    try:
        from services.ws_auth import token_from_ws as _tk
        token = _tk(ws)
    except Exception:  # noqa: BLE001
        token = ws.query_params.get("token") if hasattr(ws, "query_params") else None
    user = get_current_user_full(f"Bearer {token}", db, enforce_password_reset=False) if token else {}
    if not user.get("user_id"):
        logger.warning(f"[Terminal {server_id}] 拒绝：未携带有效登录令牌")
        await ws.close(code=4401)
        try:
            db.close()
        except Exception:  # noqa: BLE001
            pass
        return
    if user.get("must_reset_password"):
        logger.warning(f"[Terminal {server_id}] 拒绝：账号仍在使用初始口令，必须先修改密码")
        await ws.close(code=4403)
        try:
            db.close()
        except Exception:  # noqa: BLE001
            pass
        return
    try:
        from services.ws_auth import accept as _accept, selected_subprotocol as _sel
        await _accept(ws, _sel(ws))
    except Exception:  # noqa: BLE001
        await ws.accept()
    logger.info(f"[Terminal {server_id}] Connection accepted user={user.get('username', '')}")
    try:
        server = db.query(Server).filter(Server.id == server_id).first()
        is_agent = server and server.protocol == 'agent'
        is_local = server and server.ip_address in ('0.0.0.0', '127.0.0.1', 'localhost')
        server_name = server.name if server else str(server_id)
    finally:
        db.close()

    _tdb = next(get_db())
    try:
        if not has_perm(_tdb, user, "host", "terminal", "edit", "connect"):
            logger.warning(f"[Terminal {server_id}] 拒绝：角色无终端连接权限 user={user.get('username', '')}")
            await ws.send_text("\r\n[无权限] 当前角色没有WEB终端的连接权限\r\n")
            await ws.close(code=4003)
            return
        if not can_manage_server(_tdb, user, server_id):
            logger.warning(f"[Terminal {server_id}] 拒绝：主机不在角色管理范围内 user={user.get('username', '')}")
            await ws.send_text("\r\n[无权限] 该主机不在当前角色的管理范围内\r\n")
            await ws.close(code=4003)
            return
    finally:
        _tdb.close()

    try:
        await asyncio.get_event_loop().run_in_executor(
            None,
            _log_terminal_event,
            server_id,
            server_name,
            "connect",
            user.get("username", ""),
            user.get("user_id"),
            client_ip,
        )
    except Exception as e:
        logger.warning(f"[Terminal {server_id}] connect audit log failed: {e}")

    if is_agent and not is_local:
        try:
            await _proxy_terminal_to_agent(ws, server_id, server)
        finally:
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    _log_terminal_event,
                    server_id,
                    server_name,
                    "disconnect",
                    user.get("username", ""),
                    user.get("user_id"),
                    client_ip,
                )
            except Exception as e:
                logger.warning(f"[Terminal {server_id}] disconnect audit log failed: {e}")
        return

    # all line editing, echo, wrapping and backspacing. The frontend only
    # forwards raw keystrokes and renders the PTY output.
    cwd = os.path.expanduser('~')
    loop = asyncio.get_event_loop()

    if os.name == 'nt' and WinPtyProcess is not None:
        try:
            from winpty import PtyProcess as _PP
            backend = getattr(_PP, "BACKEND_WINPTY", 1)
        except Exception:
            backend = 1
        proc = WinPtyProcess.spawn(
            ['cmd.exe', '/K', 'prompt $P$G'],
            cwd=cwd,
            dimensions=(24, 80),
            backend=backend,
        )
    else:
        await ws.send_bytes(b'\r\n\x1b[31mPTY terminal is only supported on Windows with pywinpty installed.\x1b[0m')
        return

    TERMINAL_PROCS[server_id] = proc

    import queue as _queue
    import threading as _threading
    out_q: _queue.Queue = _queue.Queue(maxsize=1024)
    stop_event = _threading.Event()
    _SENTINEL = object()

    def _pty_reader():
        try:
            while not stop_event.is_set() and proc.isalive():
                try:
                    chunk = proc.read(4096)
                except EOFError:
                    break
                if chunk:
                    out_q.put(chunk)
        except Exception as e:
            logger.error(f"[Terminal {server_id}] PTY reader error: {e}")
        finally:
            out_q.put(_SENTINEL)

    async def _pty_sender():
        try:
            while True:
                chunk = await loop.run_in_executor(None, out_q.get)
                if chunk is _SENTINEL:
                    break
                try:
                    await ws.send_bytes(chunk.encode('utf-8', errors='replace'))
                except Exception:
                    break
        except Exception as e:
            logger.info(f"[Terminal {server_id}] pty_sender ended: {e}")
        finally:
            stop_event.set()

    async def _pty_writer():
        """Read from the WebSocket and write to the PTY.

        Binary messages are raw keystrokes. Text messages are JSON control
        messages (resize / ping).
        """
        try:
            logger.info(f"[Terminal {server_id}] pty_writer started")
            while True:
                msg = await ws.receive()
                if msg.get("type") != "websocket.receive":
                    continue
                if "text" in msg and msg["text"] is not None:
                    try:
                        data = json.loads(msg["text"])
                    except Exception:
                        continue
                    mtype = data.get('type')
                    if mtype == 'resize':
                        try:
                            proc.setwinsize(int(data['rows']), int(data['cols']))
                        except Exception as e:
                            logger.warning(f"[Terminal {server_id}] resize failed: {e}")
                    elif mtype == 'ping':
                        try:
                            await ws.send_text(json.dumps({"type": "pong"}))
                        except Exception:
                            pass
                    continue
                if "bytes" in msg and msg["bytes"] is not None:
                    if not proc.isalive():
                        break
                    try:
                        proc.write(msg["bytes"].decode('utf-8', errors='replace'))
                    except Exception as e:
                        logger.error(f"[Terminal {server_id}] PTY write failed: {e}")
                        break
        except Exception as e:
            logger.info(f"[Terminal {server_id}] pty_writer ended: {e}")
        finally:
            stop_event.set()

    t_reader = _threading.Thread(target=_pty_reader, daemon=True)
    t_reader.start()

    task_sender = asyncio.create_task(_pty_sender())
    task_writer = asyncio.create_task(_pty_writer())

    done, pending = await asyncio.wait(
        [task_sender, task_writer], return_when=asyncio.FIRST_COMPLETED
    )
    for t in pending:
        t.cancel()
    stop_event.set()
    TERMINAL_PROCS.pop(server_id, None)
    try:
        proc.terminate(force=True)
    except Exception:
        pass
    try:
        await asyncio.get_event_loop().run_in_executor(
            None,
            _log_terminal_event,
            server_id,
            server_name,
            "disconnect",
            user.get("username", ""),
            user.get("user_id"),
            client_ip,
        )
    except Exception as e:
        logger.warning(f"[Terminal {server_id}] disconnect audit log failed: {e}")


# 与 `/ws/terminal/{id}` 的区别：主机那条路是「服务端 → Agent 9998 → 本机 PTY」，
# 网络设备装不上 Agent，所以这里由**服务端直接 SSH / Telnet 到设备**。


@app.websocket("/ws/network-terminal/{server_id}")
async def network_terminal_endpoint(ws: WebSocket, server_id: int):
    """网络设备的WEB终端：服务端直连设备 CLI（SSH / Telnet）。"""

    # 先鉴权再 accept（与 /ws/terminal 一致：未授权不给任何回显）
    try:
        from services.ws_auth import token_from_ws as _tk
        token = _tk(ws)
    except Exception:  # noqa: BLE001
        token = ws.query_params.get("token") if hasattr(ws, "query_params") else None

    db = next(get_db())
    try:
        user = get_current_user_full(
            f"Bearer {token}", db, enforce_password_reset=False) if token else {}
    finally:
        db.close()
    if not user.get("user_id"):
        logger.warning(f"[NetTerminal {server_id}] 拒绝：未携带有效登录令牌")
        await ws.close(code=4401)
        return
    if user.get("must_reset_password"):
        logger.warning(f"[NetTerminal {server_id}] 拒绝：账号仍在使用初始口令，必须先修改密码")
        await ws.close(code=4403)
        return

    try:
        from services.ws_auth import accept as _accept, selected_subprotocol as _sel
        await _accept(ws, _sel(ws))
    except Exception:  # noqa: BLE001
        await ws.accept()

    _db = next(get_db())
    try:
        server = _db.query(Server).filter(Server.id == server_id).first()
        if server is None:
            await ws.send_text("\r\n[错误] 设备不存在\r\n")
            await ws.close(code=4004)
            return
        server_name = server.name
        from services.device_status import device_kind_of
        if device_kind_of(server) != "network":
            await ws.send_text("\r\n[错误] 该主机不是网络设备，请走普通WEB终端\r\n")
            await ws.close(code=4004)
            return
        # 复用「WEB终端」的权限点：能开终端、且这台设备在角色管理范围内
        if not has_perm(_db, user, "host", "terminal", "edit", "connect"):
            await ws.send_text("\r\n[无权限] 当前角色没有WEB终端的连接权限\r\n")
            await ws.close(code=4003)
            return
        if not can_manage_server(_db, user, server_id):
            await ws.send_text("\r\n[无权限] 该设备不在当前角色的管理范围内\r\n")
            await ws.close(code=4003)
            return
        # 关键：session 要长期持有这台 Server 的字段（口令），必须自己开一个会话，
        # 用完再关 —— 上面那个 _db 马上要关闭。
        sdb = next(get_db())
        try:
            target = sdb.query(Server).filter(Server.id == server_id).first()
        except Exception:  # noqa: BLE001
            target = None
    finally:
        _db.close()

    if target is None:
        await ws.send_text("\r\n[错误] 设备不存在\r\n")
        await ws.close(code=4004)
        return

    loop = asyncio.get_event_loop()

    def _open():
        from services import network_cli as cli
        return cli.open_cli_session(target, cols=80, rows=24, db=sdb, timeout=15)

    try:
        sess = await loop.run_in_executor(None, _open)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[NetTerminal {server_id}] 连接失败：{e}")
        try:
            await ws.send_bytes(f"\r\n\x1b[31m{e}\x1b[0m\r\n".encode("utf-8"))
        except Exception:  # noqa: BLE001
            pass
        try:
            from services.audit_logger import log_operation
            log_operation(
                sdb, category="server", action="network_device_cli_login", level="warning",
                status="failed",
                username=user.get("username", ""), user_id=user.get("user_id"),
                target_type="server", target_id=str(server_id),
                message=f"用户 {user.get('username', '未知')} 登录设备 {server_name} 命令行失败：{e}",
                details={"ok": False},
            )
        except Exception:  # noqa: BLE001
            pass
        sdb.close()
        await ws.close(code=4002)
        return

    try:
        from services.audit_logger import log_operation
        log_operation(
            sdb, category="server", action="network_device_cli_login",
            username=user.get("username", ""), user_id=user.get("user_id"),
            target_type="server", target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 登录设备 {server_name} 命令行",
            details={"ok": True},
        )
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[NetTerminal {server_id}] audit log failed: {e}")

    import queue as _queue
    import threading as _threading

    out_q: _queue.Queue = _queue.Queue(maxsize=2048)
    stop_event = _threading.Event()
    _SENTINEL = object()

    def _cli_reader():
        """设备 → 前端。设备不会主动推，只能轮询；50ms 一轮询足够跟上敲命令。"""
        try:
            while not stop_event.is_set():
                try:
                    chunk = sess.recv(8192)
                except Exception as e:  # noqa: BLE001
                    logger.info(f"[NetTerminal {server_id}] reader 结束：{e}")
                    try:
                        out_q.put_nowait(f"\r\n\x1b[31m{ e }\x1b[0m\r\n".encode("utf-8"))
                    except Exception:  # noqa: BLE001
                        pass
                    break
                if chunk:
                    try:
                        out_q.put_nowait(chunk)
                    except _queue.Full:
                        pass
                else:
                    time.sleep(0.05)
        finally:
            try:
                out_q.put_nowait(_SENTINEL)
            except Exception:  # noqa: BLE001
                pass

    async def _cli_sender():
        try:
            while True:
                chunk = await loop.run_in_executor(None, out_q.get)
                if chunk is _SENTINEL:
                    break
                try:
                    await ws.send_bytes(chunk)
                except Exception:  # noqa: BLE001
                    break
        except Exception as e:  # noqa: BLE001
            logger.info(f"[NetTerminal {server_id}] sender 结束：{e}")
        finally:
            stop_event.set()

    async def _cli_writer():
        """前端 → 设备。二进制 = 按键；文本 = JSON 控制消息（resize / ping）。"""
        try:
            while True:
                msg = await ws.receive()
                if msg.get("type") != "websocket.receive":
                    continue
                if "text" in msg and msg["text"] is not None:
                    try:
                        data = json.loads(msg["text"])
                    except Exception:  # noqa: BLE001
                        continue
                    mtype = data.get("type")
                    if mtype == "resize":
                        try:
                            await loop.run_in_executor(
                                None, sess.resize, int(data["cols"]), int(data["rows"]))
                        except Exception:  # noqa: BLE001
                            pass
                    elif mtype == "ping":
                        try:
                            await ws.send_text(json.dumps({"type": "pong"}))
                        except Exception:  # noqa: BLE001
                            pass
                    continue
                if "bytes" in msg and msg["bytes"] is not None:
                    try:
                        await loop.run_in_executor(None, sess.send, msg["bytes"])
                    except Exception as e:  # noqa: BLE001
                        logger.warning(f"[NetTerminal {server_id}] 发送失败：{e}")
                        break
        except Exception as e:  # noqa: BLE001
            logger.info(f"[NetTerminal {server_id}] writer 结束：{e}")
        finally:
            stop_event.set()

    t_reader = _threading.Thread(target=_cli_reader, daemon=True)
    t_reader.start()
    task_sender = asyncio.create_task(_cli_sender())
    task_writer = asyncio.create_task(_cli_writer())

    done, pending = await asyncio.wait(
        [task_sender, task_writer], return_when=asyncio.FIRST_COMPLETED
    )
    for t in pending:
        t.cancel()
    stop_event.set()
    try:
        await loop.run_in_executor(None, sess.close)
    except Exception:  # noqa: BLE001
        pass
    try:
        from services.audit_logger import log_operation
        log_operation(
            sdb, category="server", action="network_device_cli_logout",
            username=user.get("username", ""), user_id=user.get("user_id"),
            target_type="server", target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 断开设备 {server_name} 命令行",
            details={"ok": True},
        )
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[NetTerminal {server_id}] logout audit failed: {e}")
    finally:
        sdb.close()




def _seed_demo_data():
    """Seed demo data if the database is empty — disabled for production use."""
    db = SessionLocal()
    try:
        # 内置角色（系统管理员 / 普通用户）必须存在，否则用户没有可归属的角色
        from routes.roles import seed_roles
        seed_roles(db)
        if db.query(Server).count() > 0:
            return
        logger.info("[Seed] Database empty, ready for production servers.")
    finally:
        db.close()



def _set_no_cache(response):
    """Add aggressive no-cache headers to a response."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


class NoCacheStaticFiles(StaticFiles):
    """StaticFiles subclass that disables client-side caching for all assets."""

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        return _set_no_cache(response)


# Serve the built frontend by default (API/WebSocket routes are registered above and take priority)
import re
# JSONResponse 是第三轮审计 N-4 补进来的：SPA 兜底原来 `return {"detail": ...}`
# 会被 FastAPI 默认配 200，现在要显式回 404，必须用它带状态码。
from fastapi.responses import FileResponse, JSONResponse, Response

_ASSET_URL_RE = re.compile(r"(/assets/index-[A-Za-z0-9_-]+\.(?:css|js))")
dist_path = Path(__file__).parent.parent / "frontend" / "dist"

assets_dir = dist_path / "assets"
if assets_dir.exists():
    app.mount("/assets", NoCacheStaticFiles(directory=str(assets_dir)), name="assets")

@app.get("/{path:path}")
async def serve_spa(path: str, request: Request):
    # 设备 JS 用 `location.hostname` 硬拼绝对地址时（华为登录成功后跳首页就是这么干的），
    # 路径里的 `/api/servers/{id}/web/<ticket>/` 会被丢掉，请求就落到这条兜底上。
    # 前端拦不住（Chrome 的 location.href 是不可伪造属性），按 Referer 把票据补回去。
    fixed = network_web.recover_redirect(request, path)
    if fixed is not None:
        return fixed
    if path.startswith("api/") or path.startswith("ws/"):
        # 🚨 第三轮审计 N-4（2026-09-23）：这里原来是 `return {"detail": "Not Found"}`
        #    —— FastAPI 对**返回的 dict 一律给 200**，于是"接口不存在"被包成了一次
        #    "成功的空响应"。后果：① 前端 `res.ok` 判不出来，接口改名/路径写错会被
        #    静默吞掉；② 基于状态码的 WAF、日志告警、漏扫一律失效；③ 第三轮审计的
        #    第一版验收脚本就是被它骗过，把一批"路径写错"报成了"匿名可读"。
        #    现在显式回 404，语义与 HTTP 一致。
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    file_path = dist_path / path
    if file_path.exists() and file_path.is_file():
        return _set_no_cache(FileResponse(file_path))
    index = dist_path / "index.html"
    if index.exists():
        html = index.read_text(encoding="utf-8")
        version = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        html = _ASSET_URL_RE.sub(rf"\1?v={version}", html)
        # 设备 iframe 丢票据后就是落在这里（原本表现为"登录后页面空白"）。
        # 自救脚本对正常 SPA 是空转（window.name 为空），只有 iframe 里才生效。
        html = network_web.inject_recover_js(html)
        return _set_no_cache(Response(content=html, media_type="text/html"))
    # 同上（N-4）：前端资源缺失同样是 404，不是 200。
    return JSONResponse(status_code=404, content={"detail": "Not Found"})

logger.info(f"[Server] Serving frontend from {dist_path}")


def _no_proxy_headers_kwargs() -> dict:
    """启动 uvicorn 时关掉它自带的 `ProxyHeadersMiddleware`（2026-09-23 动态审计 D-1）。

    ⚠ 这一条是 D-1 修复**能否真正生效的关键**：uvicorn 默认会让 ASGI scope 里的
    `client` 不再是你以为的那个 socket 对端。它的 `ProxyHeadersMiddleware` 默认
    `trusted_hosts="127.0.0.1"`（或取环境变量 `FORWARDED_ALLOW_IPS`），只要直连方
    落在这个集合里、且请求带了 `X-Forwarded-For`，它就把

        scope["client"] = (XFF 里算出来的地址, 0)

    直接改写掉。**这一步发生在任何业务代码之前**，所以等我们自己的
    `services/client_ip.get_client_ip()` 再去读 `request.client.host`，读到的已经是
    被 uvicorn 改写过的、客户端说了算的值 —— 于是"不信任 XFF"的检查形同虚设：
    单元测试全绿（用的是假 request），端到端却仍然把伪造 IP `203.0.113.9`
    原样写进审计日志。这个坑很难看出来，因为两层代码单独看都"没问题"。

    关掉之后 `scope["client"]` 恒为真实 socket 对端，**不可伪造**；是否要采信反向
    代理传来的 XFF，统一交给 `services/client_ip.py` 的 `VIGILSERVE_TRUSTED_PROXIES`
    决定 —— 那里有明确的白名单、且默认是不信任。两边各写一份"谁有权解释 XFF"
    的规则会互相打架，必须只有一处真源。

    副作用已确认可接受：同时停掉的还有 uvicorn 对 `X-Forwarded-Proto` 的改写，
    而全项目**没有任何地方**读 `request.url.scheme` / `x-forwarded-proto`
    （已全局搜索核实），所以不影响 HTTP/HTTPS 判定。

    若将来确实要在前面挂 nginx 之类的反向代理：不要重新打开这个开关，
    而是配 `VIGILSERVE_TRUSTED_PROXIES=<那台代理的地址>`。
    """
    return {"proxy_headers": False}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("VIGILSERVE_BACKEND_PORT", 8000))
    if PRODUCTION:
        # 安全加固阶段 2：全链路 HTTPS。证书由服务端自己签发的本地 CA 签出，
        # Agent 安装包内置 ca.crt 做校验；VIGILSERVE_TLS=0 可临时关掉（仅排障）。
        ssl_kwargs = {}
        if _tls_mod.tls_enabled():
            try:
                info = _tls_mod.ensure_server_cert()
                ssl_kwargs = {"ssl_certfile": info["server_cert"],
                              "ssl_keyfile": info["server_key"]}
                logger.info(f"[TLS] HTTPS 已启用，SAN={info.get('sans')}，"
                            f"证书到期 {info.get('not_after')}")
            except Exception as e:  # noqa: BLE001
                # 🚨 以前这里直接降级成 HTTP 继续跑：生产环境只要证书准备出一次
                # 异常，服务就**悄悄变成明文**，而浏览器和 Agent 完全不知情
                # （Agent 是照 https 去连的，现象只是"连不上"，很难联想到这里）。
                # 改成 fail closed —— 起不来比悄悄明文好排障。
                # 确实要临时放行的场合显式给 VIGILSERVE_TLS_INSECURE_FALLBACK=1。
                if os.environ.get("VIGILSERVE_TLS_INSECURE_FALLBACK") == "1":
                    logger.error(f"[TLS] 证书准备失败，按 VIGILSERVE_TLS_INSECURE_FALLBACK=1 "
                                 f"降级为 HTTP（**明文**，仅排障）：{e}")
                else:
                    logger.error(f"[TLS] 证书准备失败，拒绝以明文启动：{e}")
                    logger.error("[TLS] 确认要临时明文启动请设 VIGILSERVE_TLS_INSECURE_FALLBACK=1")
                    raise SystemExit(2)
        else:
            logger.error("[TLS] ⚠ VIGILSERVE_TLS=0 —— 本次以**明文 HTTP** 提供服务，"
                         "登录凭据与采集数据都在链路上裸奔，仅限排障使用")

        # 必须全进程唯一一份，双实例会导致触发链（tunnel 注册的 viewer 对 config 不可见）断裂。
        #
        # 2026-09-23 动态审计 D-2：监听地址改为可配（VIGILSERVE_BIND_HOST），
        # 不配仍默认 0.0.0.0（现有部署行为不变）。只想本机访问就设 127.0.0.1。
        _host = net_guard.bind_host()
        if _host == "0.0.0.0":
            logger.warning("[net_guard] 监听 0.0.0.0 —— 对本网段内所有主机开放。"
                           "如需收紧请设 VIGILSERVE_BIND_HOST=127.0.0.1 或具体内网 IP，"
                           "或用 VIGILSERVE_ALLOWED_CIDRS 限定来源网段")
        uvicorn.run(app, host=_host, port=port, **ssl_kwargs,
                    **_no_proxy_headers_kwargs())
    else:
        uvicorn.run("main:app", host=net_guard.bind_host(), port=port, reload=True,
                    **_no_proxy_headers_kwargs())
