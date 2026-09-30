"""绑定地址与来源白名单（2026-09-23 动态审计 D-2）。

现状
----
8001（服务端）/ 8009（WEB 管理代理）/ 9998（Agent）三个服务原来都把监听地址
**硬编码成 `0.0.0.0`**，等于对任何可达的网络完全开放 —— 实测从同一内网里的
另一台机器访问，三个端口全部可达。防护完全押在"外面有防火墙"这一条上，
属于部署时最容易漏掉的单点。

本模块提供两个**可选**开关。**都不配 = 维持原行为**，不影响任何现有部署；
要收紧时按需开：

    VIGILSERVE_BIND_HOST       监听地址，默认 "0.0.0.0"
                               只允许本机访问 → 写 127.0.0.1
                               多网卡机器只想走内网 → 写具体内网 IP

    VIGILSERVE_ALLOWED_CIDRS   来源白名单，逗号分隔的 IP/CIDR，默认空 = 不限制
                               例：10.0.0.0/8,192.168.0.0/16
                               不在名单里的来源一律 403（并写 warning 日志）

⚠ 为什么**不是**"把 Agent 改成只听 127.0.0.1"
--------------------------------------------
Agent 是**分布式**部署的：每台被监控机装一个，服务端会**主动**去连
`https://<被监控机 IP>:<agent_port>/…`（见 `routes/servers.py` 的电源操作、
主机信息采集、远程桌面等）。把 Agent 绑到 loopback 会**直接切断服务端的远程
管理能力**。所以 Agent 侧的正确收紧姿势是「来源白名单 + 只绑内网网卡」。

⚠ 白名单用**哪個 IP** 判断
--------------------------
用 `services/client_ip.get_client_ip()`（= 默认直连 IP，配了可信代理才是
XFF 里的真实客户端）。**不能**直接用 `X-Forwarded-For` —— 那等于把白名单
交给客户端自己填。
"""
import ipaddress
import logging
import os
from typing import Tuple

logger = logging.getLogger("backend")

BIND_ENV = "VIGILSERVE_BIND_HOST"
CIDRS_ENV = "VIGILSERVE_ALLOWED_CIDRS"

_CACHE: dict = {"raw": None, "nets": ()}


def bind_host(default: str = "0.0.0.0") -> str:
    """监听地址。没配就用 default（保持原行为）。"""
    return (os.environ.get(BIND_ENV) or "").strip() or default


def _parse(raw: str) -> Tuple[ipaddress._BaseNetwork, ...]:
    nets = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            logger.warning(f"[net_guard] {CIDRS_ENV} 里的 {part!r} 不是合法 IP/CIDR，已忽略")
    return tuple(nets)


def allowed_networks() -> Tuple[ipaddress._BaseNetwork, ...]:
    """当前生效的来源白名单（空元组 = 不限制来源）。"""
    raw = (os.environ.get(CIDRS_ENV) or "").strip()
    if _CACHE["raw"] != raw:
        _CACHE["nets"] = _parse(raw)
        _CACHE["raw"] = raw
    return _CACHE["nets"]


def is_allowed(ip: str) -> bool:
    """该来源 IP 是否放行。白名单为空 = 全放行。"""
    nets = allowed_networks()
    if not nets:
        return True
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def make_source_guard_middleware():
    """构造 Starlette 中间件类（延迟 import，避免仅做配置时拖入依赖）。"""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse

    class SourceGuardMiddleware(BaseHTTPMiddleware):
        """来源白名单。`VIGILSERVE_ALLOWED_CIDRS` 为空时完全不介入（零开销）。"""

        async def dispatch(self, request, call_next):
            if not allowed_networks():
                return await call_next(request)
            from services.client_ip import get_client_ip

            ip = get_client_ip(request)
            if not is_allowed(ip):
                logger.warning(
                    f"[net_guard] 拒绝来源 {ip or '(未知)'} 的 {request.method} "
                    f"{request.url.path}（不在 {CIDRS_ENV} 白名单内）"
                )
                return JSONResponse(
                    status_code=403,
                    content={"detail": "来源地址不在允许范围内"},
                )
            return await call_next(request)

    return SourceGuardMiddleware
