"""客户端真实 IP 的取用规则（2026-09-23 动态审计 D-1）。

背景
----
原来 8 个模块各写了一份 `_client_ip()`，逻辑逐字相同：

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()      # ← 无条件采信
    return request.client.host if request.client else ""

`X-Forwarded-For` 是**客户端可任意伪造的 HTTP 头**。本项目服务端直接监听
`0.0.0.0:8001` 且前面没有反向代理，所以任何人都能做到：

  * 往审计日志里写任意来源 IP —— 实测把失败登录记录的 `ip_address` 写成了
    `203.0.113.9` / `192.0.2.x`，审计溯源直接失效；
  * 每次请求换一个 `X-Forwarded-For`，让「登录失败锁定」的 **IP 维度**永不累积
    —— 实测连撞 7 次不触发锁定，而固定 IP 撞 5 次就会锁。

注意：这 8 处取到的 IP **只用于记日志**，不参与任何访问控制决策，所以伪造 XFF
不能提权，危害是「溯源失效 + 横向撞库防护失效」。

取用规则
--------
只有当**直连方**（`request.client.host`）本身是可信代理时，才采信 XFF。
可信代理由环境变量 `VIGILSERVE_TRUSTED_PROXIES` 配置，逗号分隔的 IP 或 CIDR：

    VIGILSERVE_TRUSTED_PROXIES=127.0.0.1,::1,10.0.0.0/8

**默认留空 = 完全不信任 XFF**，一律用直连 IP。这是 fail-safe 的方向：
没配就退回「不可伪造」的那个值；确实走了反向代理时，由管理员显式声明代理地址。

从 XFF 取值时**从右往左**找第一个不在可信列表里的地址：XFF 是逐跳追加的
（`客户端, 代理1, 代理2`），最右侧是紧邻我们的那台可信代理**亲眼看到的**地址
（客户端伪造不了），最左侧才是客户端自称的。写 `split(",")[0]` 恰好挑中了最能伪造的那一段。

⚠ 配置边界（务必注意）：`VIGILSERVE_TRUSTED_PROXIES` 里**只能列反向代理自己的地址**，
不要把「客户端所在的网段」也写进去。这个算法无法区分「这段地址是一台代理」
和「这段地址是一个客户端」，两边撞在一个网段里时会多跳一层、取到更左侧的值：

    VIGILSERVE_TRUSTED_PROXIES=10.0.0.0/8        # ← 太宽：把整个内网都当代理了
    XFF: "1.2.3.4, 10.9.9.9"   →  返回 1.2.3.4   # 10.9.9.9 被当成代理跳过
    VIGILSERVE_TRUSTED_PROXIES=10.0.0.1          # ← 只写代理那一台的地址
    XFF: "1.2.3.4, 10.9.9.9"   →  返回 10.9.9.9  # 正确

    （同理，`127.0.0.1` / `::1` 可以放心列进去——本机反代是唯一不会与客户端冲突的。）

🚨 配套要求（缺了这个等于白改）
--------------------------------
光有本模块**不够**：uvicorn 默认启用的 `ProxyHeadersMiddleware` 会先于任何业务代码
把 ASGI scope 里的 `client` 改写成 XFF 的值（默认 trusted_hosts="127.0.0.1"），
于是这里读到的 `request.client.host` 已经是伪造值，本模块的所有判断都形同虚设。
必须在服务端启动时带上 `proxy_headers=False`（见 `main.py` 的
`_no_proxy_headers_kwargs()` 与 `web_proxy_server.py`）。

表现很有迷惑性：单元测试全绿（用的是假 request），端到端却照样把伪造 IP 写进审计日志。
"""
import ipaddress
import os
from typing import Any, Tuple

ENV_NAME = "VIGILSERVE_TRUSTED_PROXIES"

# env 每次请求读一次太浪费，按「原始字符串」缓存解析结果（改了 env 自动失效）
_CACHE: dict = {"raw": None, "nets": ()}


def _parse_networks(raw: str) -> Tuple[ipaddress._BaseNetwork, ...]:
    nets = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            # 配错了就当没配（不抛异常，避免因为一个笔误把鉴权/日志路径打断）
            continue
    return tuple(nets)


def trusted_networks() -> Tuple[ipaddress._BaseNetwork, ...]:
    """当前生效的可信代理网段（空元组 = 不信任任何 XFF）。"""
    raw = (os.environ.get(ENV_NAME) or "").strip()
    if _CACHE["raw"] != raw:
        _CACHE["nets"] = _parse_networks(raw)
        _CACHE["raw"] = raw
    return _CACHE["nets"]


def _is_trusted(addr: str) -> bool:
    nets = trusted_networks()
    if not nets or not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in n for n in nets)


def get_client_ip(request: Any) -> str:
    """返回该请求**不可伪造**的来源 IP。

    兼容 Starlette 的 `Request` 与 `WebSocket`（两者都有 `.client` 和 `.headers`）。
    任何取不到值的情况都退化成空串，绝不抛异常 —— 取 IP 是记日志的辅助动作，
    不能因为它把主流程（登录、终端、文件操作）带崩。
    """
    direct = ""
    try:
        direct = request.client.host if request.client else ""
    except Exception:  # noqa: BLE001
        direct = ""

    forwarded = ""
    try:
        forwarded = (request.headers.get("x-forwarded-for") or "").strip()
    except Exception:  # noqa: BLE001
        forwarded = ""

    if not forwarded:
        return direct

    # 直连方不是可信代理 → XFF 是客户端自己写的，一律不采信
    if not _is_trusted(direct):
        return direct

    # 直连方可信：从右往左跳过可信代理，第一个「不可信」的地址就是真实客户端
    parts = [p.strip() for p in forwarded.split(",") if p.strip()]
    for addr in reversed(parts):
        if not _is_trusted(addr):
            return addr
    # 整条链都是可信代理（少见），退回最左侧（此时它至少是代理写的）
    return parts[0] if parts else direct


def raw_forwarded_for(request: Any) -> str:
    """原样返回 X-Forwarded-For 头（用于在审计详情里留痕，不当作来源 IP）。"""
    try:
        return (request.headers.get("x-forwarded-for") or "").strip()
    except Exception:  # noqa: BLE001
        return ""
