"""服务端 → Agent(9998) 调用的统一鉴权头。

安全加固阶段 1：Agent 的本地 HTTP 接口不再裸奔。
Agent 的 token 就是注册时下发给它的那个值：

    token = hmac_sha256(agent_keys.secret_key, str(server_id)).hexdigest()

服务端持有 `secret_key`，因此可以随时算出与 Agent **完全相同** 的 token ——
不需要 Agent 再额外回报什么，也不需要动表结构。

用法（所有代理到 Agent 的地方都应该走这里）：

    from services.agent_auth import agent_headers
    resp = SESSION.get(url, headers=agent_headers(server), timeout=...)

`agent_headers()` 返回的字典已经包含：
  - `Connection: close`（必须：1.1.36 之前的 Agent 是单线程 + keep-alive，
    后端保持一条空闲长连接就会把它整个占死）
  - `X-Auth-Token`（Agent 尚未注册 / 还没有 AgentKey 时不带，兼容老 Agent）
"""
from __future__ import annotations

import hmac
import logging
import secrets
from typing import Optional

logger = logging.getLogger("backend")


def compute_agent_token(secret_key: str, server_id: int) -> str:
    """与 routes/agent.py 注册时下发的 token 完全一致。"""
    return hmac.new(secret_key.encode(), str(server_id).encode(), "sha256").hexdigest()


# 2026-09-23 开源加固 ⑤：静态 token 可轮换
# 轮换前这把 token 是**永久**的：它写在 agent_config.json 里、从注册那一刻起
# 永不改变，服务端也没有任何接口能让它失效。于是"配置文件泄露一次" =
# 现在管理员可以主动轮换：旧密钥挪到 `secret_key_prev` 并带一个截止时间，
# 窗口内仍接受（让跑在外的 Agent 靠心跳领走新 token），窗口一过自动失效。
# 轮换**不改** token 的计算公式，否则现网所有 Agent 会在重启后端的那一刻
# 集体掉线（它们的配置里还是按旧公式算出来的那份）。
ROTATE_GRACE_SECONDS = 24 * 3600


def rotate_agent_secret(key, grace_seconds: int = ROTATE_GRACE_SECONDS) -> str:
    """轮换一台 Agent 的对称密钥，返回**新的** token。

    :param key: `models.AgentKey` 实例（调用方负责 commit）。
    """
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if key.secret_key:
        key.secret_key_prev = key.secret_key
        key.secret_key_prev_until = now + timedelta(seconds=grace_seconds)
    key.secret_key = secrets.token_hex(16)
    logger.info(f"agent_auth: server_id={key.server_id} 已轮换 Agent 静态 token"
                f"（旧 token 宽限至 {key.secret_key_prev_until}）")
    return compute_agent_token(key.secret_key, key.server_id)


def match_agent_token(key, server_id: int, token: str) -> str:
    """判断 token 对得上哪一把密钥。

    返回 `"current"` / `"prev"` / `""`（都对不上）。
    调用方据此决定：prev 的话要顺手把新 token 下发给 Agent，让它换过来。
    """
    if not token:
        return ""
    # 时区必须和 `rotate_agent_secret` 写入时用的口径一致（naive UTC），
    # 否则在中国时区（UTC+8）下 `datetime.now()` 比库里存的值大 8 小时，
    # 宽限期会被截获 8 小时，表现出来就是"刚轮换完旧 token 就失效了"。
    from datetime import datetime, timezone
    cur = getattr(key, "secret_key", "") or ""
    if cur and hmac.compare_digest(compute_agent_token(cur, server_id), token):
        return "current"
    prev = getattr(key, "secret_key_prev", "") or ""
    if prev and hmac.compare_digest(compute_agent_token(prev, server_id), token):
        until = getattr(key, "secret_key_prev_until", None)
        # 宽限期已过 这把旧密钥彻底作废（泄露出去的 token 到此为止）
        if until is not None:
            _now = datetime.now(timezone.utc).replace(tzinfo=None)
            _until = until.replace(tzinfo=None) if until.tzinfo else until
            if _now > _until:
                return "expired"
        return "prev"
    return ""


# 2026-09-23 开源加固 ④：更新包签名密钥与 token 分离
# token 是 9998 的认证凭据，会随每次服务端Agent 调用在请求头里出现，
# 任何一次抓包 / 日志采集 / 配置文件读取都能拿到它，于是
# 现在签名密钥是**从 secret_key 派生的另一把钥匙**，与 token 单向隔离
# · 想在该机执行恶意包，必须**同时**有 token（过 9998 认证）和 update_key（过验签）；
# · 第 ⑤ 项让 token 可轮换后，update_key 仍独立存在，轮换不会打断验签。
# 它同样由 secret_key 派生 服务端随时可重算，**不需要新表 / 新列**，
UPDATE_KEY_DOMAIN = "vigilserve-agent-update-signing-v1"

# 时间戳新鲜性窗口（秒）。签名串里带签发时刻，超出窗口的包一律拒收，
# 这样"很久以前截获的一个合法包"不能在未来被重放。
UPDATE_TS_TOLERANCE = 300


def compute_update_key(secret_key: str, server_id: int) -> str:
    """更新包验签用的对称密钥 —— **不是** token，也不该出现在任何请求头里。"""
    return hmac.new(
        secret_key.encode(),
        f"{UPDATE_KEY_DOMAIN}|{server_id}".encode(),
        "sha256",
    ).hexdigest()


def sign_update_package(update_key: str, version: str, pkg_sha: str, ts: int) -> str:
    """更新包签名。签名串 = `{version}:{sha256}:{timestamp}`。

 加了 timestamp 才谈得上"新鲜性"：原来只有 `{version}:{sha256}`，
    同一个包在任何时刻的签名都一模一样，截获一次可以无限次重放。
    """
    return hmac.new(
        update_key.encode(),
        f"{version}:{pkg_sha}:{ts}".encode(),
        "sha256",
    ).hexdigest()


# P1-1：Agent 9998 通道全链路 TLS
# Agent 的本地 API 证书由本服务端 CA 签发（register/enroll 时随 token 一起下发），
# 所以这里校验只需锚定 CA。Agent 的 SAN 是签发时上报的 IP，换 IP 后可能不匹配，
# 因此不校验 hostname，只校验证书链，链有效即证明对端是本体系内的 Agent。

def agent_ca_verify() -> Optional[str]:
    """requests 调 Agent https://... 时的 verify 参数（CA 证书路径）。

    返回 None 时调用方应传 verify=False（仅缺 CA 的极端情况，宁可失败也不裸奔明文）。
    """
    try:
        from services import tls as _tls
        if _tls.CA_CERT.exists():
            return str(_tls.CA_CERT)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"agent_auth: 读取 CA 失败：{e}")
    return None


def agent_ssl_context():
    """websockets.connect(wss://...) 连 Agent 终端用的 SSLContext（CA 链校验）。"""
    import ssl
    try:
        from services import tls as _tls
        ctx = ssl.create_default_context(cafile=str(_tls.CA_CERT))
    except Exception as e:  # noqa: BLE001
        logger.warning(f"agent_auth: 构造 SSLContext 失败：{e}")
        ctx = ssl.create_default_context()
    # 交付审查 P1-6 复核（2026-09-23）：这里的 `check_hostname = False` **不是漏洞**，
    # 别照着"关闭了校验"的清单把它改回去。
    # 本函数的前一行是 `verify_mode = CERT_REQUIRED` 且 CA 锚定到**我们自己的本地 CA**
    #，攻击者没有 CA 私钥就签不出能通过这道校验的证书，中间人照样进不来。
    # 不校验主机名是因为：Agent 证书的 SAN 是**签发时上报的 IP**，DHCP 换址或换网卡后
    # 就不匹配了，硬要校验会把大批正常 Agent 打成连接失败。
    # 想收紧的话正确做法是"换 IP 时重新签发/上报并更新 SAN"，而不是打开 check_hostname。
    ctx.check_hostname = False   # Agent 证书 SAN 是签发时的 IP；DHCP 换址后不必匹配
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def token_for_server_id(server_id: int) -> Optional[str]:
    """按 server_id 查 AgentKey 并算出 token；查不到返回 None。"""
    if not server_id:
        return None
    try:
        from database import SessionLocal
        from models import AgentKey
        db = SessionLocal()
        try:
            key = db.query(AgentKey).filter(AgentKey.server_id == server_id).first()
            if not key or not key.secret_key:
                return None
            return compute_agent_token(key.secret_key, server_id)
        finally:
            db.close()
    except Exception as e:  # noqa: BLE001
        logger.warning(f"agent_auth: 读取 AgentKey 失败 server_id={server_id}: {e}")
        return None


def agent_headers(server=None, server_id: Optional[int] = None) -> dict:
    """构造访问 Agent 9998 的请求头。`server` 传 models.Server 或 server_id。"""
    if server_id is None and server is not None:
        server_id = getattr(server, "id", None) or None
    headers = {"Connection": "close"}
    tok = token_for_server_id(int(server_id)) if server_id else None
    if tok:
        headers["X-Auth-Token"] = tok
    return headers


def agent_headers_by_ip(ip: str, port: Optional[int] = None, server_id: Optional[int] = None) -> dict:
    """构造访问 Agent 9998 的请求头，`server_id` 优先于 IP 反查。

 **为什么必须按 server_id 而不是 IP**：S1 之后 IP 不再是身份，同一条线路的
    出口 IP 可能同时对应好几台内网主机（NAT / VPN / 端口映射都行）。这时候按 IP
    反查会取错主机 —— 拿 A 机的口令去敲 B 机的门，运气好只是 401，运气差就是
    "用错误的凭据访问了错误的机器"。给 `server_id` 就没这个歧义。

    为了不让 `file_explorer.py` 的 15 处调用点全部改动，这里保留了 IP 兜底；
    但所有调用点都已经改成显式传 server_id（见 `_proxy_to_agent`）。
    """
    if server_id:
        return agent_headers(server_id=int(server_id))
    headers = {"Connection": "close"}
    if not ip:
        return headers
    logger.warning(
        f"agent_auth: 缺少 server_id，回退到按 IP 反查 token（{ip}:{port}）——"
        f"NAT 场景下可能取到错误的主机，请检查调用方是否已传入 server_id"
    )
    try:
        from database import SessionLocal
        from models import AgentKey, Server
        db = SessionLocal()
        try:
            q = db.query(Server).filter(Server.ip_address == ip)
            if port:
                q = q.filter((Server.agent_port == int(port)) | (Server.agent_port.is_(None)))
            srv = q.first()
            if not srv:
                return headers
            key = db.query(AgentKey).filter(AgentKey.server_id == srv.id).first()
            if key and key.secret_key:
                headers["X-Auth-Token"] = compute_agent_token(key.secret_key, srv.id)
        finally:
            db.close()
    except Exception as e:  # noqa: BLE001
        logger.warning(f"agent_auth: 按 IP 查 token 失败 {ip}:{port}: {e}")
    return headers
