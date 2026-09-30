"""Agent 侧 TLS 工具（安全加固阶段 2）。

服务端启用 HTTPS 后，Agent 需要：
  1. 用**随包内置的 CA**（`ca/vigilserve-ca.crt`）校验服务端证书，而不是"信任一切"；
  2. 在老配置（http）下探测同端口是否已升级到 https，成功就自动改写配置 ——
     这样服务端切 HTTPS 后 Agent 会自己找回来，不必逐台手改。

CA 路径优先级：
  配置里的 `ca_file`  >  %LOCALAPPDATA%\\VigilServe\\Config\\Agent\\vigilserve-ca.crt
                     >  安装目录\\ca\\vigilserve-ca.crt  >  安装目录\\vigilserve-ca.crt

 从 1.1.56 起，随包内置的 CA 只是一种"开箱即用"的便利，**不再被当作唯一来源**：
每台服务端都自签自己的本地 CA，预置 CA 只对打包那台机器有效。换台机器部署就必然
报「证书未被信任（缺少本地 CA）」，这时由 `fetch_server_ca()` + `trust_ca_pem()`
从服务端把 CA 取回来并落盘（上面第 2 个路径，优先级高于内置 CA），操作员核对
指纹后生效。详见本文件 `CA_UNTRUSTED_MARK` 附近的说明。
"""
from __future__ import annotations

import os
import ssl
import socket

_CTX_CACHE: dict = {}
_warned_no_verify = False


def _warn_no_verify() -> None:
    """配置里关掉了证书校验 —— 只在第一次告警一次，别把日志刷满。"""
    global _warned_no_verify
    if _warned_no_verify:
        return
    _warned_no_verify = True
    try:
        import logging
        logging.getLogger(__name__).warning(
            "[tls] ⚠ 配置 verify_tls=false —— 与服务端的连接**不校验证书**，"
            "链路可被中间人窃听/篡改。除非正在排障，请把配置改回 true。"
        )
    except Exception:  # noqa: BLE001
        pass


def bundled_ca_path() -> str:
    """随包内置的 CA 证书路径；找不到返回空串。"""
    try:
        from paths import CONFIG_DIR, INSTALL_DIR
    except Exception:  # noqa: BLE001
        INSTALL_DIR = os.path.dirname(os.path.abspath(__file__))
        CONFIG_DIR = INSTALL_DIR
    for p in (
        os.path.join(CONFIG_DIR, "vigilserve-ca.crt"),
        os.path.join(INSTALL_DIR, "ca", "vigilserve-ca.crt"),
        os.path.join(INSTALL_DIR, "vigilserve-ca.crt"),
    ):
        if p and os.path.isfile(p):
            return p
    return ""


def ca_path(cfg: dict | None = None) -> str:
    cfg = cfg or {}
    explicit = str(cfg.get("ca_file") or "").strip()
    if explicit and os.path.isfile(explicit):
        return explicit
    return bundled_ca_path()


def load_cfg() -> dict:
    try:
        import config as _cfg_mod
        return _cfg_mod.load() or {}
    except Exception:  # noqa: BLE001
        return {}


def ssl_context(cfg: dict | None = None) -> ssl.SSLContext:
    """构造校验证书用的 SSLContext（按 CA/校验开关做缓存）。"""
    cfg = cfg if cfg is not None else load_cfg()
    verify = cfg.get("verify_tls") is not False
    ca = ca_path(cfg)
    key = (ca, verify)
    ctx = _CTX_CACHE.get(key)
    if ctx is not None:
        return ctx
    if not verify:
        # 交付审查 P1-6 复核：这个分支本身是**显式 opt-out**（默认走上面的 CA 校验），
        # 属于合理设计。以前它静默生效，配置里躺着一个 verify_tls=false，出问题
        # 排查半天也想不到链路是裸的。现在每次构造都留一条告警。
        _warn_no_verify()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif ca:
        ctx = ssl.create_default_context(cafile=ca)
    else:
        # 没有内置 CA（极少见） 退回系统信任库，仍然会校验证书链
        ctx = ssl.create_default_context()
    _CTX_CACHE[key] = ctx
    return ctx


def context_from_disk() -> ssl.SSLContext:
    return ssl_context(load_cfg())


def request_context(url: str, cfg: dict | None = None):
    """给 urllib 请求挑 SSLContext：https 要带本地 CA，http 不需要。

    `urlopen(req, context=...)` 传 None 表示走默认行为（http 或不校验）。
    """
    if str(url or "").startswith("https://"):
        return ssl_context(cfg if cfg is not None else load_cfg())
    return None


def _friendly_error(e: Exception, url: str) -> str:
    """把 urlopen 的异常翻成运维看得懂的话（原来只显示 `str(e)[:60]`，全是英文）。"""
    msg = str(e)[:160]
    low = msg.lower()
    if "certificate_verify_failed" in low or "certificate verify failed" in low:
        return f"证书未被信任（缺少本地 CA）— {url}"
    if "remote end closed" in low or "10061" in msg or "refused" in low:
        return f"连不上，服务端可能已切到 HTTPS — {url}"
    if "timed out" in low or "timeout" in low:
        return f"连接超时 — {url}"
    return msg


# 背景：每台 VigilServe 服务端都在**首次启动时自签一把本地 CA**（backend/services/tls.py），
# 所以任何"预置在 Agent 安装包里"的 CA 只对打包那台机器有效。换个服务端部署，
# 内置 CA 必然校验不过，界面上就是「证书未被信任（缺少本地 CA）」，而且此时 Agent
# 还没有任何凭据，所有需要登录的接口都调不动，靠自己是走不出来的。
# 出路只有一个：让 Agent 能从服务端把 CA 取回来。取回来必须**人工核对指纹**再落盘，
# 否则等于"第一次连接谁先说谁就是服务端"，中间人插一脚就永久被骗（TOFU 的老问题）。
# 服务端侧的同一串指纹可以在「系统设置 - 安全设置 - 服务端证书」里看到。

CA_UNTRUSTED_MARK = "证书未被信任"


def is_ca_untrusted(msg: str) -> bool:
    """这句失败说明是"CA 不认识"，而不是网络不通 —— 界面据此给出下一步指引。"""
    return CA_UNTRUSTED_MARK in (msg or "")


def _unverified_context() -> ssl.SSLContext:
    """只为取信任根用的一次性上下文：**不校验任何证书**。

    这不是"偷懒关校验"：本函数的存在意义就是"在还没有信任根的时候把信任根拿回来"，
    鸡生蛋问题没有第二种解法。安全性靠调用方的人工指纹核对兜住。
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_server_ca(base_url: str, timeout: float = 8.0) -> tuple[bool, str, dict]:
    """从服务端取本地 CA：`GET {base_url}/api/agent/ca`（该接口免鉴权）。

    返回 `(是否成功, 失败说明, 服务端回包)`；回包里含 `ca_pem` / `fingerprint`。
    """
    import json as _json
    from urllib import request as _rq

    base = str(base_url or "").strip().rstrip("/")
    if not base:
        return False, "请先填写服务端地址", {}
    url = base + "/api/agent/ca"
    try:
        req = _rq.Request(url, method="GET")
        with _rq.urlopen(req, timeout=timeout,
                         context=_unverified_context()) as resp:
            data = _json.loads(resp.read().decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        return False, _friendly_error(e, url), {}
    if not isinstance(data, dict) or not (data.get("ca_pem") or "").strip():
        return False, "服务端没有返回 CA 证书（可能尚未启用 HTTPS）", {}
    return True, "", data


def fingerprint_of_pem(pem: str) -> str:
    """CA 证书的 SHA-256 指纹，格式与服务端显示的完全一致（`AA:BB:…`）。

    两边显示的格式必须一样，否则"对着念"这件事根本做不到。
    """
    import hashlib
    try:
        der = ssl.PEM_cert_to_DER_cert(str(pem))
    except Exception:  # noqa: BLE001
        return ""
    fp = hashlib.sha256(der).hexdigest().upper()
    return ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))


def manual_ca_path() -> str:
    """人工放置 CA 的目标路径（无界面 / 无头模式下没有"信任"按钮时用）。"""
    cfg = load_cfg()
    explicit = str(cfg.get("ca_file") or "").strip()
    if explicit:
        return explicit
    try:
        from paths import CONFIG_DIR
    except Exception:  # noqa: BLE001
        CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(CONFIG_DIR, "vigilserve-ca.crt")


def cert_error_hint(exc_or_msg) -> str:
    """证书不被信任时，返回"人该怎么做"，否则返回空串。

    无头模式（`agent_headless.py`，服务端本机自带的 Agent 就是这个模式）没有界面可点，
    必须在日志里把出路写清楚，否则现场看到的只是一串
    `SSLCertVerificationError`，根本不知道下一步做什么。
    """
    text = str(exc_or_msg or "")
    low = text.lower()
    if not any(k in low for k in (
            "certificate_verify_failed", "certificate verify failed",
            "self-signed", "self signed", "unable to get local issuer")):
        return ""
    return ("本机没有该服务端的 CA 证书。两条出路：① 在有界面的 Agent 配置面板点"
            "「信任服务端证书」；② 把服务端 backend\\certs\\ca.crt 复制为 "
            f"{manual_ca_path()}，然后重启 Agent。")


def trust_ca_pem(pem: str) -> str:
    """把服务端 CA 落盘为**本机的信任根**，返回落盘路径。

    写入位置：配置里显式指定了 `ca_file` 就尊重它，否则写
    `%LOCALAPPDATA%\\VigilServe\\Config\\Agent\\vigilserve-ca.crt`
    —— 这个路径在 `bundled_ca_path()` 的查找顺序里**排在随包内置 CA 之前**，
    所以写进去立刻生效，不需要改任何其它代码。

 必须清 `_CTX_CACHE`：`ssl_context()` 按 (ca, verify) 做了缓存，
    不清的话新 CA 要等进程重启才生效，界面上就是"点了信任、再测还是失败"。
    """
    pem = str(pem or "").strip()
    if not pem:
        raise ValueError("CA 内容为空")
    ssl.PEM_cert_to_DER_cert(pem)  # 格式不对会在这里抛，别把坏文件写进信任库

    cfg = load_cfg()
    explicit = str(cfg.get("ca_file") or "").strip()
    if explicit:
        target = explicit
        os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
    else:
        try:
            from paths import CONFIG_DIR
        except Exception:  # noqa: BLE001
            CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))
        os.makedirs(CONFIG_DIR, exist_ok=True)
        target = os.path.join(CONFIG_DIR, "vigilserve-ca.crt")

    if not pem.endswith("\n"):
        pem += "\n"
    with open(target, "w", encoding="utf-8") as f:
        f.write(pem)
    _CTX_CACHE.clear()
    return target


def ping_server(url: str, cfg: dict | None = None, timeout: float = 10.0) -> tuple[bool, str]:
    """「测试连接」按钮用：请求服务端 `/api/agent/ping`。

    服务端切到 HTTPS 后，裸 `urlopen` 会因自签证书直接 CERTIFICATE_VERIFY_FAILED，
    必须带上随包内置的 CA；若用户填的还是 http://，再自动试一次同端口的 https。
    返回 `(是否可达, 说明文字)`。
    """
    ok, msg, _ = resolve_base_url(url, cfg, timeout)
    return ok, msg


def resolve_base_url(url: str, cfg: dict | None = None,
                     timeout: float = 10.0) -> tuple[bool, str, str]:
    """同 ping_server，但**额外返回真正连通的那个 base url**。

    为什么要返回它：服务端切 HTTPS 后，配置里可能还留着 http（`server_scheme`
    缺失或没被更新）。此时 ping 内部会自动改试 https 并成功，但调用方手里那个
    `url` 仍是个 http —— 拿它去发后续请求（例如注册）就变成"明文 HTTP 打 HTTPS
    端口"，服务端直接断开，报 `RemoteDisconnected: Remote end closed connection
    without response`。所以调用方必须改用这里返回的 effective url。

    返回 `(是否可达, 说明文字, 生效的 base url)`；不可达时第三项为空串。
    """
    from urllib import request as _rq

    cfg = cfg if cfg is not None else load_cfg()
    url = str(url or "").strip().rstrip("/")
    if not url:
        return False, "请先填写服务端地址", ""

    attempts = [url]
    if url.startswith("http://"):
        attempts.append("https://" + url[len("http://"):])

    last = ""
    for idx, target in enumerate(attempts):
        try:
            req = _rq.Request(target + "/api/agent/ping", method="GET")
            with _rq.urlopen(req, timeout=timeout, context=request_context(target, cfg)) as resp:
                resp.read()
            suffix = "（服务端已切 HTTPS，已自动改用）" if idx else ""
            return True, f"服务端可达 — {target}{suffix}", target
        except Exception as e:  # noqa: BLE001
            last = _friendly_error(e, target)
    return False, f"连接失败 - {last}", ""


def probe_https(host: str, port: int, cfg: dict | None = None, timeout: float = 4.0) -> bool:
    """探一次 TLS 握手，看该端口是否已是**由本地 CA 签出**的证书。

    刻意不校验主机名：这里只想判断"服务端已经开了 HTTPS"，
    真正发起业务请求时由 urlopen 做完整校验（含 SAN）。
    """
    if not host or not port:
        return False
    cfg = cfg if cfg is not None else load_cfg()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    if cfg.get("verify_tls") is False:
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ca = ca_path(cfg)
        ctx.verify_mode = ssl.CERT_REQUIRED
        if ca:
            try:
                ctx.load_verify_locations(cafile=ca)
            except Exception:  # noqa: BLE001
                ctx.load_default_certs()
        else:
            ctx.load_default_certs()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            with ctx.wrap_socket(raw):
                return True
    except Exception:  # noqa: BLE001
        return False
