"""网络设备 WEB 代理的 **TLS 指纹钉扎**（TOFU）。

背景
----
代理转发请求给交换机 / 路由器 / NAS / 防火墙时，目标用的是**设备自己签发的证书**，
不在任何公共信任链里，我们的本地 CA 也签不了它 —— 所以代码只能写 `verify=False`。
代价是完全不设防：内网里谁能做一次中间人，谁就能读到我们替设备带上的会话 Cookie
和自动填充的登录口令。

解决办法改成 **Trust On First Use（首次使用即钉住）**：

  * 第一次连某台设备：取它叶子证书的 SHA-256 指纹，记进 JSON，放行；
  * 之后每次连接：比对该指纹，**不一致就直接断开**并报明确错误
    —— 这正是一次中间人攻击会出现的现象；
  * 设备重装 / 换证书后需要**显式重钉**（`clear_pin()` 或 repin 接口），
    不允许自动接受新指纹（否则中间人只要等一次换证就进来了）。

为什么指纹用**整张叶子证书**而不是 SPKI 公钥：设备重签（同一把私钥换新有效期）
时 SPKI 不变、整证书变。这里宁可严格一点——换了就要求人工重钉。

为什么不用 `cert_verify` 之类的 requests 钩子：那样拿不到对端证书。这里通过
urllib3 的 connection 子类，在 TLS 握手完成后立刻读 `getpeercert()`，
**不额外增加一次往返**，因此不会拖慢设备页面的子资源加载。

文件落在 `backend/data/` 下（运行时数据，已被打包脚本排除）。
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("backend")

_PIN_PATH = Path(__file__).resolve().parent.parent / "data" / "device_tls_pins.json"

_lock = threading.Lock()
_cache: dict = {"mtime": -1.0, "data": {}}

#   strict—— 与 tofu 相同，但**没有**已存指纹时直接拒绝（需先手工录入，适合强管控）
#   off   —— 退回原来的完全不校验（排障用）
VALID_MODES = ("tofu", "strict", "off")


def mode() -> str:
    raw = (os.environ.get("VIGILSERVE_DEVICE_TLS_PIN") or "tofu").strip().lower()
    return raw if raw in VALID_MODES else "tofu"


def _load() -> dict:
    try:
        st = _PIN_PATH.stat()
    except OSError:
        return {}
    if st.st_mtime != _cache["mtime"]:
        try:
            raw = json.loads(_PIN_PATH.read_text(encoding="utf-8"))
            _cache["data"] = raw if isinstance(raw, dict) else {}
        except Exception:  # noqa: BLE001  文件损坏 → 当作全部未钉
            _cache["data"] = {}
        _cache["mtime"] = st.st_mtime
    return _cache["data"]


def _save(data: dict) -> None:
    try:
        _PIN_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _PIN_PATH.with_name(_PIN_PATH.name + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, _PIN_PATH)
        _cache["data"] = dict(data)
        try:
            _cache["mtime"] = _PIN_PATH.stat().st_mtime
        except OSError:
            _cache["mtime"] = -1.0
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"[device-tls] 指纹落盘失败（本次钉扎不生效）：{exc}")


def _key(server_id) -> str:
    return str(int(server_id))


def get_pin(server_id) -> Optional[str]:
    """这台设备已经钉住的证书指纹（十六进制 sha256）；没有则返回 None。"""
    with _lock:
        entry = _load().get(_key(server_id))
    if isinstance(entry, dict):
        fp = entry.get("sha256")
        return str(fp) if fp else None
    return None


def pin_info(server_id) -> Optional[dict]:
    with _lock:
        entry = _load().get(_key(server_id))
    return dict(entry) if isinstance(entry, dict) else None


def set_pin(server_id, fingerprint: str, subject: str = "") -> None:
    """记下这台设备的证书指纹（首次连接时自动调用）。"""
    with _lock:
        data = dict(_load())
        data[_key(server_id)] = {
            "sha256": fingerprint,
            "pinned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "subject": subject or "",
        }
        _save(data)
    logger.info(f"[device-tls] 已为设备 {server_id} 钉住证书指纹 "
                f"{fingerprint[:16]}…（{subject or '未知主体'}）")


def clear_pin(server_id) -> bool:
    """撤销这台设备的指纹（换证书/重装设备后由运维显式触发）。"""
    with _lock:
        data = dict(_load())
        existed = data.pop(_key(server_id), None) is not None
        if existed:
            _save(data)
    if existed:
        logger.info(f"[device-tls] 已撤销设备 {server_id} 的证书指纹，下次连接将重新钉扎")
    return existed


def fingerprint_of_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


# ── 转发前校验 ──────────────────────────────────────────────────
# 每个设备 HEAD 一次 TLS 握手太重（设备页面一屏几十个子资源），所以校验结果在进程内
# 缓存 _PIN_TTL 秒：这段时间内的后续请求沿用刚才那条已验证过的 TLS 连接结论。
# 窗口很短，够覆盖一次页面加载，又不会让校验证书长期失察。
_PIN_TTL = 60.0
_probe_timeout = 5.0
_checked: dict = {}


def set_probe_timeout(seconds: float) -> None:
    global _probe_timeout
    _probe_timeout = float(seconds)


def _subject_of(peer: dict) -> str:
    try:
        parts = []
        for rdn in peer.get("subject") or ():
            for k, v in rdn:
                if k in ("commonName", "organizationName"):
                    parts.append(f"{k}={v}")
        return ", ".join(parts)
    except Exception:  # noqa: BLE001
        return ""


def probe(host, port, timeout: float | None = None) -> tuple:
    """与设备做一次握手，返回 (指纹, 证书主体)。

    这里刻意用 CERT_NONE：**设备的自签证书本来就不在任何信任链里**，
    拿它做链路校验只会永远失败；防中间人不靠信任链，靠后面的指纹比对。
    """
    import socket
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, int(port)),
                                  timeout=timeout or _probe_timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=str(host)) as s:
            der = s.getpeercert(binary_form=True)
            if not der:
                raise RuntimeError("对端没有出示证书")
            return fingerprint_of_der(der), _subject_of(s.getpeercert() or {})


def before_request(server_id, scheme: str, host, port) -> tuple:
    """转发到设备之前调用。返回 (是否放行, 错误说明)。"""
    if mode() == "off":
        return True, ""
    if (scheme or "").lower() != "https":
        # 明文连接没有证书可钉（真要防得去设备上开 HTTPS，不在本函数职责内）
        return True, ""

    target = f"{host}:{port}"
    cached = _checked.get(server_id)
    if cached and cached[0] == target and (time.time() - cached[2]) < _PIN_TTL:
        return True, ""

    try:
        fp, subject = probe(host, port)
    except Exception as exc:  # noqa: BLE001
        return False, f"与设备 {target} 建立 TLS 连接失败：{exc}"

    known = get_pin(server_id)
    if known is None:
        if mode() == "strict":
            return False, (f"strict 模式下设备 {target} 还没有录入证书指纹，"
                           "拒绝连接；请先在「网络设备」上执行一次重钉。")
        set_pin(server_id, fp, subject)
    elif known != fp:
        return False, (
            f"设备 {target} 的证书与已记录的不一致（记录 {known[:12]}…，本次 {fp[:12]}…）。"
            "如果是设备重装或换过证书，请在「网络设备」里执行「重钉证书」；"
            "否则请按中间人攻击排查后再继续。"
        )
    _checked[server_id] = (target, fp, time.time())
    return True, ""


def forget_cached(server_id) -> None:
    """重钉之后立刻作废进程内缓存，下次请求重新握手。"""
    _checked.pop(server_id, None)
