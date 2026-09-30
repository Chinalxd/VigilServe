"""「WEB管理」代理用的窄票据（ticket）。

为什么需要它
------------
设备自带的 Web 界面里，点链接、meta refresh、表单提交都不会带上我们第一次那
个 `?token=`，所以要么用 Cookie、要么把凭据写进 URL。

* Cookie 这条路在**沙箱 iframe 里走不通** —— 实测：不带 allow-same-origin 时浏览器
  会把该文档下发/接收的 Cookie 全部丢掉（不透明源 = 第三方），连设备自己的登录
  Cookie 也存不住，界面直接废掉；
* 而 allow-same-origin 一给，设备页面就跟我们同源，能读 localStorage 里的管理员
  登录令牌 —— 设备被入侵时这是现成的跳板，不能接受。

所以：Sandbox 保持严格，凭据改成**写进 URL 的窄票据**。它跟登录令牌是两回事：

  * 只对 `/api/servers/{id}/web/…` 这一个前缀有效；
  * 绑定了 user 与 server，30 分钟过期；
  * 用主密钥派生的独立密钥做 HMAC，伪造不了，也换不出登录令牌。

即使设备页面把 URL 里的票据读走，能做的也只有"再访问它自己的管理页面"。

会话吊销（2026-09-23 交付审查补漏）
----------------------------------
票据原本只验"签名 + 设备 + 30 分钟有效期"，**不看持有者的会话还在线不在线**：
用户点了退出登录、或被改密码/踢下线之后，已经发出去的票据还能再用满 30 分钟。
因为票据在 URL 里，这段窗口期内任何拿到该 URL 的人都能继续操作设备后台。

加一层**用户级会话代号（epoch）**：签发时把用户当前的 epoch 写进载荷，
校验时比对；登出 / 改密码 / 改角色 / 停用 / 删号时 epoch +1，该用户**所有**
已签发的票据立刻失效。

为什么用文件而不是内存字典：独立源代理（`web_proxy_server.py`，8009）是**另一个
进程**，读不到主进程的 `routes.auth.TOKENS`。落到 `backend/data/` 下的一个小 JSON，
两个进程共享同一份状态，且不需要动数据库表结构。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Optional

from services.secret_store import derived_key

_PURPOSE = "network-web-proxy"
TTL_SECONDS = 30 * 60

# epoch 落盘位置：`backend/data/` 是运行时数据目录（已被打包脚本排除，见
_EPOCH_PATH = Path(__file__).resolve().parent.parent / "data" / "web_ticket_epoch.json"

# 代理页每个子资源请求都要过一次 verify()，所以按 mtime 做一层读缓存，
_epoch_cache: dict = {"mtime": -1.0, "data": {}}


def _load_epochs() -> dict:
    try:
        st = _EPOCH_PATH.stat()
    except OSError:
        return {}
    if st.st_mtime != _epoch_cache["mtime"]:
        try:
            raw = json.loads(_EPOCH_PATH.read_text(encoding="utf-8"))
            _epoch_cache["data"] = {int(k): int(v) for k, v in raw.items()}
        except Exception:  # noqa: BLE001 文件损坏/为空 当作全部未吊销
            _epoch_cache["data"] = {}
        _epoch_cache["mtime"] = st.st_mtime
    return _epoch_cache["data"]


def _save_epochs(data: dict) -> None:
    try:
        _EPOCH_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _EPOCH_PATH.with_name(_EPOCH_PATH.name + ".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, _EPOCH_PATH)
        _epoch_cache["data"] = dict(data)
        try:
            _epoch_cache["mtime"] = _EPOCH_PATH.stat().st_mtime
        except OSError:
            _epoch_cache["mtime"] = -1.0
    except Exception as exc:  # noqa: BLE001
        # 写不进去不能让登录/登出失败，降级为"本次吊销不生效"
        import logging
        logging.getLogger(__name__).warning(f"[web-ticket] 会话代号落盘失败：{exc}")


def current_epoch(user_id) -> int:
    """该用户当前的会话代号（从未吊销过则为 0）。"""
    try:
        return int(_load_epochs().get(int(user_id), 0))
    except (TypeError, ValueError):
        return 0


def bump_epoch(user_id) -> int:
    """吊销该用户**所有**已发出的 WEB 代理票据，返回新的代号。"""
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return 0
    data = dict(_load_epochs())
    data[uid] = int(data.get(uid, 0)) + 1
    _save_epochs(data)
    return data[uid]


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(payload: bytes) -> str:
    mac = hmac.new(derived_key(_PURPOSE), payload, hashlib.sha256).digest()
    return _b64e(mac[:24])


def _decode(payload: bytes):
    """载荷 → (uid, sid, exp, epoch)。兼容升级前签发的三段式旧票据（epoch 视为 0）。"""
    parts = payload.decode("ascii").split(".")
    if len(parts) == 4:
        uid, sid, exp, ep = parts
    elif len(parts) == 3:
        uid, sid, exp = parts
        ep = "0"
    else:
        raise ValueError("bad payload")
    return int(uid), int(sid), int(exp), int(ep)


def mint(user_id: int, server_id: int, ttl: int = TTL_SECONDS) -> str:
    """发一张票据：载荷 = 用户 + 设备 + 过期时间 + 会话代号。"""
    payload = (
        f"{int(user_id)}.{int(server_id)}.{int(time.time()) + int(ttl)}"
        f".{current_epoch(user_id)}"
    ).encode("ascii")
    return f"{_b64e(payload)}.{_sign(payload)}"


def verify(ticket: str, server_id: int) -> Optional[int]:
    """校验通过返回 user_id，否则 None。

    不通过的几种情况：签名不符、换了设备、过期，以及**会话已结束**
    （用户登出 / 被改密码 / 被停用后，代号已经变了）。
    """
    if not ticket or "." not in ticket:
        return None
    body, _, sig = ticket.rpartition(".")
    try:
        payload = _b64d(body)
    except Exception:  # noqa: BLE001
        return None
    if not hmac.compare_digest(sig, _sign(payload)):
        return None
    try:
        uid, sid, exp, epoch = _decode(payload)
        if int(sid) != int(server_id):
            return None
        if int(exp) < int(time.time()):
            return None
        if epoch != current_epoch(uid):
            return None
        return int(uid)
    except Exception:  # noqa: BLE001
        return None


def peek_server_id(ticket: str) -> Optional[int]:
    """**先验签**再返回票据里的 server_id；任何一步不过就返回 None。

    给"独立源"部署用（`backend/web_proxy_server.py`）：那里路径里没有 {server_id}，
    但票据签名本来就把 server_id 覆盖在内，取出来不降低鉴权强度——
    伪造的票据在这一步就会被签名校验挡掉，过期票据也挡掉。
    注意：拿到 sid 之后**仍要**照常调 `verify(ticket, sid)` 取 user_id，
    本函数只是"换一个 server_id 的来源"。
    """
    if not ticket or "." not in ticket:
        return None
    body, _, sig = ticket.rpartition(".")
    try:
        payload = _b64d(body)
    except Exception:  # noqa: BLE001
        return None
    if not hmac.compare_digest(sig, _sign(payload)):
        return None
    try:
        _uid, sid, exp, _epoch = _decode(payload)
        if int(exp) < int(time.time()):
            return None
        sid = int(sid)
        return sid if sid > 0 else None
    except Exception:  # noqa: BLE001
        return None
