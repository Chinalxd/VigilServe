"""设备 Web 会话 Cookie 的服务端保管箱。

沙箱 iframe 里浏览器**不保存任何 Cookie**（原因见 `web_proxy_ticket` 的模块说明），
所以设备自己的登录会话只能由服务端替它记着：设备下发 `Set-Cookie` 时我们收进内存，
下次转发请求时再原样送回去。浏览器全程不参与，因此这些 Cookie 也不会落在我们的
域名下，更不会被别的页面拿到。

键 = `(user_id, server_id)` —— 同一台设备换个人打开就是另一个会话，不会串号。
条目带最后使用时间，闲置超 `IDLE_TTL` 即丢弃；总量设上限，防止内存被顶爆。
"""
from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Tuple

IDLE_TTL = 2 * 60 * 60
MAX_SESSIONS = 200

_lock = threading.Lock()
_store: Dict[Tuple[int, int], dict] = {}


def _prune(now: float) -> None:
    dead = [k for k, v in _store.items() if now - v["ts"] > IDLE_TTL]
    for k in dead:
        _store.pop(k, None)
    if len(_store) > MAX_SESSIONS:
        for k, _ in sorted(_store.items(), key=lambda kv: kv[1]["ts"])[: len(_store) - MAX_SESSIONS]:
            _store.pop(k, None)


def store(user_id: int, server_id: int, set_cookie_headers: List[str]) -> None:
    """收下设备下发的 Set-Cookie（含删除语义：Max-Age=0 / 过期即移除）。"""
    if not set_cookie_headers:
        return
    key = (int(user_id), int(server_id))
    now = time.time()
    with _lock:
        _prune(now)
        entry = _store.setdefault(key, {"cookies": {}, "ts": now})
        for raw in set_cookie_headers:
            pair = (raw or "").split(";")[0].strip()
            if not pair or "=" not in pair:
                continue
            name, _, value = pair.partition("=")
            name, value = name.strip(), value.strip()
            low = (raw or "").lower()
            expired = "max-age=0" in low or "max-age=-" in low or "expires=thu, 01 jan 1970" in low
            if not value or expired:
                entry["cookies"].pop(name, None)
            else:
                entry["cookies"][name] = value
        entry["ts"] = now


def header_for(user_id: int, server_id: int) -> Optional[str]:
    """拼出要发给设备的 Cookie 头；没有会话就返回 None。"""
    key = (int(user_id), int(server_id))
    now = time.time()
    with _lock:
        entry = _store.get(key)
        if not entry:
            return None
        if now - entry["ts"] > IDLE_TTL:
            _store.pop(key, None)
            return None
        entry["ts"] = now
        if not entry["cookies"]:
            return None
        return "; ".join(f"{k}={v}" for k, v in entry["cookies"].items())


def drop(user_id: int, server_id: int) -> None:
    with _lock:
        _store.pop((int(user_id), int(server_id)), None)


def count() -> int:
    with _lock:
        return len(_store)
