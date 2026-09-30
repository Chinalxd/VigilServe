"""WebSocket 鉴权（安全加固阶段 3）。

浏览器给 WebSocket 发自定义 Header 是不可能的，所以以前只能把 JWT 塞进
URL query（`/ws/terminal/1?token=xxx`）。问题是 URL 会落到：
  - 服务端访问日志 / 反向代理日志
  - 浏览器历史与 Referer
  - 前端崩溃上报

现在改用 **WebSocket 子协议** 携带：
    new WebSocket(url, ["guacamole", "vigitoken.<jwt>"])
子协议只在握手帧里出现，不进 URL、不进 Referer、不进历史记录。

兼容：仍接受 query 参数里的 token（旧前端 / 旧 Agent），但新版本一律走子协议。
"""
from __future__ import annotations

SUBPROTOCOL_PREFIX = "vigitoken."


def token_from_ws(ws) -> str:
    """从子协议里取 token；取不到再回退 query 参数（旧版兼容）。"""
    subs = None
    try:
        subs = ws.scope.get("subprotocols")
    except Exception:  # noqa: BLE001
        subs = None
    for p in (subs or []):
        if isinstance(p, str) and p.startswith(SUBPROTOCOL_PREFIX):
            return p[len(SUBPROTOCOL_PREFIX):].strip()
    try:
        return (ws.query_params.get("token") or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def selected_subprotocol(ws) -> str | None:
    """accept 时必须**回显客户端提供过的**子协议，否则 Chrome 直接断连。

    （RFC6455：服务端只能选客户端列表里的值，或干脆不选；实测 Chrome 对
    "客户端发了但服务端没回"会关掉连接。）
    """
    try:
        subs = ws.scope.get("subprotocols") or []
    except Exception:  # noqa: BLE001
        return None
    for p in subs:
        if isinstance(p, str) and p.startswith(SUBPROTOCOL_PREFIX):
            return p
    return None


def accept(ws, subprotocol: str | None = None):
    """接受连接；显式回显子协议，避免某些浏览器因“服务端未选择子协议”而报错。

    返回 coroutine，调用方 `await accept(ws, "guacamole")`。
    """
    try:
        return ws.accept(subprotocol=subprotocol)
    except TypeError:
        return ws.accept()
