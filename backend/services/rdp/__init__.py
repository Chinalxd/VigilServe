"""远程桌面 hub —— C 方案核心（自研直讲 Guacamole 协议）。

架构（不使用 Windows RDP，所有传输全部通过 Agent）：

    浏览器 (guacamole-common-js)
         <--WS /api/rdp/tunnel/{server_id} (子协议 "guacamole", 文本指令)-->  本模块
         <--WS /api/rdp/agent/{server_id} (二进制 JPEG 上行 / JSON 控制下行)--> VigilServe Agent

协议要点（已逐行核对 guacamole-common-js 1.5.0，勿凭记忆改）：
  * 首条指令必须是内部指令（opcode 为空）+ 单个元素 = tunnel UUID，客户端据此把
    tunnel 置为 OPEN
  * 服务端发首条 sync 后客户端才 setState(CONNECTED)，并 echo sync 回来（测 RTT）
  * 客户端空闲时发内部 ping，必须原样回一条
  * jpeg 指令的 channelMask 必须是 0x0E（见 guac.py 注释），发 0x0F 会全画面饱和成白

会话生命周期：
  * 观看端连上 tunnel -> viewers[server_id] 非空 -> /api/agent/config 返回
    remote_desktop_active=true -> Agent 在下一次配置轮询（约 5 秒内）开流
  * 最后一个观看端断开 -> viewers[server_id] 清空 -> 标志变 false -> Agent 停流
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid

from . import guac, keysym

logger = logging.getLogger("backend.rdp")

M_LEFT, M_MIDDLE, M_RIGHT, M_WHEEL_UP, M_WHEEL_DOWN = 1, 2, 4, 8, 16
_BUTTONS = ((M_LEFT, "left"), (M_MIDDLE, "middle"), (M_RIGHT, "right"))
WHEEL_DELTA = 120
VK_SHIFT = 0xA0
VK_CAPITAL = 0x14

_CAPS_KEYSYMS = frozenset((0xFFE5, 0xFFE6))
_SHIFT_KEYSYMS = frozenset((0xFFE1, 0xFFE2))
_CMD_KEYSYMS = frozenset((0xFFE3, 0xFFE4, 0xFFE7, 0xFFE8, 0xFFE9, 0xFFEA,
                          0xFFEB, 0xFFEC, 0xFFED, 0xFFEE, 0xFE03))

# ---------------------------------------------------------------- 安全策略（阶段 3）
# 远程桌面等同于拿到被控端桌面的完整控制权，按项目惯例只允许管理员使用
REQUIRE_ADMIN = True
MAX_VIEWERS_PER_SERVER = 8
MAX_SESSIONS_PER_USER = 4
SESSION_MAX_SECONDS = 8 * 3600
VIEWER_IDLE_SECONDS = 180       # 观看端多久没有任何指令（含客户端 ping）就判定掉线
IDLE_CHECK_INTERVAL = 20

DEFAULT_SETTINGS = {"fps": 15, "quality": 60, "max_width": 1600}
QUALITY_PRESETS = {
    "low": {"fps": 10, "quality": 35, "max_width": 1024},
    "medium": {"fps": 15, "quality": 60, "max_width": 1600},
    "high": {"fps": 20, "quality": 80, "max_width": 1920},
}

COMBOS = {
    "cad": "Ctrl+Alt+Del",
    "taskmgr": "任务管理器",
    "altab": "Alt+Tab",
    "winl": "锁定",
    "win": "开始菜单",
}


class GuacViewer:
    """一个观看端连接。帧从 Agent 广播进来排队，由 sender 协程编码成 Guacamole 指令。"""

    def __init__(self, server_id: int, ws, user: dict | None = None,
                 client_ip: str = "") -> None:
        self.server_id = server_id
        self.ws = ws
        self.queue: asyncio.Queue[tuple[int, int, bytes]] = asyncio.Queue(maxsize=2)
        self.width = 0
        self.height = 0
        self.mouse_mask = 0
        self.shift_held = False
        self.cmd_held: set[int] = set()
        self.sent_frames = 0
        self.pending_sync: dict[str, float] = {}
        self.rtt_ms = 0.0
        # 会话元信息（审计 / 超时判定用）
        self.user = user or {}
        self.username = self.user.get("username", "")
        self.user_id = self.user.get("user_id")
        self.client_ip = client_ip
        self.started_at = time.time()
        self.last_seen = time.time()
        self.disconnect_reason = ""

    def touch(self) -> None:
        """任何来自客户端的指令都算一次活跃（含客户端空闲时自动发的 ping）。"""
        self.last_seen = time.time()

    @property
    def caps_on(self) -> bool:
        """被控机 CapsLock 当前是否开启（按主机维度共享）。

        两个来源：Agent 注入 CapsLock 后回报的权威值（`set_caps_state`），以及
        观看端按 CapsLock 时本地翻转。字母大小写的 Shift 决策要靠它，猜错就会
        打反大小写（见 keysym.shift_needed）。
        """
        return caps_state.get(self.server_id, False)

    def elapsed(self) -> float:
        return time.time() - self.started_at

    async def send_clipboard(self, text: str) -> None:
        """被控端剪贴板 -> 观看端（两段式：clipboard 建流 + blob/end 灌数据）。"""
        try:
            await self.ws.send_text(guac.clipboard_begin() + guac.clipboard_text(text))
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[rdp:{self.server_id}] send clipboard failed: {exc!r}")

    def offer(self, width: int, height: int, data: bytes) -> None:
        """Agent 来了一帧。队列满就丢最旧的一帧（实时性优先于完整性）。"""
        if self.queue.full():
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            self.queue.put_nowait((width, height, data))
        except asyncio.QueueFull:
            pass

    async def send_loop(self) -> None:
        await self.ws.send_text(guac.instr("", str(uuid.uuid4())))
        # 2) 有缓存帧先给一帧，避免白屏；没有就先给一个默认画布占位
        cached = last_frame.get(self.server_id)
        if cached:
            w, h = guac.jpeg_size(cached) or (0, 0)
            self.offer(w, h, cached)
        else:
            await self.ws.send_text(guac.size(0, 1024, 768) + guac.sync(_now()))

        while True:
            width, height, data = await self.queue.get()
            if width and height and (width, height) != (self.width, self.height):
                self.width, self.height = width, height
                await self.ws.send_text(guac.size(0, width, height))
            ts = _now()
            self.pending_sync[ts] = time.perf_counter()
            if len(self.pending_sync) > 200:  # 客户端不 echo 时别让字典无限涨
                self.pending_sync.clear()
            await self.ws.send_text(guac.jpeg_frame(data, ts))
            self.sent_frames += 1

    async def handle(self, args: list[str]) -> None:
        op = args[0]
        self.touch()

        if op == "combo" and len(args) >= 2:
            # 自定义指令：工具栏特殊组合键。客户端 parser 会解析但 Client 不认识，忽略。
            await self._on_combo(args[1])
            return

        if op == "":
            if len(args) >= 3 and args[1] == "ping":
                await self.ws.send_text(guac.instr("", "ping", args[2]))
            return

        if op == "sync":
            if len(args) >= 2:
                t0 = self.pending_sync.pop(args[1], None)
                if t0 is not None:
                    self.rtt_ms = round((time.perf_counter() - t0) * 1000, 1)
            return

        if op == "mouse" and len(args) >= 4:
            await self._on_mouse(int(args[1]), int(args[2]), int(args[3]))
            return

        if op == "key" and len(args) >= 3:
            await self._on_key(int(args[1]), args[2] not in ("0", "false", ""))
            return

        if op == "clipboard" and len(args) >= 3:
            await self._send_agent({"type": "clipboard", "text": args[2]})
            return


    async def _on_mouse(self, x: int, y: int, mask: int) -> None:
        if self.width and self.height:
            await self._send_agent({"type": "mousemove",
                                    "x": x / self.width, "y": y / self.height})
        for bit, name in _BUTTONS:
            if (mask & bit) and not (self.mouse_mask & bit):
                await self._send_agent({"type": "mousedown", "button": name})
            elif not (mask & bit) and (self.mouse_mask & bit):
                await self._send_agent({"type": "mouseup", "button": name})
        if (mask & M_WHEEL_UP) and not (self.mouse_mask & M_WHEEL_UP):
            await self._send_agent({"type": "wheel", "delta": WHEEL_DELTA})
        if (mask & M_WHEEL_DOWN) and not (self.mouse_mask & M_WHEEL_DOWN):
            await self._send_agent({"type": "wheel", "delta": -WHEEL_DELTA})
        self.mouse_mask = mask

    async def _on_key(self, ks: int, pressed: bool) -> None:
        # 修饰键状态：用来判断"字符需要 Shift 时是否已经按住了"
        if ks in _SHIFT_KEYSYMS:
            self.shift_held = pressed
        if ks in _CMD_KEYSYMS:
            if pressed:
                self.cmd_held.add(ks)
            else:
                self.cmd_held.discard(ks)
        # CapsLock 是"翻转"键：按下时先把本地镜像翻一下（keyup 不翻，与 Windows 一致）。
        # Agent 注入后会把真实状态回报过来（routes/rdp.py 的 keystate），
        # 以它为准，这样即使中途被人按过物理键盘也能自动纠正。
        if ks in _CAPS_KEYSYMS and pressed:
            caps_state[self.server_id] = not self.caps_on

        action = keysym.resolve(ks)
        if action is None:
            logger.debug(f"[rdp:{self.server_id}] unknown keysym 0x{ks:X}")
            return
        kind, value = action

        if kind == "vk":
            await self._send_agent({"type": "keyvk", "vk": value, "down": pressed})
            return

        if kind == "vkshift":
            vk, need_shift = value
            # 所以这里按需补一次 Shift，抬起时再放开。若用户已经按住 Shift 就不再动它，
            # 避免把人家真按着的 Shift 给弹起来。
            ch = keysym.keysym_to_char(ks)
            if ch is not None:
                need_shift = keysym.shift_needed(ch, need_shift, self.caps_on,
                                                 bool(self.cmd_held))
            borrow = need_shift and not self.shift_held

            # 新通道：把"字符 + VK"一起交给 Agent，由它在**注入那一刻**决定怎么打。
            # `cmd=True`（按住 Ctrl/Alt/Win）时必须走 VK，那是快捷键不是字符，
            # 用 Unicode 直注会失去按键语义（Ctrl+C 会变成真的输入一个 c）。
            # 其余情况 Agent 一律 Unicode 直注字符本身：这样大小写只取决于
            # 观看端给出的最终字符，不再依赖被控端的 CapsLock 状态、
            # 也不用"借 Shift"，从根上避免「怎么切都是小写」。
            # 老 Agent 不认 keychar，这里按能力位回退，不会把字全丢掉。
            if ch is not None and agent_char_inject.get(self.server_id):
                await self._send_agent({"type": "keychar", "text": ch, "vk": vk,
                                        "borrow": borrow, "cmd": bool(self.cmd_held),
                                        "down": pressed})
                return

            if borrow and pressed:
                await self._send_agent({"type": "keyvk", "vk": VK_SHIFT, "down": True})
            await self._send_agent({"type": "keyvk", "vk": vk, "down": pressed})
            if borrow and not pressed:
                await self._send_agent({"type": "keyvk", "vk": VK_SHIFT, "down": False})
            return

        if kind == "char":
            await self._send_agent({"type": "keytext", "text": value, "down": pressed})
        elif kind == "ctrlchar":
            await self._send_agent({"type": "keyctrl", "vk": value, "down": pressed})

    async def _on_combo(self, name: str) -> None:
        """工具栏特殊组合键。走白名单：名字不认识就不转发，避免被当成任意注入通道。"""
        if name not in COMBOS:
            logger.debug(f"[rdp:{self.server_id}] ignored unknown combo {name!r}")
            return
        await self._send_agent({"type": "combo", "name": name})

    async def _send_agent(self, payload: dict) -> None:
        ws = agents.get(self.server_id)
        if ws is None:
            return
        try:
            await ws.send_text(json.dumps(payload))
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[rdp:{self.server_id}] forward to agent failed: {exc!r}")


def _now() -> str:
    return str(int(time.time() * 1000))



agents: dict[int, object] = {}
viewers: dict[int, set[GuacViewer]] = {}
last_frame: dict[int, bytes] = {}
agent_settings: dict[int, dict] = {}
caps_state: dict[int, bool] = {}
# 老 Agent 没有这个能力位，服务端会退回 `keyvk`，保证升级过渡期打字不丢。
agent_char_inject: dict[int, bool] = {}
stats = {"frames": 0, "bytes": 0}


def set_caps_state(server_id: int, caps: bool, char_inject: bool | None = None,
                   ime: bool | None = None) -> None:
    """Agent 回报被控机 CapsLock 状态（注入后回报 / 会话开始回报）。

    以 Agent 的实测值为准：观看端自己按 CapsLock 时的本地翻转只是即时反馈，
    这条回报才是权威值，可以把中途的偏差纠正回来。

    同时可能带回两个可选字段：
      `char_inject` —— Agent 是否支持 keychar 指令；
      `ime`         —— 当前是否处于输入法非英文状态（仅用于日志排查）。
    """
    caps_state[server_id] = bool(caps)
    if char_inject is not None:
        agent_char_inject[server_id] = bool(char_inject)
    logger.debug(f"[rdp:{server_id}] caps lock = {bool(caps)}"
                 + (f", ime = {bool(ime)}" if ime is not None else ""))


async def query_keystate(server_id: int) -> None:
    """向 Agent 要一次当前修饰键状态（新观看端接入时刷新，agent 侧应答 keystate）。"""
    ws = agents.get(server_id)
    if ws is None:
        return
    try:
        await ws.send_text(json.dumps({"type": "keystate_query"}))
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[rdp:{server_id}] keystate_query failed: {exc!r}")


def session_active(server_id: int) -> bool:
    """是否有观看端在看这台主机（Agent 据此决定开/停流）。"""
    return bool(viewers.get(server_id))


def admission_check(server_id: int, user: dict) -> tuple[bool, str]:
    """观看端接入前的准入判定，返回 (是否放行, 拒绝原因)。

    三条限制：管理员角色、单主机并发上限、单用户并发会话数。
    """
    if REQUIRE_ADMIN and user.get("role") != "admin":
        return False, "无权限：远程桌面仅管理员可用"
    if len(viewers.get(server_id, ())) >= MAX_VIEWERS_PER_SERVER:
        return False, f"该主机观看端已达上限 {MAX_VIEWERS_PER_SERVER}"
    uid = user.get("user_id")
    if uid is not None:
        mine = sum(1 for v in _all_viewers() if v.user_id == uid)
        if mine >= MAX_SESSIONS_PER_USER:
            return False, f"单用户并发会话已达上限 {MAX_SESSIONS_PER_USER}"
    return True, ""


def _all_viewers() -> list[GuacViewer]:
    return [gv for group in viewers.values() for gv in group]


def viewer_connected(server_id: int, gv: GuacViewer) -> None:
    viewers.setdefault(server_id, set()).add(gv)


def viewer_disconnected(server_id: int, gv: GuacViewer) -> None:
    viewers.get(server_id, set()).discard(gv)
    if not viewers.get(server_id):
        viewers.pop(server_id, None)
        # 断开后清掉缓存帧，避免下一个观看端连上时看到几分钟前的旧画面
        last_frame.pop(server_id, None)


def session_info(server_id: int) -> dict:
    """会话概览：给前端状态条和排障用。"""
    group = list(viewers.get(server_id, ()))
    agent_up = server_id in agents
    return {
        "streaming": agent_up,
        "viewers": len(group),
        "max_viewers": MAX_VIEWERS_PER_SERVER,
        "rtt_ms": min([gv.rtt_ms for gv in group], default=0.0),
        "frames": sum(gv.sent_frames for gv in group),
        "sessions": [
            {
                "username": gv.username,
                "client_ip": gv.client_ip,
                "elapsed": round(gv.elapsed()),
                "frames": gv.sent_frames,
                "rtt_ms": gv.rtt_ms,
            }
            for gv in group
        ],
        "settings": agent_settings.get(server_id, dict(DEFAULT_SETTINGS)),
    }


async def broadcast_clipboard(server_id: int, text: str) -> None:
    """被控端剪贴板 -> 所有观看端。"""
    if not text:
        return
    for gv in list(viewers.get(server_id, ())):
        await gv.send_clipboard(text)


def apply_settings(server_id: int, settings: dict) -> dict:
    """合并采集参数并下发给 Agent（Agent 不在线时只记下来，连上时补发）。"""
    cur = dict(agent_settings.get(server_id, DEFAULT_SETTINGS))
    for key in ("fps", "quality", "max_width"):
        if key in settings and settings[key] is not None:
            try:
                cur[key] = int(settings[key])
            except (TypeError, ValueError):
                pass
    cur["fps"] = max(1, min(cur["fps"], 30))
    cur["quality"] = max(10, min(cur["quality"], 95))
    cur["max_width"] = max(640, min(cur["max_width"], 3840))
    agent_settings[server_id] = cur

    ws = agents.get(server_id)
    if ws is not None:
        try:
            asyncio.create_task(ws.send_text(json.dumps({"type": "settings", **cur})))
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[rdp:{server_id}] push settings failed: {exc!r}")
    return cur
