"""VigilServe 远程桌面 —— Agent 端（被控端，Windows）。

采集屏幕 -> JPEG 编码 -> WebSocket 推给服务端 hub；接收 JSON 控制指令用 Win32 注入。
不使用 Windows RDP，所有传输全部通过本 Agent。

用法（随 Agent 常驻，由 agent.py 在检测到 remote_desktop_active 后自动拉起；
也支持独立运行做测试）:
  python remote_desktop.py --server http://127.0.0.1:8000 --server-id 1 --token XXX [--duration 30]

采集后端优先级: WGC(windows-capture, 30fps+) -> GDI(mss, 约 8fps)
编码: PIL 快路径（frombuffer BGRX），不引入 opencv/numpy，控制安装包体积。
"""
from __future__ import annotations

import asyncio
import ctypes
import io
import json
import queue
import threading
import time

# 坐标一律用归一化值(0.0~1.0)，映射到主显示器全屏，避免前后端分辨率不一致时错位。

user32 = ctypes.WinDLL("user32", use_last_error=True)

SM_CXSCREEN = 0
SM_CYSCREEN = 1

MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_ABSOLUTE = 0x8000
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_MIDDLEDOWN = 0x0020
MOUSEEVENTF_MIDDLEUP = 0x0040
MOUSEEVENTF_WHEEL = 0x0800

KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_EXTENDEDKEY = 0x0001

_BUTTONS = {
    "left": (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
    "right": (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
    "middle": (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
}

VK_MAP = {
    "Enter": 0x0D, "NumpadEnter": 0x0D, "Escape": 0x1B, "Backspace": 0x08,
    "Tab": 0x09, "Space": 0x20, "Delete": 0x2E, "Insert": 0x2D,
    "Home": 0x24, "End": 0x23, "PageUp": 0x21, "PageDown": 0x22,
    "ArrowLeft": 0x25, "ArrowUp": 0x26, "ArrowRight": 0x27, "ArrowDown": 0x28,
    "CapsLock": 0x14, "PrintScreen": 0x2C, "ScrollLock": 0x91, "Pause": 0x13,
    "ShiftLeft": 0xA0, "ShiftRight": 0xA1, "ControlLeft": 0xA2, "ControlRight": 0xA3,
    "AltLeft": 0xA4, "AltRight": 0xA5, "MetaLeft": 0x5B, "MetaRight": 0x5C,
    "ContextMenu": 0x5D, "NumLock": 0x90,
    "F1": 0x70, "F2": 0x71, "F3": 0x72, "F4": 0x73, "F5": 0x74, "F6": 0x75,
    "F7": 0x76, "F8": 0x77, "F9": 0x78, "F10": 0x79, "F11": 0x7A, "F12": 0x7B,
}

_EXTENDED = {0x25, 0x26, 0x27, 0x28, 0x2D, 0x2E, 0x24, 0x23, 0x21, 0x22, 0x5B, 0x5C, 0x5D}

KEYEVENTF_UNICODE = 0x0004
INPUT_KEYBOARD = 1

_ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", ctypes.c_ushort),
        ("wScan", ctypes.c_ushort),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", _ULONG_PTR),
    ]


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.c_long),
        ("dy", ctypes.c_long),
        ("mouseData", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", _ULONG_PTR),
    ]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("ki", _KEYBDINPUT), ("mi", _MOUSEINPUT)]


class _INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("type", ctypes.c_ulong), ("u", _INPUTUNION)]


user32.MapVirtualKeyW.argtypes = [ctypes.c_uint, ctypes.c_uint]
user32.MapVirtualKeyW.restype = ctypes.c_uint
user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
user32.GetAsyncKeyState.restype = ctypes.c_short

VK_CAPITAL = 0x14
VK_SHIFT = 0xA0

_ASCII_LETTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

# 被控端开着中文输入法时，注入方式必须切换
# * 输入法非英文（中文/全角/中文标点）-> **必须发真实虚拟键**，让远端输入法
# 自己组字。Unicode 直注绕过了组字链路，结果就是「切到中文却只冒小写字母」。
# * 输入法关闭 / 英文模式 -> Unicode 直注字符本身，大小写只由观看端
# 所以每个字符注入前都要先问一次"现在是不是中文模式"。
WM_IME_CONTROL = 0x0283
IMC_GETOPENSTATUS = 0x0005
IMC_GETCONVERSIONMODE = 0x0002
IME_CMODE_NATIVE = 0x0001
IME_CMODE_FULLSHAPE = 0x0008
IME_CMODE_SYMBOL = 0x0400
_CJK_LANGS = {0x04, 0x11, 0x12}

_imm32 = None


def _imm() -> "ctypes.WinDLL":
    global _imm32
    if _imm32 is None:
        _imm32 = ctypes.WinDLL("imm32", use_last_error=True)
        _imm32.ImmGetDefaultIMEWnd.argtypes = [ctypes.c_void_p]
        _imm32.ImmGetDefaultIMEWnd.restype = ctypes.c_void_p
    return _imm32


def _foreground_is_cjk_layout() -> bool:
    """兜底判据：拿不到 IME 窗口时，看前台线程的键盘布局是不是中日韩。

    TSF / UWP 应用（Edge、新版记事本等）常常没有传统 IME 窗口，这种时候只能
    看布局。判成 CJK 就走 Unicode 直注——对英文输入无害（字符还是那个字符）。
    """
    try:
        user32.GetForegroundWindow.restype = ctypes.c_void_p
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return False
        user32.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p,
                                                    ctypes.POINTER(ctypes.c_ulong)]
        user32.GetWindowThreadProcessId.restype = ctypes.c_ulong
        tid = user32.GetWindowThreadProcessId(ctypes.c_void_p(hwnd), None)
        user32.GetKeyboardLayout.argtypes = [ctypes.c_ulong]
        user32.GetKeyboardLayout.restype = ctypes.c_void_p
        hkl = user32.GetKeyboardLayout(tid)
        return ((int(hkl or 0) & 0xFFFF) & 0x3FF) in _CJK_LANGS
    except Exception:  # noqa: BLE001
        return False


def ime_active() -> bool:
    """前台窗口是否处于"输入法非英文"状态（中文/全角/中文标点）。

    * 没装输入法 / 输入法关闭（英文模式） -> False：走 VK 注入，行为与以前一致；
    * 中文模式 / 全角 / 中文标点         -> True：必须走 VK 注入让远端输入法组字。
    """
    try:
        user32.GetForegroundWindow.restype = ctypes.c_void_p
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return False
        ime_wnd = _imm().ImmGetDefaultIMEWnd(ctypes.c_void_p(hwnd))
        if not ime_wnd:
            return _foreground_is_cjk_layout()
        user32.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                        ctypes.c_size_t, ctypes.c_ssize_t]
        user32.SendMessageW.restype = ctypes.c_ssize_t
        opened = user32.SendMessageW(ctypes.c_void_p(ime_wnd), WM_IME_CONTROL,
                                     IMC_GETOPENSTATUS, 0)
        if not opened:
            return False
        mode = user32.SendMessageW(ctypes.c_void_p(ime_wnd), WM_IME_CONTROL,
                                   IMC_GETCONVERSIONMODE, 0)
        return bool(int(mode or 0) & (IME_CMODE_NATIVE | IME_CMODE_FULLSHAPE |
                                      IME_CMODE_SYMBOL))
    except Exception:  # noqa: BLE001 探测失败就按"没输入法"处理，保持旧行为
        return False


# 缓存 150ms 足够跟上人工切换输入法的节奏，又能省掉绝大部分跨进程调用。
_IME_CACHE_TTL = 0.15
_ime_cache: dict = {"ts": 0.0, "value": False}


def ime_non_english() -> bool:
    """带缓存的 `ime_active()`：给每个注入的字符判断路由时用。"""
    now = time.monotonic()
    if now - _ime_cache["ts"] < _IME_CACHE_TTL:
        return bool(_ime_cache["value"])
    _ime_cache["ts"] = now
    _ime_cache["value"] = ime_active()
    return bool(_ime_cache["value"])


def get_caps_lock() -> bool:
    """被控机 CapsLock 当前是否开启（只读）。

    用 `GetAsyncKeyState` 而不是 `GetKeyState`：后者返回的是"调用线程消息队列里的
    状态"，后台线程拿到的基本是过期值。最低位 = 是否锁定（MSDN 对 CAPS/NUM/
    SCROLL LOCK 有效）。

    这个值要回报给服务端：字母的最终大小写 = CapsLock ⊕ Shift，服务端决定
    "要不要补按 Shift"时必须知道 CapsLock 状态，否则 CapsLock 开着时会打反。
    """
    return bool(user32.GetAsyncKeyState(VK_CAPITAL) & 0x0001)


def _send_keyboard_input(vk: int, scan: int, flags: int) -> None:
    """统一的键盘注入原语。

    一律走 `SendInput`：旧的 `keybd_event` 在走 TSF 的现代控件（WinUI3 等）上
    会出现"前面几个键能进、后面静默丢弃"的行为，不要改回 keybd_event。
    """
    inp = _INPUT()
    inp.type = INPUT_KEYBOARD
    inp.ki.wVk = vk
    inp.ki.wScan = scan
    inp.ki.dwFlags = flags
    if not user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(_INPUT)):
        raise ctypes.WinError(ctypes.get_last_error())


def _utf16_units(text: str) -> list[int]:
    """字符 -> UTF-16 编码单元（BMP 外字符拆成代理项对）。"""
    units: list[int] = []
    for ch in text:
        cp = ord(ch)
        if cp > 0xFFFF:
            cp -= 0x10000
            units.append(0xD800 + (cp >> 10))
            units.append(0xDC00 + (cp & 0x3FF))
        else:
            units.append(cp)
    return units


def set_dpi_aware() -> None:
    """让进程按物理像素坐标工作，否则高 DPI 下坐标会缩放错位。"""
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:  # noqa: BLE001
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:  # noqa: BLE001
            pass


class Injector:
    def __init__(self) -> None:
        set_dpi_aware()

    def move(self, nx: float, ny: float) -> None:
        nx = min(max(nx, 0.0), 1.0)
        ny = min(max(ny, 0.0), 1.0)
        user32.mouse_event(
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
            int(nx * 65535), int(ny * 65535), 0, 0,
        )

    def button(self, name: str, down: bool) -> None:
        pair = _BUTTONS.get(name)
        if pair is None:
            return
        user32.mouse_event(pair[0] if down else pair[1], 0, 0, 0, 0)

    def wheel(self, delta: int) -> None:
        user32.mouse_event(MOUSEEVENTF_WHEEL, 0, 0, int(delta), 0)

    def key_vk(self, vk: int, down: bool) -> None:
        flags = (0 if down else KEYEVENTF_KEYUP) | (KEYEVENTF_EXTENDEDKEY if vk in _EXTENDED else 0)
        _send_keyboard_input(vk, user32.MapVirtualKeyW(vk, 0), flags)

    def key_unicode(self, ch: str, down: bool) -> None:
        """SendInput + KEYEVENTF_UNICODE 直注字符（当前布局没有的字符/中文）。"""
        flags = KEYEVENTF_UNICODE | (0 if down else KEYEVENTF_KEYUP)
        for unit in _utf16_units(ch):
            _send_keyboard_input(0, unit, flags)

    def ctrl_combo(self, vk: int, down: bool) -> None:
        """控制字符（0xFF01-0xFF1A，如 Ctrl+C）成对注入，不留粘滞修饰键。"""
        if down:
            self.key_vk(0xA2, True)
            self.key_vk(vk, True)
        else:
            self.key_vk(vk, False)
            self.key_vk(0xA2, False)

    def key(self, code: str, down: bool) -> None:
        vk = VK_MAP.get(code)
        if vk is None:
            if len(code) == 1:
                vk = ord(code.upper())
            elif code.startswith("Key") and len(code) == 4:
                vk = ord(code[3])
            elif code.startswith("Digit") and len(code) == 6:
                vk = ord(code[5])
            else:
                return
        flags = (0 if down else KEYEVENTF_KEYUP) | (KEYEVENTF_EXTENDEDKEY if vk in _EXTENDED else 0)
        _send_keyboard_input(vk, user32.MapVirtualKeyW(vk, 0), flags)

    # ---- 工具栏特殊组合键（后端已按白名单过滤，这里只管注入） ----
    VK_CTRL, VK_ALT, VK_LWIN, VK_SHIFT = 0xA2, 0xA4, 0x5B, 0xA0
    VK_DELETE, VK_ESC, VK_TAB, VK_L = 0x2E, 0x1B, 0x09, 0x4C

    def combo(self, name: str) -> None:
        """一次组合键：修饰键先按下、主键按抬、修饰键最后抬起，不留粘滞。"""
        seq: list[tuple[int, bool]] = []
        if name == "cad":
            # 安全桌面序列（SAS）：普通进程注入在锁屏/UAC 界面上不会生效，
            # 但会话内（部分远程场景）有效，失败也无副作用，故照常发。
            seq = [(self.VK_CTRL, True), (self.VK_ALT, True), (self.VK_DELETE, True),
                   (self.VK_DELETE, False), (self.VK_ALT, False), (self.VK_CTRL, False)]
        elif name == "taskmgr":
            seq = [(self.VK_CTRL, True), (self.VK_SHIFT, True), (self.VK_ESC, True),
                   (self.VK_ESC, False), (self.VK_SHIFT, False), (self.VK_CTRL, False)]
        elif name == "altab":
            seq = [(self.VK_ALT, True), (self.VK_TAB, True),
                   (self.VK_TAB, False), (self.VK_ALT, False)]
        elif name == "winl":
            seq = [(self.VK_LWIN, True), (self.VK_L, True),
                   (self.VK_L, False), (self.VK_LWIN, False)]
        elif name == "win":
            seq = [(self.VK_LWIN, True), (self.VK_LWIN, False)]
        for vk, down in seq:
            self.key_vk(vk, down)
            time.sleep(KEY_GAP)


def _inject_char(injector: "Injector", msg: dict) -> None:
    """处理 hub 下发的 `keychar`（一个可打印字符的按下/抬起）。

    三条路由，判据全部在**注入那一刻**决定：

      1. `cmd=True`  —— 观看端正按住 Ctrl/Alt/Win，这是快捷键不是字符，
                       必须发真实虚拟键；Unicode 直注会丢掉按键语义
                       （Ctrl+C 会变成真的打出一个 c）。
      2. 远端输入法非英文（中文/全角/中文标点）—— 同样必须发真实按键，让
                       **远端输入法自己组字**。Unicode 直注绕过了输入法的
                       组字链路，结果就是「切到中文却只冒小写字母」。
      3. 其余        —— 直接 KEYEVENTF_UNICODE 注入字符本身。

    为什么第 3 条不再用「VK + 借 Shift」还原大小写：那条路要靠被控端
    CapsLock 的真实状态、以及 Shift 有没有真的被按住，二者任意一个不同步
    （观看端输入法吃掉 Shift、caps 状态没回报上来），结果就是「怎么切换都
    只能打小写」。字符本身由观看端按最终形态给出，直注它与被控端的
    CapsLock/Shift 无关。
    """
    ch = str(msg.get("text", ""))[:1]
    if not ch:
        return
    down = bool(msg.get("down", True))
    vk = int(msg.get("vk") or 0)

    if msg.get("cmd") or (vk and ime_non_english()):
        # 快捷键走 hub 给的结果（它对 Ctrl/Alt 场景已经判定过不要补 Shift）；
        # 其余（远端输入法在组字时敲的字母）用**本机的实时 CapsLock** 重算要不要补 Shift，
        # 不依赖 hub 的镜像状态，Windows 大小写是 CapsLock ⊕ Shift，
        # 镜像一旦过期就会「怎么切都是小写」。
        borrow = bool(msg.get("borrow", False))
        if ch in _ASCII_LETTERS and not msg.get("cmd"):
            borrow = ch.isupper() != get_caps_lock()
        if borrow and down:
            injector.key_vk(VK_SHIFT, True)
        injector.key_vk(vk, down)
        if borrow and not down:
            injector.key_vk(VK_SHIFT, False)
    else:
        injector.key_unicode(ch, down)



# 按键之间的最小间隔（秒）。down/up 零间隔连发时，被控端（尤其走 TSF 的
# 现代控件 / 带 IME 的输入框）会来不及处理而丢字。实测 20ms 足够。
KEY_GAP = 0.02


def encode_jpeg(raw: bytes, width: int, height: int, quality: int, max_width: int) -> bytes:
    """BGRA 原始帧 -> JPEG。PIL 快路径：frombuffer(rawmode="BGRX") 免逐像素转换。"""
    from PIL import Image

    img = Image.frombuffer("RGB", (width, height), raw, "raw", "BGRX", 0, 1)
    if max_width and width > max_width:
        scale = max_width / width
        img = img.resize((max_width, max(1, round(height * scale))), Image.BILINEAR)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=quality)
    return buf.getvalue()


class Source(threading.Thread):
    """采集线程基类：把编码后的 JPEG 丢进单槽队列，槽满则丢旧帧。"""

    daemon = True
    name = "source"
    key = "?"          # 稳定标识（用于"这台机器上某后端不可用"的记忆）

    def __init__(self, out: "queue.Queue[bytes]", quality: int, max_width: int, fps: int,
                 on_error=None, log=None) -> None:
        super().__init__()
        self.out = out
        self.quality = quality
        self.max_width = max_width
        self.fps = fps
        self.stop_flag = threading.Event()
        self.frames = 0
        self.bytes = 0
        self.error = ""
        self._on_error = on_error
        self._log = log

    def log(self, msg: str) -> None:
        """普通信息日志：只写日志，绝不影响采集状态（不能用 _report）。"""
        if not self._log:
            return
        try:
            self._log(msg)
        except Exception:  # noqa: BLE001
            pass

    def run(self) -> None:
        """线程入口统一兜异常。

        Agent 以 console=False 打包，stderr 不可见：采集线程一旦抛异常，
        表现就是「已连接 hub + 永久黑屏 + 日志一片空白」，没有任何线索。
        这里把异常收进 self.error 并回调上报。
        """
        try:
            self._run()
        except BaseException as exc:  # noqa: BLE001
            self.error = repr(exc)
            self._report(exc)

    def _run(self) -> None:
        raise NotImplementedError

    def _report(self, exc: BaseException) -> None:
        if self._on_error:
            try:
                self._on_error(self.name, exc)
            except Exception:  # noqa: BLE001
                pass

    def push(self, raw: bytes, width: int, height: int) -> None:
        try:
            data = encode_jpeg(raw, width, height, self.quality, self.max_width)
        except Exception as exc:  # noqa: BLE001
            # 只报第一次：编码失败会逐帧触发，刷屏反而淹掉别的线索
            if not self.error:
                self.error = "encode: " + repr(exc)
                self._report(exc)
            return
        self.frames += 1
        self.bytes += len(data)
        try:
            self.out.get_nowait()
        except queue.Empty:
            pass
        try:
            self.out.put_nowait(data)
        except queue.Full:
            pass


class WgcSource(Source):
    name = "WGC"
    key = "wgc"

    def _run(self) -> None:
        from windows_capture import InternalCaptureControl, WindowsCapture

        # 千万不要传 draw_border！
        # windows-capture 2.0.1 只要显式给了这个参数（哪怕 False），
        # 就会去调 GraphicsCaptureApi 的 SetIsBorderRequired；Win10 22H2（19045）
        # 不支持该 API，start() 立刻抛
        # "Toggling the capture border is not supported by the Graphics
        # Capture API on this platform."
        # 现象就是「已连上 hub + 永久黑屏 + 只有一行异常日志」。
        # 参数默认 None = 一个字节都不动，天然安全；描边只有抓单个窗口时才看得见，
        # 我们抓的是整块显示器，无任何影响。
        # cursor_capture 显式关掉：帧率只有 12~15fps，把被控机光标烤进帧里就等于
        # 给观看端叠了一个永远慢半拍的鬼影（2026-09-15 用户要求去除）。关掉后
        # 画面里只有观看端浏览器自己的指针，跟随是零延迟的。
        cap = WindowsCapture(cursor_capture=False, monitor_index=1)
        interval = 1.0 / self.fps if self.fps else 0.0
        last = [0.0]

        @cap.event
        def on_frame_arrived(frame, control: InternalCaptureControl):  # noqa: ANN001
            if self.stop_flag.is_set():
                control.stop()
                return
            now = time.perf_counter()
            if interval and (now - last[0]) < interval:
                return
            last[0] = now
            buf = frame.frame_buffer
            w, h = frame.width, frame.height
            try:
                raw = bytes(memoryview(buf))
            except TypeError:
                import numpy as np
                raw = np.asarray(buf).tobytes()
            self.push(raw, w, h)

        @cap.event
        def on_closed():
            pass

        cap.start()


class MssSource(Source):
    name = "GDI(mss)"
    key = "mss"

    def _run(self) -> None:
        import mss

        # 帧内一律不含光标：光标由观看端浏览器自己画（本地指针零延迟）。
        # 之前在 Python 侧用 GetCursorInfo + GetIconInfo 把被控机光标合成进
        # 帧缓冲，但帧率只有 12~15fps，光标在画面里永远比本地指针慢半拍，
        # 拖动鼠标时会看到一个「滞后跟随」的鬼影（2026-09-15 用户要求去除）。
        with mss.MSS() as sct:
            mon = sct.monitors[1]
            while not self.stop_flag.is_set():
                t0 = time.perf_counter()
                shot = sct.grab(mon)
                self.push(shot.bgra, shot.width, shot.height)
                if self.fps:
                    dt = 1.0 / self.fps - (time.perf_counter() - t0)
                    if dt > 0:
                        time.sleep(dt)


def make_source(out: "queue.Queue[bytes]", quality: int, max_width: int, fps: int,
                prefer: str = "auto", on_error=None, skip=(), log=None) -> Source:
    """skip: 已知在这台机器上不可用的后端 key 集合（跨会话记忆）。"""
    skip = set(skip or ())
    if prefer in ("auto", "wgc") and "wgc" not in skip:
        try:
            import windows_capture  # noqa: F401
            return WgcSource(out, quality, max_width, fps, on_error=on_error,
                             log=log)
        except Exception:
            if prefer == "wgc":
                raise
    return MssSource(out, quality, max_width, fps, on_error=on_error, log=log)



DEFAULT_FPS = 15
DEFAULT_QUALITY = 60
DEFAULT_MAX_WIDTH = 1600
# 请求停流后 watch 线程超过这个秒数还没退出，就认为它假死了（允许重开一条）
WATCH_STUCK_SECONDS = 15
# 开流后这么久还一帧都没有，就认为当前采集后端在这台机器上不出图，自动换备用后端。
# 没有这个看门狗就表现为永久黑屏且日志无任何异常。
FIRST_FRAME_TIMEOUT = 3.0


class RemoteDesktopController:
    """远程桌面会话生命周期管理。

    agent 主循环在每次 fetch_config 时把服务端下发的 remote_desktop_active
    喂给 set_active()；watch 线程负责实际的流开/停与断线重连。
    """

    def __init__(self, log=None) -> None:
        self.log = log or (lambda msg: print(f"[rdp] {msg}", flush=True))
        self._active = False
        self._running = False
        self._lock = threading.Lock()
        self._watch_thread: threading.Thread | None = None
        self.server_url = ""
        self.server_id = 0
        self.token = ""
        self.fps = DEFAULT_FPS
        self.quality = DEFAULT_QUALITY
        self.max_width = DEFAULT_MAX_WIDTH
        self.session_started_at = 0.0
        self.session_frames = 0
        self._restart = False  # 采集参数变更 -> 需要重建采集源（立即重连，不等 5 秒）
        self._deactivate_at = 0.0  # 最近一次请求停流的时间，用于识别「线程假死」
        # 已知在这台机器上不可用的采集后端（如 Win10 上的 WGC）。
        # 记下来后，后续每次重连都直接跳过，不再让用户每次白等一次黑屏。
        self._skip_backends: set[str] = set()

    def configure(self, server_url: str, server_id: int, token: str) -> None:
        self.server_url = (server_url or "").rstrip("/")
        self.server_id = int(server_id or 0)
        self.token = token or ""

    def set_active(self, flag: bool) -> None:
        with self._lock:
            changed = flag != self._active
            self._active = bool(flag)
        if changed:
            self.log(f"远程桌面会话 {'请求' if flag else '结束'}")
        if flag:
            # 兜底：watch 线程已死，或上次请求停流后迟迟没退出（假死）时，
            # 允许重新起一条，否则一次卡死会让远程桌面在这台机器上永久失效。
            dead = self._running and not (self._watch_thread and self._watch_thread.is_alive())
            stuck = (self._running and self._deactivate_at
                     and time.time() - self._deactivate_at > WATCH_STUCK_SECONDS)
            if dead or stuck:
                self.log("watch 线程未真正退出（已结束或假死），重置状态后重新开流")
                self._running = False
            self._deactivate_at = 0.0
            if not self._running:
                self._start()
        else:
            self._deactivate_at = time.time()
        # 停流由 watch 线程发现标志翻转后自行退出，避免在这里阻塞

    def stop(self) -> None:
        self.set_active(False)
        self._active = False

    def _apply_runtime_settings(self, msg: dict) -> bool:
        """观看端下发的采集参数（fps / quality / max_width），返回是否真的变了。

        采集源在启动后不再读这些值，所以只有真正变化时才置 _restart，
        由 _watch_loop 立即重建流（走正常重连路径，不 sleep）。
        注意：服务端每次 agent 连上都会补发一次当前 settings，
        若不看变化就重建，会变成「连上即拆流」的 5 秒死循环。
        """
        changed: dict[str, int] = {}
        for key in ("fps", "quality", "max_width"):
            raw = msg.get(key)
            if raw is None:
                continue
            try:
                value = int(raw)
            except (TypeError, ValueError):
                continue
            if getattr(self, key, None) != value:
                setattr(self, key, value)
                changed[key] = value
        if changed:
            self._restart = True
            self.log(f"采集参数更新 {changed}，重建推流")
        return bool(changed)

    def _start(self) -> None:
        if not (self.server_url and self.server_id and self.token):
            self.log("远程桌面缺少 server_url/server_id/token，无法开流")
            return
        self._running = True
        self._watch_thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._watch_thread.start()

    def _watch_loop(self) -> None:
        try:
            while self._active:
                self.session_started_at = time.time()
                try:
                    asyncio.run(self._stream_loop())
                except Exception as exc:  # noqa: BLE001
                    self.log(f"流异常退出: {exc!r}")
                if not self._active:
                    break
                if self._restart:
                    # 采集参数变更导致的重建：立刻重来，不走 5 秒退避
                    self._restart = False
                    continue
                self.log("5 秒后重连流…")
                time.sleep(5)
        finally:
            self._running = False
            self.log("远程桌面推流已停止")

    def _ws_url(self) -> str:
        # 安全加固阶段 3：token 不再拼进 URL（会落到访问日志），改由子协议携带
        base = self.server_url.replace("http://", "ws://").replace("https://", "wss://")
        return f"{base}/api/rdp/agent/{self.server_id}"

    def _ws_subprotocols(self) -> list:
        """子协议携带 token（服务端 1.1.30+ 认识 `vigitoken.<token>`）。"""
        return ["vigitoken." + (self.token or "")]

    def _on_source_error(self, name: str, exc: BaseException) -> None:
        self.log(f"采集源 {name} 异常: {exc!r}")

    async def _stream_loop(self) -> None:
        from websockets.asyncio.client import connect

        out: "queue.Queue[bytes]" = queue.Queue(maxsize=1)
        src = make_source(out, self.quality, self.max_width, self.fps,
                          on_error=self._on_source_error, skip=self._skip_backends,
                          log=self.log)
        injector = Injector()

        # wss 必须显式带上内置 CA：server_url 切 https 后这里会变成 wss://，
        # 而 websockets 默认用系统信任库校验，自签证书直接
        # `SSLCertVerificationError: CERTIFICATE_VERIFY_FAILED`，表现为
        # 「页签打开、点连接、FPS 永远 0」（连不上 hub，日志里也只有这么一行）。
        ws_kwargs: dict = {}
        if self._ws_url().startswith("wss://"):
            try:
                import tls_util
                ws_kwargs["ssl"] = tls_util.context_from_disk()
            except Exception as e:  # noqa: BLE001
                self.log(f"构造 wss 证书上下文失败，将退回系统信任库: {e!r}")

        async with connect(self._ws_url(), max_size=None, ping_interval=20,
                           ping_timeout=20, subprotocols=self._ws_subprotocols(),
                           **ws_kwargs) as ws:
            self.log(f"已连接服务端 hub，采集后端启动中…（{src.name}，帧内不含光标）")
            src.start()
            stop = asyncio.Event()

            # 会话开始先报一次 CapsLock：服务端靠它决定字母要不要补 Shift
            # （见 backend/services/rdp/keysym.shift_needed），猜错会大小写打反。
            # `char:1` 告诉服务端"我支持 keychar 指令"，老 Agent 没有这个字段，
            # 服务端会自动退回老的 keyvk 通道，不会出现"打字全丢"。
            try:
                await ws.send(json.dumps({"type": "keystate", "caps": get_caps_lock(),
                                          "ime": ime_active(), "char": 1}))
            except Exception:  # noqa: BLE001
                pass

            async def first_frame_watchdog():
                """首帧看门狗：主后端不出帧就换备用后端。

                两种失败都要覆盖，少一种就是「永久黑屏但日志没线索」：
                  1) 启动就抛异常（如 Win10 上 WGC 的 draw_border 不支持）；
                  2) 不抛异常但永远不回调 on_frame_arrived。
                兜底后再记进 _skip_backends，下次重连直接选能用的那个。

                结尾必须 await stop.wait()，否则这个协程一返回就会被
                asyncio.wait(FIRST_COMPLETED) 当成「流结束」而收掉整条流。
                """
                nonlocal src
                for _ in range(2):
                    waited = 0.0
                    while waited < FIRST_FRAME_TIMEOUT:
                        if src.frames:
                            await stop.wait()
                            return
                        if src.error:
                            break
                        await asyncio.sleep(0.2)
                        waited += 0.2
                    if src.frames:
                        await stop.wait()
                        return
                    alt = "mss" if isinstance(src, WgcSource) else "wgc"
                    why = f"启动失败（{src.error}）" if src.error else f"{FIRST_FRAME_TIMEOUT}s 内无帧"
                    self.log(f"采集后端 {src.name} {why}，自动降级到 {alt}")
                    self._skip_backends.add(src.key)
                    src.stop_flag.set()
                    src.join(timeout=3)
                    try:
                        out.get_nowait()
                    except queue.Empty:
                        pass
                    try:
                        src = make_source(out, self.quality, self.max_width, self.fps,
                                          prefer=alt, on_error=self._on_source_error,
                                          skip=self._skip_backends, log=self.log)
                    except Exception as exc:  # noqa: BLE001
                        self.log(f"降级到 {alt} 失败: {exc!r}")
                        await stop.wait()
                        return
                    src.start()
                    self.log(f"已切换到采集后端 {src.name}"
                             f"（本机可用后端: {src.key}）")
                await stop.wait()

            async def watch():
                """观看端全部断开（标志翻转）后 2 秒内停流。"""
                while self._active and not src.stop_flag.is_set():
                    await asyncio.sleep(2)
                stop.set()

            async def control_loop():
                async for message in ws:
                    if isinstance(message, bytes):
                        continue
                    try:
                        msg = json.loads(message)
                    except Exception:  # noqa: BLE001
                        continue
                    kind = msg.get("type")
                    is_key = kind in ("key", "keyvk", "keytext", "keyctrl", "keychar", "combo")
                    caps_report = False
                    try:
                        if kind == "mousemove":
                            injector.move(float(msg["x"]), float(msg["y"]))
                        elif kind == "mousedown":
                            injector.button(msg.get("button", "left"), True)
                        elif kind == "mouseup":
                            injector.button(msg.get("button", "left"), False)
                        elif kind == "wheel":
                            injector.wheel(int(msg.get("delta", 0)))
                        elif kind == "key":
                            injector.key(str(msg.get("code", "")), bool(msg.get("down", True)))
                        elif kind == "keyvk":
                            vk = int(msg["vk"])
                            down = bool(msg.get("down", True))
                            injector.key_vk(vk, down)
                            caps_report = (vk == VK_CAPITAL and down)
                        elif kind == "keychar":
                            _inject_char(injector, msg)
                        elif kind == "keytext":
                            injector.key_unicode(str(msg.get("text", "")), bool(msg.get("down", True)))
                        elif kind == "keyctrl":
                            injector.ctrl_combo(int(msg["vk"]), bool(msg.get("down", True)))
                        elif kind == "combo":
                            injector.combo(str(msg.get("name", "")))
                        elif kind == "clipboard":
                            # 写入失败必须留痕：早期版本因为 64 位句柄截断而静默失败，
                            # 表现为「粘贴没反应」，日志里却什么都没有。
                            if not _set_clipboard_text(str(msg.get("text", ""))):
                                self.log("剪贴板写入失败（OpenClipboard 被占用或分配内存失败）")
                        elif kind == "keystate_query":
                            await ws.send(json.dumps({"type": "keystate",
                                                      "caps": get_caps_lock(),
                                                      "ime": ime_active(), "char": 1}))
                        elif kind == "settings":
                            # 只有参数真的变了才收流重建；否则（服务端例行的
                            # settings 补发）保持当前流不动。
                            if self._apply_runtime_settings(msg):
                                stop.set()
                    except Exception as exc:  # noqa: BLE001
                        self.log(f"inject error {kind}: {exc}")
                    if is_key:
                        await asyncio.sleep(KEY_GAP)
                    if caps_report:
                        # 必须等 KEY_GAP 之后再读：SendInput 刚塞进去的键，异步键状态
                        # 还没更新，立刻读会拿到翻转前的旧值。
                        try:
                            await ws.send(json.dumps({"type": "keystate",
                                                      "caps": get_caps_lock(),
                                                      "ime": ime_active(), "char": 1}))
                        except Exception:  # noqa: BLE001
                            pass

            async def send_loop():
                self.session_frames = 0
                last_log = time.time()
                last_count = 0
                while not stop.is_set():
                    # 必须带 timeout：无超时的 queue.get() 会把线程池里的 worker 永久
                    # 卡住，cancel 任务也救不回来，asyncio.run() 收尾时
                    # shutdown_default_executor() 会无限等待 -> watch 线程假死。
                    try:
                        frame = await asyncio.to_thread(out.get, True, 0.5)
                    except queue.Empty:
                        continue
                    if frame is None:
                        break
                    await ws.send(frame)
                    self.session_frames += 1
                    # 每 10 秒报一次推流速率：出现「画面卡死」时，这一行能直接区分
                    # 是采集端不出帧、还是传输/浏览器端的问题（日志里有没有这行）。
                    now = time.time()
                    if now - last_log >= 10:
                        self.log(
                            f"推流 {self.session_frames - last_count} 帧/10s"
                            f"（累计 {self.session_frames}，采集 {src.frames}，"
                            f"队列积压 {out.qsize()}）"
                        )
                        last_log, last_count = now, self.session_frames

            async def clipboard_loop():
                """被控端剪贴板 -> 观看端（轮询，只在变化时推）。"""
                last = ""
                while not stop.is_set():
                    await asyncio.sleep(1.5)
                    try:
                        text = await asyncio.to_thread(_get_clipboard_text)
                    except Exception:  # noqa: BLE001
                        continue
                    if not text or text == last:
                        continue
                    last = text
                    try:
                        await ws.send(json.dumps({"type": "clipboard_push", "text": text}))
                    except Exception:  # noqa: BLE001
                        # 这里不能 return，否则一条剪贴板就会把正常会话打断。
                        continue

            tasks = [
                asyncio.create_task(watch(), name="watch"),
                asyncio.create_task(control_loop(), name="control"),
                asyncio.create_task(send_loop(), name="send"),
                asyncio.create_task(clipboard_loop(), name="clipboard"),
                asyncio.create_task(first_frame_watchdog(), name="firstframe"),
            ]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            # 任何一路协程结束都会收掉整条流，所以必须说清是谁先退的，
            # 否则现象只有「反复重连」而看不出原因。
            for t in done:
                exc = None if t.cancelled() else t.exception()
                self.log(f"流结束：{t.get_name()} 退出"
                         + (f"（异常 {exc!r}）" if exc else "（正常结束）"))
            stop.set()
            for t in pending:
                t.cancel()
            # 否则 asyncio.run() 会在关闭线程池时被拖住（队列满则先腾一格）。
            try:
                out.put_nowait(None)
            except queue.Full:
                try:
                    out.get_nowait()
                except queue.Empty:
                    pass
                try:
                    out.put_nowait(None)
                except queue.Full:
                    pass
            src.stop_flag.set()
            src.join(timeout=3)
            if src.is_alive():
                self.log(f"采集线程 {src.name} 未能在 3 秒内退出，已放弃等待（后台残留）")


# 64 位 Python 下 ctypes 的**默认 restype 是 c_int**，HGLOBAL / 数据指针
# 会被截断成 32 位。实测（2026-09-17 在本机）
# 后果是**静默失败**：写入时 memmove(NULL) 抛异常被 except 吞掉（远端剪贴板
# 根本没变），读取时 GlobalLock 返回空 -> 永远返回 ""（"远端复制 -> 本机粘贴"
# 因此从来没数据）。所以下面这些签名**必须显式声明**，别再省这几行。
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
_kernel32.GlobalAlloc.restype = ctypes.c_void_p
_kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
_kernel32.GlobalLock.restype = ctypes.c_void_p
_kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
_kernel32.GlobalUnlock.restype = ctypes.c_int
_kernel32.GlobalSize.argtypes = [ctypes.c_void_p]
_kernel32.GlobalSize.restype = ctypes.c_size_t
_kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
_kernel32.GlobalFree.restype = ctypes.c_void_p

user32.OpenClipboard.argtypes = [ctypes.c_void_p]
user32.OpenClipboard.restype = ctypes.c_int
user32.CloseClipboard.argtypes = []
user32.CloseClipboard.restype = ctypes.c_int
user32.EmptyClipboard.argtypes = []
user32.EmptyClipboard.restype = ctypes.c_int
user32.GetClipboardData.argtypes = [ctypes.c_uint]
user32.GetClipboardData.restype = ctypes.c_void_p
user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
user32.SetClipboardData.restype = ctypes.c_void_p

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002
CLIPBOARD_PUSH_LIMIT = 20000


def _set_clipboard_text(text: str) -> bool:
    """观看端 -> 被控端剪贴板。返回是否真的写进去了（失败要能被日志看见）。"""
    data = text.encode("utf-16-le") + b"\x00\x00"
    if not user32.OpenClipboard(None):
        return False
    h = None
    try:
        user32.EmptyClipboard()
        h = _kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data) + 2)
        if not h:
            return False
        p = _kernel32.GlobalLock(ctypes.c_void_p(h))
        if not p:
            return False
        try:
            ctypes.memmove(p, data, len(data))
        finally:
            _kernel32.GlobalUnlock(ctypes.c_void_p(h))
        if not user32.SetClipboardData(CF_UNICODETEXT, ctypes.c_void_p(h)):
            return False
        # SetClipboardData 成功后内存归系统所有，**不能**再 GlobalFree
        h = None
        return True
    except Exception:  # noqa: BLE001
        return False
    finally:
        user32.CloseClipboard()
        if h:
            try:
                _kernel32.GlobalFree(ctypes.c_void_p(h))
            except Exception:  # noqa: BLE001
                pass


def _get_clipboard_text(limit: int = CLIPBOARD_PUSH_LIMIT) -> str:
    """读取被控端剪贴板文本（只取文本，失败返回空串）。

    刚写完立刻读会偶发拿到空句柄（last_error=1418，实测与系统剪贴板历史服务抢
    占有有关），所以给一次 50ms 重试——否则"远端刚复制、1.5s 轮询恰好撞上"就会
    漏掉这次同步。
    """
    for attempt in (0, 1):
        if not user32.OpenClipboard(None):
            return ""
        try:
            handle = user32.GetClipboardData(CF_UNICODETEXT)
            if not handle and attempt == 0:
                time.sleep(0.05)
                continue
            return _read_clipboard_handle(handle, limit)
        except Exception:  # noqa: BLE001
            return ""
        finally:
            user32.CloseClipboard()
    return ""


def _read_clipboard_handle(handle: int | None, limit: int) -> str:
    """把已拿到的 CF_UNICODETEXT 句柄解成字符串（调用方负责开关剪贴板）。"""
    try:
        if not handle:
            return ""
        ptr = _kernel32.GlobalLock(ctypes.c_void_p(handle))
        if not ptr:
            return ""
        try:
            raw = ctypes.string_at(ptr, _kernel32.GlobalSize(ctypes.c_void_p(handle)))
        finally:
            _kernel32.GlobalUnlock(ctypes.c_void_p(handle))
        return raw.decode("utf-16-le", errors="ignore").split("\x00", 1)[0][:limit]
    except Exception:  # noqa: BLE001
        return ""



def main() -> None:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True, help="如 http://127.0.0.1:8000")
    ap.add_argument("--server-id", type=int, required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--fps", type=int, default=DEFAULT_FPS)
    ap.add_argument("--quality", type=int, default=DEFAULT_QUALITY)
    ap.add_argument("--max-width", type=int, default=DEFAULT_MAX_WIDTH)
    ap.add_argument("--duration", type=float, default=0, help="秒；0=一直运行")
    args = ap.parse_args()

    ctl = RemoteDesktopController()
    ctl.configure(args.server, args.server_id, args.token)
    ctl.fps, ctl.quality, ctl.max_width = args.fps, args.quality, args.max_width
    ctl.set_active(True)

    try:
        while ctl._running:
            time.sleep(1)
            if args.duration and (time.time() - ctl.session_started_at) > args.duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        ctl.stop()
        print(f"[rdp] 总计 {ctl.session_frames} 帧", flush=True)


if __name__ == "__main__":
    main()
