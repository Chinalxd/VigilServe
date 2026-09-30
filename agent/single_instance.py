"""Single-instance helpers for VigilServe Agent on Windows.

Uses named mutexes to ensure only one agent tray process and one config
window run at a time. If a second instance is started, it brings the existing
window to the foreground and exits without creating duplicate tray icons.

 2026-09-28：Agent 的单实例判断**必须跨会话**，见下面 `_agent_mutex_handles`
   的注释。配置窗口仍然是会话内的 —— 窗口本来就属于会话。
"""
import logging
import sys
import ctypes

ERROR_ALREADY_EXISTS = 183
ERROR_ACCESS_DENIED = 5
SYNCHRONIZE = 0x00100000

_AGENT_MUTEX_BASE = "VigilServeAgent_SingleInstance_Mutex"
_CONFIG_MUTEX_BASE = "VigilServeAgent_Config_SingleInstance_Mutex"

# 为什么要同时占**两个**名字（2026-09-28）
# Windows 上不带前缀的互斥名落在**调用者所在会话**的命名空间里，只有加 `Global\`
# 前缀才能跨会话。而 Agent 恰恰会跨会话重复启动：托盘通常跑在用户的交互会话，
# 服务 / 计划任务跑在 session 0；配置面板在 RDP 的另一个会话里打开时，
# `is_agent_running()` 只看会话内那把 判定"后台没人" **再拉起一个采集进程**。
# 两个采集循环共用同一份 `agent_config.json`，各自把内存里的整份 cfg 覆盖写盘，
# 于是 A 刚登记回来的 server_id / token 会被 B 的旧快照抹掉，现象就是
# 「注册成功几秒后又变回未注册」。所以：**两把都要占**，任一把已被占 = 重复启动。
_agent_mutex_handles: list = []
_config_mutex_handles: list = []


def _mutex_names(base: str) -> tuple:
    """要占的名字：全局优先，会话内兜底。"""
    return ("Global\\" + base, base)


def _kernel32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    # restype 必须显式给：ctypes 对 windll 的默认返回类型是 c_int，会把 64 位
    # HANDLE 截断成 32 位，截断后 CloseHandle 会关错对象，而且**不报任何错**，
    # 只会在别处莫名其妙地失败。这里统一改成 c_void_p。
    k.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
    k.CreateMutexW.restype = ctypes.c_void_p
    k.OpenMutexW.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_wchar_p]
    k.OpenMutexW.restype = ctypes.c_void_p
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    k.CloseHandle.restype = ctypes.c_bool
    return k


def _create_mutex(name: str):
    """建 / 开一个命名互斥体，返回 `(handle, status)`。

    status 取值：
      · ``"ok"``     —— 本次创建成功，句柄归调用方持有
      · ``"exists"`` —— 已被别的进程持有 ⇒ 判定为重复启动
      · ``"failed"`` —— 建不起来（权限 / 资源等），这个名字用不了，换下一个
    """
    if sys.platform != "win32":
        return None, "failed"
    k = _kernel32()
    handle = k.CreateMutexW(None, False, name)
    if not handle:
        return None, "failed"
    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        k.CloseHandle(handle)
        return None, "exists"
    return handle, "ok"


def _close_all(handles: list) -> None:
    if sys.platform != "win32":
        handles.clear()
        return
    k = _kernel32()
    for h in handles:
        if h:
            k.CloseHandle(h)
    handles.clear()


def _acquire(handles: list, base: str, names: tuple) -> bool:
    """按 `names` 逐个占名字。任一已被占则整体失败（并释放已占的）。"""
    if handles:
        return True
    got = []
    for name in names:
        h, st = _create_mutex(name)
        if st == "exists":
            _close_all(got)
            return False
        if st == "ok":
            got.append(h)
    if not got:
        # 一把都没建起来，判不出有没有重复实例。宁可放行（功能不能因为判不出来
        # 就锁死），但必须留下痕迹，否则又会变成"偶发起了两个却查无实据"。
        try:
            logging.getLogger(__name__).warning(
                "单实例互斥体创建失败，本次无法检测重复启动")
        except Exception:  # noqa: BLE001
            pass
        return True
    handles.extend(got)
    return True


def acquire_agent_mutex() -> bool:
    """Try to acquire the agent tray-process mutex（全局 + 会话内两把）。"""
    return _acquire(_agent_mutex_handles, _AGENT_MUTEX_BASE,
                    _mutex_names(_AGENT_MUTEX_BASE))


def acquire_config_mutex() -> bool:
    """Try to acquire the config-window mutex.

    配置窗口**保持会话内**：窗口天然属于某个会话，跨会话互相阻止反而是错的。
    这里只顺带修掉 HANDLE 截断的问题（走同一个 `_create_mutex`）。
    """
    return _acquire(_config_mutex_handles, _CONFIG_MUTEX_BASE,
                    (_CONFIG_MUTEX_BASE,))


def is_agent_running() -> bool:
    """Return True if an agent tray process already exists.

    Deliberately uses OpenMutexW (open, not create) so this probe can never
    "use up" the mutex: calling it must not make a later acquire_agent_mutex()
    fail, which is exactly what would happen if we probed by acquiring.

    两个名字都查 —— 只查会话内那把会漏掉另一个会话里的 Agent，
    而那正是 `--config` 面板会误判"后台没人"、重复拉起采集进程的原因。
    """
    if sys.platform != "win32":
        return False
    k = _kernel32()
    for name in _mutex_names(_AGENT_MUTEX_BASE):
        handle = k.OpenMutexW(SYNCHRONIZE, False, name)
        if handle:
            k.CloseHandle(handle)
            return True
        if ctypes.get_last_error() == ERROR_ACCESS_DENIED:
            return True
    return False


def release_agent_mutex() -> None:
    _close_all(_agent_mutex_handles)


def release_config_mutex() -> None:
    _close_all(_config_mutex_handles)


def bring_config_to_front() -> bool:
    """Find an existing config window and bring it to the foreground."""
    if sys.platform != "win32":
        return False
    user32 = ctypes.windll.user32

    hwnd = user32.FindWindowW("VigilServeAgentConfig", None)
    if not hwnd:
        hwnd = user32.FindWindowW(None, "VigilServe Agent - 配置")
    if not hwnd:
        return False

    if user32.IsIconic(hwnd):
        user32.ShowWindow(hwnd, 9)
    user32.SetForegroundWindow(hwnd)
    return True


def is_config_window_open() -> bool:
    """Return True if a config window already exists."""
    if sys.platform != "win32":
        return False
    user32 = ctypes.windll.user32
    hwnd = user32.FindWindowW("VigilServeAgentConfig", None)
    if not hwnd:
        hwnd = user32.FindWindowW(None, "VigilServe Agent - 配置")
    return bool(hwnd)
