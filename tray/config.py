"""Service definitions and user-configurable settings for VigilServe tray."""
import json
import os
import shutil
import socket
import subprocess
import sys



def _resolve_app_root() -> str:
    """Resolve the VigilServe application root from frozen or source layout."""
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        basename = os.path.basename(exe_dir).lower()
        candidates = [exe_dir]
        if basename == "outputs":
            candidates.insert(0, os.path.join(os.path.dirname(exe_dir), "vigilserve"))
        elif basename == "tray":
            candidates.insert(0, os.path.dirname(exe_dir))
        elif basename == "dist":
            tray_dir = os.path.dirname(exe_dir)
            project_dir = os.path.dirname(tray_dir)
            candidates.insert(0, project_dir)
            candidates.insert(1, tray_dir)
        for cand in candidates:
            current = cand
            for _ in range(4):
                if os.path.isdir(os.path.join(current, "backend")) and os.path.isdir(
                    os.path.join(current, "frontend")
                ):
                    return current
                parent = os.path.dirname(current)
                if parent == current:
                    break
                current = parent
        return exe_dir
    else:
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


APP_ROOT = _resolve_app_root()
WORKSPACE_ROOT = os.path.dirname(APP_ROOT)


# Therefore every candidate must (a) not be a Store alias and (b) actually run.

def _is_store_alias(path: str) -> bool:
    """True for the Microsoft Store app-execution alias stubs (0-byte files)."""
    if "windowsapps" in path.lower():
        return True
    try:
        return os.path.getsize(path) == 0
    except OSError:
        return True


def _probe_interpreter(path: str, timeout: int = 10) -> bool:
    """Run the candidate once to confirm it is a working Python 3."""
    try:
        proc = subprocess.run(
            [path, "-c", "import sys;print(sys.version_info[0])"],
            capture_output=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return False
    return proc.returncode == 0 and proc.stdout.strip().startswith(b"3")


def _resolve_python() -> str:
    """Return a *working* Python interpreter path, or "" when none is found.

    Search order mirrors ``installer/scripts/start.bat`` so the tray and the
    legacy batch entry point always agree on which interpreter to use:
      1. WorkBuddy managed venv (development workstation)
      2. ``python_runtime\\python.exe`` next to the installed app (portable
         runtime bundle, when present)
      3. The first usable ``python`` / ``python3`` / ``py`` on PATH
    """
    candidates: list[str] = []

    home = os.path.expanduser("~")
    candidates.append(os.path.join(
        home, ".workbuddy", "binaries", "python", "envs", "default", "Scripts", "python.exe"
    ))
    candidates.append(os.path.join(
        home, ".workbuddy", "binaries", "python", "versions", "3.13.12", "python.exe"
    ))

    for base in (APP_ROOT, os.path.join(APP_ROOT, "tray")):
        candidates.append(os.path.join(base, "python_runtime", "python.exe"))

    for exe in ("python.exe", "python3.exe", "py.exe"):
        found = shutil.which(exe)
        if found:
            candidates.append(found)

    seen: set[str] = set()
    deferred: list[str] = []  # Store aliases — usable only as a last resort
    for cand in candidates:
        if not cand:
            continue
        key = os.path.normcase(os.path.abspath(cand))
        if key in seen:
            continue
        seen.add(key)
        if not os.path.isfile(cand):
            continue
        if _is_store_alias(cand):
            deferred.append(cand)
            continue
        if _probe_interpreter(cand):
            return cand

    for cand in deferred:
        if _probe_interpreter(cand):
            return cand
    return ""


PYTHON_EXE = _resolve_python()

PYTHON_MISSING_HINT = (
    "未找到可用的 Python 解释器，后端服务无法启动。\n\n"
    "VigilServe 服务端需要 Python 3.10+，请任选其一：\n"
    "  1. 安装 Python 并勾选 “Add python.exe to PATH”；\n"
    "  2. 将便携版 Python 解压到安装目录下的 python_runtime\\ 文件夹；\n"
    "  3. 在“服务配置”页手动指定 python.exe 后重试。\n\n"
    "提示：Microsoft Store 提供的 WindowsApps\\python.exe 只是应用别名，无法运行。"
)


def _resolve_app_icon() -> str:
    """Return the path to the tray icon, preferring bundled frozen assets."""
    candidates = []
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(os.path.join(meipass, "tray_icon.ico"))
        candidates.append(os.path.join(os.path.dirname(sys.executable), "tray_icon.ico"))
    candidates.append(os.path.join(APP_ROOT, "tray", "tray_icon.ico"))
    for path in candidates:
        if os.path.exists(path):
            return path
    return candidates[-1]


APP_ICON = _resolve_app_icon()



_USER_CONFIG_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "VigilServe")
_USER_CONFIG_PATH = os.path.join(_USER_CONFIG_DIR, "tray-config.json")

_DEFAULT_PORTS = {
    "backend": 8001,
    "agent": 9998,
    "webproxy": 8009,
}


def load_user_config() -> dict:
    """Load user configuration from APPDATA, returning defaults if missing."""
    if not os.path.exists(_USER_CONFIG_PATH):
        return {"ports": dict(_DEFAULT_PORTS)}
    try:
        with open(_USER_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        ports = cfg.get("ports", {})
        merged = dict(_DEFAULT_PORTS)
        merged.update({k: int(v) for k, v in ports.items() if isinstance(v, (int, str)) and str(v).isdigit()})
        cfg["ports"] = merged
        return cfg
    except Exception:
        return {"ports": dict(_DEFAULT_PORTS)}


def save_user_config(cfg: dict) -> None:
    """Persist user configuration to APPDATA."""
    os.makedirs(_USER_CONFIG_DIR, exist_ok=True)
    with open(_USER_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


_USER_CONFIG = load_user_config()


def get_ports() -> dict:
    """Return the currently configured service ports."""
    return dict(_USER_CONFIG.get("ports", _DEFAULT_PORTS))


def set_ports(ports: dict) -> None:
    """Update and persist the service ports."""
    merged = dict(_DEFAULT_PORTS)
    merged.update({k: int(v) for k, v in ports.items() if isinstance(v, (int, str)) and str(v).isdigit()})
    _USER_CONFIG["ports"] = merged
    save_user_config(_USER_CONFIG)


# 为什么需要它：Agent 的「服务端地址」要填的是**这台服务器在网络上真实的地址**。
# 服务端本机自己用 127.0.0.1 没问题，但其它机器上的 Agent 拿 127.0.0.1 永远连不上
#，这是新部署现场最常见的一次踩坑。所以面板上直接列出本机网卡 IP，选定后
# * 「打开 Web 控制台」用它拼地址（本机永远可达，比 127.0.0.1 更贴近实际用法）；
# 多网卡（有线 + 无线 + 虚拟网卡）时由用户下拉选择，选择结果持久化到 APPDATA。

def list_local_ips(include_loopback: bool = False) -> list[str]:
    """本机所有**已启用**网卡的 IPv4 地址，去重并保持稳定顺序。

    排除项：
      * 回环 127.0.0.0/8（除非显式要）
      * APIPA 169.254.0.0/16 —— 拿不到 DHCP 时的自分配地址，填给 Agent 是错的
      * 已 down 的网卡（`psutil.net_if_stats().isup`）—— 否则面板上会混进一堆
        拔了网线的旧地址，选错了现场根本连不通
    """
    ips: list[str] = []
    try:
        import psutil
        stats = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            st = stats.get(name)
            if st is not None and not st.isup:
                continue
            for a in addrs:
                if a.family != socket.AF_INET:
                    continue
                ip = (a.address or "").strip()
                if not ip or ip == "0.0.0.0":
                    continue
                if not include_loopback and ip.startswith("127."):
                    continue
                if ip.startswith("169.254."):
                    continue
                if ip not in ips:
                    ips.append(ip)
    except Exception:  # noqa: BLE001 枚举网卡失败不能拖垮面板
        pass
    if include_loopback and "127.0.0.1" not in ips:
        ips.append("127.0.0.1")
    return ips


def get_server_ip() -> str:
    """面板上选定的服务端 IP；没选过返回空串（调用方自行回落 127.0.0.1）。"""
    return str(_USER_CONFIG.get("server_ip") or "").strip()


def set_server_ip(ip: str) -> None:
    """持久化选定的服务端 IP。"""
    _USER_CONFIG["server_ip"] = (ip or "").strip()
    save_user_config(_USER_CONFIG)


def build_services() -> list:
    """Build the service definitions using current user-configured ports.

    The local Agent service is controlled by the Agent tray program independently,
    so the server tray only manages the backend API service.
    """
    ports = get_ports()
    backend_dir = os.path.join(APP_ROOT, "backend")
    return [
        {
            "id": "backend",
            "name": "后端 API 服务",
            "note": "FastAPI + uvicorn，提供 REST API、WebSocket 终端代理并托管前端页面",
            "database": "SQLite (backend/monitor.db)",
            "port": ports["backend"],
            "cwd": backend_dir,
            "cmd": [PYTHON_EXE, "main.py"],
            "env": {
                "PYTHONIOENCODING": "utf-8",
                "PRODUCTION": "1",
                # 必须告诉主站「独立源代理在哪个端口」：web-config 只会在这个变量
                # 存在时才下发 proxy_base_url，前端才会把 WEB 管理的 iframe / 新窗口
                # 指到那个源上。缺了它前端会退回同源形态，独立源等于白配。
                "VIGILSERVE_WEBPROXY_PORT": str(ports["webproxy"]),
            },
            # has always done this, but the installer's [Run] entry only calls
            # start_tray.bat and the tray launches the backend itself, so on a
            # fresh machine nothing ever ran it — the service then died with
            # ModuleNotFoundError while the tray reported a successful start.
            # The installer now bundles a complete portable runtime, so this
            # normally only verifies and exits. `marker` is still written as a
            # record of a successful check (and removed on uninstall), but the
            # tray no longer trusts its presence to skip verification: a marker
            # from an earlier release must not be able to mask a broken runtime.
            "deps": {
                "requirements": os.path.join(backend_dir, "requirements.txt"),
                "marker": os.path.join(backend_dir, ".deps_installed"),
            },
        },
        # 网络设备「WEB管理」反向代理（2026-09-20 新增）。
        # 单独一个源是**安全需要**：跟主站同源时，设备页面只要一被入侵就能读
        # `parent.localStorage` 里的管理员令牌；沙箱能挡住嵌入式访问，挡不住
        # 「新窗口打开」那个顶层窗口。换源之后这条路才真正断掉。
        {
            "id": "webproxy",
            "name": "设备 WEB 管理代理",
            "note": "反向代理网络设备的自带管理界面，跑在独立端口以免与主站同源",
            "database": "无（复用主站的 SQLite 与证书）",
            "port": ports["webproxy"],
            "cwd": backend_dir,
            "cmd": [PYTHON_EXE, "web_proxy_server.py"],
            "env": {
                "PYTHONIOENCODING": "utf-8",
                "PRODUCTION": "1",
                "VIGILSERVE_WEBPROXY_PORT": str(ports["webproxy"]),
                "VIGILSERVE_WEBPROXY_PORT_HINT": str(ports["webproxy"]),
            },
            "deps": {
                "requirements": os.path.join(backend_dir, "requirements.txt"),
                "marker": os.path.join(backend_dir, ".deps_installed"),
            },
        },
    ]


SERVICES = build_services()
