"""Agent configuration — persistent settings stored in JSON."""
import json
import os
import winreg

from paths import CONFIG_PATH

DEFAULTS = {
    "server_url": "",
    "server_host": "",      # server host only, e.g. 192.0.2.10
    "server_port": 8001,
    "server_scheme": "http",  # http | https —— 服务端启用 HTTPS 后由 Agent 自动切换
    "verify_tls": True,     # 是否用内置 CA 校验证书（只有排障才关）
    "ca_file": "",
    "server_id": 0,
    "token": "",
    # 2026-09-23 开源加固 ④：更新包验签密钥（注册/入户时随 token 一起下发）。
    # **故意与 token 分开存**：token 是 9998 的认证头、每次调用都在网络上跑，
    # 用它当签名密钥等于"抓一次包就能永久给本机签任意安装包"。
    "update_key": "",
    "interval_seconds": 60,
    "auto_start": True,
    "minimize_to_tray": True,
    "debug": False,
    "api_port": 9998,
    "web_proxy_port": 8009,
    "business_system": "",
}


def build_server_url(cfg: dict) -> str:
    """Return the full backend URL from scheme + server_host + server_port.

    Falls back to the legacy server_url field when server_host is empty.
    """
    host = (cfg.get("server_host") or "").strip()
    if not host:
        legacy = (cfg.get("server_url") or "").strip()
        return legacy

    host = host.replace("http://", "").replace("https://", "").rstrip("/")
    if not host:
        return ""

    scheme = str(cfg.get("server_scheme") or "http").strip().lower()
    if scheme not in ("http", "https"):
        scheme = "http"

    port = cfg.get("server_port", DEFAULTS["server_port"])
    try:
        port = int(port)
    except (ValueError, TypeError):
        port = DEFAULTS["server_port"]
    return f"{scheme}://{host}:{port}"


def load() -> dict:
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                cfg.update(loaded)
        except Exception:
            pass

    if not cfg.get("server_host") and cfg.get("server_url"):
        legacy = str(cfg.get("server_url") or "").strip()
        if legacy:
            # 保留 scheme：手填 https:// 时不能悄悄降级成 http
            _scheme = "https" if legacy.lower().startswith("https://") else "http"
            legacy = legacy.replace("http://", "").replace("https://", "").rstrip("/")
            if ":" in legacy:
                host, port_str = legacy.rsplit(":", 1)
                cfg["server_host"] = host
                try:
                    cfg["server_port"] = int(port_str)
                except (ValueError, TypeError):
                    cfg["server_port"] = DEFAULTS["server_port"]
            else:
                cfg["server_host"] = legacy
                cfg["server_port"] = DEFAULTS["server_port"]
            cfg["server_scheme"] = _scheme
            cfg["server_url"] = ""
            try:
                save(cfg)
            except Exception:
                pass

    return cfg


def save(cfg: dict) -> None:
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def get(key: str):
    return load().get(key, DEFAULTS.get(key))


def set(key: str, value) -> None:
    cfg = load()
    cfg[key] = value
    save(cfg)


def get_auto_start() -> bool:
    """Check if agent is set to auto-start via Windows registry."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run")
        val, _ = winreg.QueryValueEx(key, "VigilServeAgent")
        winreg.CloseKey(key)
        return bool(val)
    except Exception:
        return False


def set_auto_start(enabled: bool) -> None:
    """Enable/disable auto-start via Windows registry Run key."""
    try:
        import sys
        exe = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        if enabled:
            winreg.SetValueEx(key, "VigilServeAgent", 0, winreg.REG_SZ, f'"{exe}"')
        else:
            try:
                winreg.DeleteValue(key, "VigilServeAgent")
            except Exception:
                pass
        winreg.CloseKey(key)
    except Exception as e:
        print(f"Auto-start config failed: {e}")
