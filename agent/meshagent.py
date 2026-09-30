"""MeshCentral MeshAgent companion for the VigilServe Agent.

The VigilServe Agent (monitoring) and the MeshCentral MeshAgent (remote
desktop) are two completely separate programs. Since 1.1.27 the installer
ships the MeshAgent binaries alongside the Agent so a single install gives
the host both capabilities.

Responsibilities of this module:

  * locate the bundled MeshAgent binaries (``meshagent/`` next to the Agent)
  * detect the MeshCentral **node id** of this machine so the backend can
    build a ``?node=<nodeid>`` deep link straight to this host's desktop
  * install / uninstall the MeshAgent Windows service (needs elevation)

Node-id discovery
-----------------
MeshAgent keeps its identity in the registry under::

    HKLM\\SOFTWARE\\Open Source\\<service name>\\NodeId

The sub-key name is the MeshAgent service name (``Mesh Agent`` for the
default ``-fullinstall``), which can be customised with
``--meshServiceName=``, so instead of guessing we enumerate every child of
``HKLM\\SOFTWARE\\Open Source`` and ``HKCU\\SOFTWARE\\Open Source`` and take
the first one that exposes a ``NodeId`` value. On Linux/macOS (or when the
agent was never installed) this simply returns ``""``.
"""
from __future__ import annotations

import os
import subprocess
import sys

SERVICE_EXE = "MeshService64-VigilServe.exe"
USERMODE_EXE = "MeshCmd64-VigilServe.exe"

_OPEN_SOURCE_HIVES = ("HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER")
_OPEN_SOURCE_ROOT = r"SOFTWARE\Open Source"




def _base_dir() -> str:
    """Directory the Agent runs from (the PyInstaller bundle dir when frozen)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def meshagent_dir() -> str:
    """Directory holding the bundled MeshAgent binaries."""
    return os.path.join(_base_dir(), "meshagent")


def service_exe() -> str:
    return os.path.join(meshagent_dir(), SERVICE_EXE)


def usermode_exe() -> str:
    return os.path.join(meshagent_dir(), USERMODE_EXE)


def bundled() -> bool:
    """True when the MeshAgent binaries were shipped with this install."""
    return os.path.isfile(service_exe())




def detect_node_id() -> str:
    """Return this machine's MeshCentral node id, or "" when unavailable.

    Never raises — a failure to read the registry just means "no MeshAgent",
    which the backend treats as "remote desktop not available for this host".
    """
    if os.name != "nt":
        return ""
    try:
        import winreg
    except Exception:
        return ""

    for hive_name in _OPEN_SOURCE_HIVES:
        hive = getattr(winreg, hive_name, None)
        if hive is None:
            continue
        try:
            with winreg.OpenKey(hive, _OPEN_SOURCE_ROOT) as root:
                index = 0
                while True:
                    try:
                        sub = winreg.EnumKey(root, index)
                    except OSError:
                        break
                    index += 1
                    node_id = _read_value(winreg, hive, f"{_OPEN_SOURCE_ROOT}\\{sub}", "NodeId")
                    if node_id:
                        return node_id
        except OSError:
            continue
    return ""


def _read_value(winreg, hive, key_path: str, name: str) -> str:
    try:
        with winreg.OpenKey(hive, key_path) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return str(value).strip()
    except OSError:
        return ""


def is_service_running() -> bool:
    """True when the MeshAgent Windows service is present and running."""
    if os.name != "nt":
        return False
    try:
        out = subprocess.run(
            ["sc", "query", "MeshAgent"],
            capture_output=True,
            text=True,
            timeout=10,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return "RUNNING" in (out.stdout or "").upper()
    except Exception:
        return False


def status() -> dict:
    """Small status dict used by logs / the config panel."""
    return {
        "bundled": bundled(),
        "node_id": detect_node_id(),
        "service_running": is_service_running(),
    }




def _is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def install(elevate: bool = True) -> tuple[bool, str]:
    """Install the MeshAgent Windows service (``-fullinstall``).

    Requires elevation. When running elevated the install is executed inline
    and its exit code is returned. Otherwise ShellExecute's ``runas`` verb is
    used, which pops UAC and returns immediately — the caller only learns that
    elevation was requested, not whether the user accepted.

    Returns (ok, message). Never raises.
    """
    exe = service_exe()
    if not os.path.isfile(exe):
        return False, f"未找到 MeshAgent 安装文件: {exe}"

    if os.name != "nt":
        return False, "MeshAgent 服务仅支持 Windows"

    if not _is_admin():
        if not elevate:
            return False, "需要管理员权限才能安装 MeshAgent 服务"
        try:
            import ctypes

            rc = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", exe, "-fullinstall", meshagent_dir(), 1
            )
            if rc <= 32:
                return False, f"请求管理员权限失败 (ShellExecute rc={rc})"
            return True, "已弹出 UAC 提权请求，请在弹窗中允许以完成安装"
        except Exception as e:
            return False, f"提权失败: {e}"

    try:
        proc = subprocess.run(
            [exe, "-fullinstall"],
            cwd=meshagent_dir(),
            capture_output=True,
            text=True,
            timeout=120,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as e:
        return False, f"安装失败: {e}"
    if proc.returncode == 0:
        return True, "MeshAgent 服务安装完成"
    return False, f"MeshAgent 安装返回 {proc.returncode}: {(proc.stderr or proc.stdout or '').strip()[:200]}"


def uninstall(elevate: bool = True) -> tuple[bool, str]:
    """Stop and remove the MeshAgent service (``-fulluninstall``)."""
    exe = service_exe()
    if not os.path.isfile(exe):
        return False, f"未找到 MeshAgent 安装文件: {exe}"
    if os.name != "nt":
        return False, "MeshAgent 服务仅支持 Windows"

    if not _is_admin():
        if not elevate:
            return False, "需要管理员权限才能卸载 MeshAgent 服务"
        try:
            import ctypes

            rc = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", exe, "-fulluninstall", meshagent_dir(), 1
            )
            if rc <= 32:
                return False, f"请求管理员权限失败 (ShellExecute rc={rc})"
            return True, "已弹出 UAC 提权请求，请在弹窗中允许以完成卸载"
        except Exception as e:
            return False, f"提权失败: {e}"

    try:
        proc = subprocess.run(
            [exe, "-fulluninstall"],
            cwd=meshagent_dir(),
            capture_output=True,
            text=True,
            timeout=120,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as e:
        return False, f"卸载失败: {e}"
    if proc.returncode == 0:
        return True, "MeshAgent 服务已卸载"
    return False, f"MeshAgent 卸载返回 {proc.returncode}: {(proc.stderr or proc.stdout or '').strip()[:200]}"


if __name__ == "__main__":
    import json

    print(json.dumps(status(), ensure_ascii=False, indent=2))
