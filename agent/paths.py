"""Shared path resolution for VigilServe Agent.

In frozen (PyInstaller) mode:
  - The EXE lives in Program Files (the install directory).
  - Logs are stored under the install directory in a ``logs`` sub-folder.
    The installer grants Users write access to this folder so the agent
    (running as the logged-in user) can write logs.
  - Config remains in %LOCALAPPDATA% so it is writable even before the
    installer-created log folder is present.

During development the script directory is used directly.
"""
import os
import shutil
import sys

if getattr(sys, 'frozen', False):
    INSTALL_DIR = os.path.dirname(sys.executable)
    CONFIG_DIR = os.path.join(
        os.environ.get('LOCALAPPDATA', os.path.expanduser('~')),
        'VigilServe', 'Config', 'Agent'
    )
    LOG_DIR = os.path.join(INSTALL_DIR, 'logs')
else:
    INSTALL_DIR = os.path.dirname(os.path.abspath(__file__))
    CONFIG_DIR = INSTALL_DIR
    LOG_DIR = os.path.join(INSTALL_DIR, 'logs')

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

CONFIG_PATH = os.path.join(CONFIG_DIR, "agent_config.json")
# 本机配置页口令（第二轮复查 R-7）：GET/POST /config 用它替代"只要是 loopback 就放行"。
# 别的账户读不到；同账户进程可读，但同账户本来就能做更多事，属于合理边界。
LOCAL_TOKEN_PATH = os.path.join(CONFIG_DIR, "local_token")
LOG_PATH = os.path.join(LOG_DIR, "agent.log")
ICON_PATH = os.path.join(INSTALL_DIR, "agent_icon.ico")

_INSTALL_CONFIG = os.path.join(INSTALL_DIR, "agent_config.json")
if not os.path.exists(CONFIG_PATH) and os.path.exists(_INSTALL_CONFIG):
    try:
        shutil.copy2(_INSTALL_CONFIG, CONFIG_PATH)
    except Exception:
        pass
