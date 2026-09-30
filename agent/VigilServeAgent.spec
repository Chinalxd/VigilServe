# -*- mode: python ; coding: utf-8 -*-
import os
import sysconfig

from PyInstaller.utils.hooks import collect_all

# is used. The venv MUST be based on a Python that ships tkinter, otherwise
_SITE = sysconfig.get_paths()["purelib"]
_WINPTY = os.path.join(_SITE, "winpty")

# This MUST be validated explicitly. If the build venv lacks the package,
# PyInstaller only writes a single line into warn-<name>.txt and still
try:
    import cryptography  # noqa: F401
except ImportError:
    raise SystemExit(
        "ERROR: the build interpreter has no `cryptography` package.\n"
        "       The packaged Agent would crash at startup with\n"
        "       ModuleNotFoundError: No module named 'cryptography'.\n"
        "       Fix: <build-venv>\\Scripts\\python.exe -m pip install cryptography"
    )

_crypto_datas, _crypto_binaries, _crypto_hidden = collect_all("cryptography")

block_cipher = None

a = Analysis(
    ['agent.py'],
    pathex=[],
    binaries=[
        (os.path.join(_WINPTY, 'winpty.dll'), 'winpty'),
        (os.path.join(_WINPTY, 'conpty.dll'), 'winpty'),
        (os.path.join(_WINPTY, 'winpty-agent.exe'), 'winpty'),
        (os.path.join(_WINPTY, 'OpenConsole.exe'), 'winpty'),
    ] + _crypto_binaries,
    datas=[
        ('paths.py', '.'), ('collector_v2.py', '.'),
        ('connector.py', '.'), ('config.py', '.'), ('api_server.py', '.'),
        ('agent_headless.py', '.'),
        # 卸载上报（2026-09-28）：卸载前向服务端通报，好让主机列表立刻置离线。
        # 漏登记 打包后 `import uninstall_report` 失败，而它被 try/except 兜住，
        # 于是上报**静默失效**，只能等心跳超时才显示离线（且「是否清配置」的
        # 分支永远不会生效）。
        ('uninstall_report.py', '.'),
        ('logger.py', '.'), ('single_instance.py', '.'),
        # 主机信息 / 应用管理 / 启动项 / 事件日志采集（源码投放，勿忘登记）
        ('host_info.py', '.'),
        # PyInstaller cannot see them — they must be listed in hiddenimports
        # below or the packaged Agent silently loses remote desktop.
        ('remote_desktop.py', '.'),
        # TLS 工具（安全加固阶段 2）：用它加载随包内置的本地 CA 校验服务端证书。
        # 漏登记 打包后的 Agent 在服务端切 HTTPS 后报
        # "ModuleNotFoundError: No module named 'tls_util'"，且**静默**退回不校验。
        ('tls_util.py', '.'),
        # 设备身份（安全演进 S1）：node_id + RSA 密钥对 + CSR + 请求签名。
        # 漏登记 打包后的 Agent 静默退回遗留 HMAC token 认证（永远拿不到证书）。
        ('identity.py', '.'),
        ('meshagent.py', '.'),
        # Agent 自身完整性自检（开源加固 ⑥）。漏登记 打包后的 Agent 在
        # connector.heartbeat 里的 `import self_check` 抛 ModuleNotFoundError，
        # 而它被 try/except 兜住了，于是**静默**不再上报指纹、服务端永远登记
        # 不了基线，比直接崩更糟，因为没人看得出来。
        ('self_check.py', '.'),
        ('agent_icon.ico', '.'),
        ('tray_idle.ico', '.'), ('tray_running.ico', '.'),
        ('tray_error.ico', '.'), ('tray_connecting.ico', '.'),
        # 服务端本地 CA（安全加固阶段 2）。由 build_installer.py 在打包前从
        # backend/certs/ca.crt 复制过来；Agent 用它校验服务端 HTTPS 证书。
        ('ca/vigilserve-ca.crt', 'ca'),
    ] + _crypto_datas,
    hiddenimports=[
        'pystray._win32', 'tkinter', 'tkinter.ttk', 'tkinter.messagebox',
        'winpty', 'winpty.ptyprocess', 'winpty.enums', 'winpty._winpty',
        'psutil', 'PIL._tkinter_finder', 'psutil._psutil_windows',
        'paths', 'collector_v2', 'connector', 'config', 'api_server',
        'single_instance', 'meshagent', 'host_info', 'tls_util', 'identity',
        'self_check', 'uninstall_report',
        'remote_desktop', 'websockets', 'websockets.asyncio.client',
        'windows_capture', 'mss',
    ] + _crypto_hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='VigilServeAgent',
    icon='agent_icon.ico',
    uac_admin=False,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_info.txt',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='VigilServeAgent',
)
