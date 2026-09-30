# -*- mode: python ; coding: utf-8 -*-
import os

block_cipher = None

a = Analysis(
    ['tray_app.py'],
    pathex=[os.path.dirname(os.path.abspath(SPEC))],
    binaries=[],
    datas=[
        ('tray_icon.ico', '.'),
        ('vigilserve_logo.png', '.'),
        ('logger.py', '.'),
        ('docs', 'docs'),
    ],
    hiddenimports=[
        'pystray._win32',
        'PIL',
        'PIL.ImageTk',
        'PIL._imagingtk',
        'tkinter',
        'tkinter.ttk',
        'tkinter.messagebox',
        'psutil',
        'psutil._psutil_windows',
        'docx',
        'docx.oxml',
        'docx.oxml.ns',
        'docx.opc.constants',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='VigilServeTray',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='tray_icon.ico',
    uac_admin=True,
    version='version_info.txt',
)
