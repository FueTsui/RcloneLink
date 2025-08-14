# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['RcloneLink.py'],
    pathex=[],
    binaries=[('rclone.exe', '.')],
    datas=[('winfsp-2.1.25156.msi', '.'), ('icon.png', '.')],
    hiddenimports=['win32api', 'winreg', 'PySide6.QtSvg'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='RcloneLink',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='file_version_info.txt',
    icon=['icon.ico'],
)
