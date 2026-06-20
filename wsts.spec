# -*- mode: python ; coding: utf-8 -*-
# ── WSTS — Windows Security Threat Scanner — PyInstaller spec ────────────────
# Packages win_scanner_app.py (Flask local dashboard) into a single signed,
# windowed executable. Build:  pyinstaller wsts.spec --clean
#
# Security notes baked in:
#   • console=False  → no scary black terminal window
#   • version resource embeds publisher metadata for Authenticode + SmartScreen
#   • codesign_identity left None here; signing is done post-build by
#     build_wsts.ps1 with signtool so the cert/timestamp stay out of the repo.

import os

block_cipher = None

# wsts/ is the self-contained project root (this spec lives in it).
PROJECT_DIR = os.path.abspath(SPECPATH)  # noqa: F821 (SPECPATH injected by PyInstaller)

a = Analysis(
    [os.path.join(PROJECT_DIR, 'win_scanner_app.py')],
    pathex=[PROJECT_DIR],
    binaries=[],
    datas=[
        # Bundle the WSTS shield/icon if present (optional UI assets)
        (os.path.join(PROJECT_DIR, 'static', 'img', 'wsts_shield.png'), 'static/img'),
    ],
    hiddenimports=[
        # Flask/Jinja sometimes need these spelled out for the frozen build
        'jinja2',
        'werkzeug',
        'click',
        'itsdangerous',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Trim the binary — nothing here is imported by the scanner
        'tkinter',
        'PyQt5',
        'PySide2',
        'matplotlib',
        'numpy',
        'pandas',
    ],
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
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='WSTS',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # UPX disabled: compressed binaries are a top cause of false-positive AV
    # detections and SmartScreen warnings. An uncompressed, signed binary is
    # far less likely to be flagged.
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(PROJECT_DIR, 'static', 'img', 'wsts.ico'),
    version=os.path.join(PROJECT_DIR, 'version_wsts.txt'),
)
