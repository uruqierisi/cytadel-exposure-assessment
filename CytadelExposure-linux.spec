# -*- mode: python ; coding: utf-8 -*-
# Linux build spec. Differs from the plain CLI build in one important way: it
# DROPS the bundled GLib stack so the system's (newer, ABI-compatible) GLib is
# used at runtime. Without this, a binary built on ubuntu-22.04 ships an old
# libglib, and when a newer distro (e.g. Kali) loads its own gio/gvfs/dconf
# modules into the process they fail with "undefined symbol: g_task_set_static_name"
# and the app segfaults at QApplication init.

import os

from PyInstaller.utils.hooks import collect_submodules

_DROP_PREFIXES = (
    "libglib-2.0",
    "libgio-2.0",
    "libgobject-2.0",
    "libgmodule-2.0",
    "libgthread-2.0",
)

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[("assets", "assets")],
    hiddenimports=collect_submodules("reportlab"),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

# Use the system GLib instead of the bundled one.
a.binaries = [
    b for b in a.binaries
    if not os.path.basename(b[0]).startswith(_DROP_PREFIXES)
]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="CytadelExposure",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,          # --windowed
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
