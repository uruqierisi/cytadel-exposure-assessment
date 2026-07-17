"""Resource path resolution that works from source and when PyInstaller-frozen.

When frozen with ``--onefile``, PyInstaller unpacks bundled data (added via
``--add-data "assets;assets"``) into a temporary dir exposed as
``sys._MEIPASS``. When running from source, resources live under the project
root (the parent of this package).
"""

from __future__ import annotations

import os
import sys

# Project root = parent of the ``cytadel`` package directory.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resource_base() -> str:
    """Base directory that bundled resources are resolved against."""
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return meipass
        return os.path.dirname(sys.executable)
    return _PROJECT_ROOT


def resource_path(*parts: str) -> str:
    """Absolute path to a bundled resource, e.g. ``resource_path('assets', 'app.ico')``."""
    return os.path.join(resource_base(), *parts)


def asset_path(name: str) -> str:
    """Absolute path to a file in the ``assets`` folder."""
    return resource_path("assets", name)
