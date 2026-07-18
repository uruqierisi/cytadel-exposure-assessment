"""Entry point for the Cytadel Exposure Assessment GUI."""

import faulthandler
import os
import sys

# Dump a native traceback to stderr if the process ever hard-crashes (segfault),
# so a crash is diagnosable from a terminal instead of closing silently.
faulthandler.enable()

# On some Linux setups (notably Kali/Debian with ibus/fcitx), a mismatched Qt
# input-method plugin bundled by PyInstaller segfaults on the first keystroke
# into a text field — the app "just closes" the moment you type. Disable the Qt
# IME unless the user explicitly set one; plain ASCII keyboard input (domains,
# emails) works fine without it. Must be set before QApplication is created.
if sys.platform.startswith("linux"):
    os.environ.setdefault("QT_IM_MODULE", "none")
    # Use an in-process GSettings backend instead of dconf, whose system module
    # can be ABI-mismatched against the runtime GLib on some distros (Kali) and
    # spam load errors. The report/UI don't rely on system GTK settings.
    os.environ.setdefault("GSETTINGS_BACKEND", "memory")
    # Force software rendering. In a VM (or after a Mesa/libGL upgrade) Qt's
    # GLX/EGL path can segfault the moment the first window is shown. This is a
    # plain form UI with no need for GPU acceleration. setdefault() preserves any
    # value the user set explicitly (e.g. to re-enable hardware GL).
    os.environ.setdefault("LIBGL_ALWAYS_SOFTWARE", "1")
    os.environ.setdefault("QT_OPENGL", "software")


def main() -> int:
    from cytadel.ui import run_app

    return run_app()


if __name__ == "__main__":
    sys.exit(main())
