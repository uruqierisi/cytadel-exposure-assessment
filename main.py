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
if sys.platform.startswith("linux") and not os.environ.get("QT_IM_MODULE"):
    os.environ["QT_IM_MODULE"] = "none"


def main() -> int:
    from cytadel.ui import run_app

    return run_app()


if __name__ == "__main__":
    sys.exit(main())
