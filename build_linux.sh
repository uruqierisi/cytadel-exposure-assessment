#!/usr/bin/env bash
# Build CytadelExposure as a single Linux binary (run this on Kali / Debian / Ubuntu).
# The Windows .exe is built by build.bat; this produces the Linux equivalent.
set -euo pipefail

cd "$(dirname "$0")"

echo "=== Creating virtualenv ==="
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "=== Installing dependencies ==="
python -m pip install --upgrade pip
pip install -r requirements.txt

echo "=== Running tests ==="
python -m pytest -q

echo "=== Building single-file binary with PyInstaller ==="
# On Linux --add-data uses ':' as the separator (not ';' like Windows).
# --icon is a Windows/macOS concept and is omitted here.
pyinstaller --noconfirm --onefile --windowed \
  --add-data "assets:assets" \
  --name CytadelExposure \
  --collect-submodules reportlab \
  main.py

echo
echo "=== Build complete: dist/CytadelExposure ==="
echo "Run it with:  ./dist/CytadelExposure"
echo "If the GUI fails to start, install Qt's runtime libs:"
echo "  sudo apt install -y libxcb-cursor0 libegl1 libgl1 libxkbcommon-x11-0"
