#!/usr/bin/env bash
# Cytadel Exposure — Kali/Debian launcher & self-heal.
#
# Fixes the "Segmentation fault at startup" (crash inside app.exec) that shows up
# after a full `sudo apt update && apt full-upgrade`. Cause: the prebuilt release
# binary is built on ubuntu-22.04 and is ABI-mismatched against the freshly
# upgraded system Qt / GLib / Mesa stack it partially links to.
#
# Strategy: ignore the prebuilt binary. Run from source against the CURRENT
# system Qt (the PySide6 wheel matches your live system era), with the same Linux
# env guards main.py already sets, plus software rendering for VM GPU stacks.
#
# Usage:  bash run_kali.sh          (run from inside the repo)
set -euo pipefail
cd "$(dirname "$0")"

echo "== 1/4  System Qt runtime libraries =="
sudo apt update
sudo apt install -y \
  python3-venv python3-pip \
  libxcb-cursor0 libxcb-xinerama0 libxkbcommon-x11-0 \
  libegl1 libgl1 libglx-mesa0 \
  unrar || true   # unrar is optional (.rar support); ignore if unavailable

echo "== 2/4  Python virtualenv + dependencies =="
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

echo "== 3/4  Launch (Qt matched to current system) =="
# main.py already sets QT_IM_MODULE=none and GSETTINGS_BACKEND=memory on Linux.
# Force software rendering too: inside a VM the GPU/GLX path is the usual
# post-upgrade segfault. Harmless on bare metal (this is a form UI, no GPU need).
export QT_QPA_PLATFORM=xcb
export LIBGL_ALWAYS_SOFTWARE=1
export QT_OPENGL=software

if python main.py; then
  exit 0
fi

echo
echo "== 4/4  Still crashed — collecting diagnostics =="
echo "-- Qt platform-plugin trace (last 40 lines) --"
QT_DEBUG_PLUGINS=1 python main.py 2>&1 | tail -40 || true
echo
echo "Headless sanity check (no window; should NOT segfault):"
echo "  QT_QPA_PLATFORM=offscreen python main.py"
echo
echo "Paste the trace above back to me and I'll pin the exact failing library."
