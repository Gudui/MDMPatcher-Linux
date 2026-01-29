#!/bin/bash
# Setup virtual environment for iOS backup decryption tools

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "[+] Creating Python virtual environment in $SCRIPT_DIR/.venv"
python3 -m venv .venv

echo "[+] Activating virtual environment"
source .venv/bin/activate

echo "[+] Installing dependencies"
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "============================================"
echo "Virtual environment ready!"
echo ""
echo "To activate, run:"
echo "  source $SCRIPT_DIR/.venv/bin/activate"
echo ""
echo "Then use decrypt_backup.py:"
echo "  python $SCRIPT_DIR/decrypt_backup.py --help"
echo "============================================"
