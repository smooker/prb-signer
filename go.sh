#!/bin/bash
# PRB Digital Signer — replacement for SIRMA Java applet
# Usage: ./go.sh [--pin PIN]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$HOME/venv/pdfsign"

# Activate venv
source "$VENV/bin/activate" || { echo "ERROR: venv not found at $VENV"; exit 1; }

# Install deps if missing
python3 -c "import websockets, signxml, PyKCS11, lxml" 2>/dev/null || {
    echo "Installing dependencies..."
    pip install -q websockets signxml PyKCS11 lxml
}

PKCS11_LIB="/usr/lib64/pkcs11/onepin-opensc-pkcs11.so"
echo "=== PRB Digital Signer ==="

# Check pcscd + smart card
pgrep -x pcscd >/dev/null 2>&1 || { echo "ERROR: pcscd not running. Start with: rc-service pcscd start"; deactivate; exit 1; }
python3 -c "import PyKCS11; p=PyKCS11.PyKCS11Lib(); p.load('$PKCS11_LIB'); slots=p.getSlotList(tokenPresent=True); assert slots, 'No smart card'; print(f'Smart card OK: {p.getTokenInfo(slots[0]).label.strip()}')" 2>/dev/null || { echo "ERROR: No smart card found. Insert card and try again."; deactivate; exit 1; }

# Check if port is free
PORT="${PRB_PORT:-38383}"
if ss -tlnp 2>/dev/null | grep -q ":${PORT} " || netstat -tlnp 2>/dev/null | grep -q ":${PORT} "; then
    PID=$(ss -tlnp 2>/dev/null | grep ":${PORT} " | grep -oP 'pid=\K\d+' || fuser ${PORT}/tcp 2>/dev/null)
    echo "ERROR: Port ${PORT} is in use (PID: ${PID})"
    echo "Kill it with: kill -9 ${PID}"
    deactivate; exit 1
fi

echo "Ctrl+C to stop"
echo ""

python3 "$SCRIPT_DIR/prb_signer.py" "$@"

deactivate
