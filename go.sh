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

echo "=== PRB Digital Signer ==="
echo "Ctrl+C to stop"
echo ""

python3 "$SCRIPT_DIR/prb_signer.py" "$@"

deactivate
