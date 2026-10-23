#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR/cbp_network_anomaly"

echo "========================================================"
echo "  Network Anomaly Detection System (NIDS) - Linux / Mac"
echo "========================================================"

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 is required but not installed."
    exit 1
fi

# Create venv if not present
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment in ./venv..."
    python3 -m venv venv
    source venv/bin/activate
    echo "[*] Installing dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

echo "[*] Starting Streamlit dashboard..."
streamlit run dashboard/app.py --server.port 8501
