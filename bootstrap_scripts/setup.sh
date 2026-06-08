#!/usr/bin/env bash

# setup.sh – a bootstrap script to install dependencies and set up the environment

set -e

echo "[setup] Installing Python dependencies..."
if command -v pip >/dev/null 2>&1; then
    pip install --upgrade pip
    if [ -f requirements.txt ]; then
        pip install -r requirements.txt
    else
        echo "[setup] No requirements.txt found.  Skipping dependency installation."
    fi
else
    echo "[setup] pip is not available.  Please install Python 3 and pip before running this script."
    exit 1
fi

echo "[setup] Checking environment variables..."
# Set default environment variables if not already defined
: "${ATTACKLENS_ENVIRONMENT:=development}"
export ATTACKLENS_ENVIRONMENT
echo "[setup] ATTACKLENS_ENVIRONMENT set to ${ATTACKLENS_ENVIRONMENT}"

echo "[setup] Bootstrapping complete.  You can now run python app.py to start the application."