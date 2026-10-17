#!/bin/sh
# ==============================================================================
# Script Name:   run.sh
# Description:   Universal launcher for OSPF TopoViz (Linux/macOS/WSL).
# Author:        Mai Tan Duc <ducmai.network@gmail.com>
# Created:       2026-10-10
# Version:       1.0.0
# License:       MIT
# ==============================================================================
# Usage:         ./run.sh [options]
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
VENV_PYTHON="$VENV_DIR/bin/python"

# 1. Initialize config/settings.yaml from example if missing
if [ ! -f "$ROOT_DIR/config/settings.yaml" ] && [ -f "$ROOT_DIR/config/settings.yaml.example" ]; then
    cp "$ROOT_DIR/config/settings.yaml.example" "$ROOT_DIR/config/settings.yaml"
    echo "Initialized config/settings.yaml from template."
fi

# 2. Check and bootstrap virtual environment if missing
if [ ! -f "$VENV_PYTHON" ]; then
    echo "Virtual environment not found in .venv. Initializing..."

    PYTHON_CMD=""
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_CMD="python3"
    elif command -v python >/dev/null 2>&1; then
        PYTHON_CMD="python"
    else
        echo "Error: Python 3 is not installed or not in PATH."
        exit 1
    fi

    "$PYTHON_CMD" -m venv "$VENV_DIR"

    if [ -f "$ROOT_DIR/requirements.lock" ]; then
        echo "Installing locked dependencies..."
        "$VENV_DIR/bin/pip" install --quiet -r "$ROOT_DIR/requirements.lock"
    elif [ -f "$ROOT_DIR/requirements.txt" ]; then
        echo "Installing dependencies from requirements.txt..."
        "$VENV_DIR/bin/pip" install --quiet -r "$ROOT_DIR/requirements.txt"
    fi
fi

# 3. Execute main.py with virtual environment python forwarding all arguments
exec "$VENV_PYTHON" "$ROOT_DIR/main.py" "$@"
