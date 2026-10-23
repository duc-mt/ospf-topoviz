#!/bin/bash
# ==============================================================================
# Script Name:   run_ospf_cron.sh
# Description:   Automated cronjob runner with non-blocking flock concurrency lock
#                and environment file (.env) isolation for hands-free daemonization.
# Author:        Antigravity
# Created:       2026-10-23
# Version:       1.0.0
# License:       MIT
# ==============================================================================
# Usage:         ./scripts/run_ospf_cron.sh [options]
# Crontab:       */15 * * * * /home/nms-net/ospf-topoviz/scripts/run_ospf_cron.sh >> /var/log/ospf-topoviz-cron.log 2>&1
# ==============================================================================

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOCK_FILE="/tmp/ospf-topoviz.lock"
ENV_FILE="${ROOT_DIR}/.env"
VENV_PYTHON="${ROOT_DIR}/.venv/bin/python"

# 1. Source environment file if available
if [[ -f "${ENV_FILE}" ]]; then
    # Load non-commented, non-empty exports
    set -a
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    set +a
fi

# 2. Check virtual environment python
if [[ ! -x "${VENV_PYTHON}" ]]; then
    if command -v python3 >/dev/null 2>&1; then
        VENV_PYTHON="$(command -v python3)"
    else
        echo "[ERROR] Python interpreter not found." >&2
        exit 1
    fi
fi

# 3. Concurrency safety: acquire non-blocking file lock via file descriptor 200
exec 200>"${LOCK_FILE}"
if ! flock -n 200; then
    echo "[INFO] [$(date '+%Y-%m-%d %H:%M:%S')] Another OSPF poll job is currently running. Skipping."
    exit 0
fi

# Ensure lock is held and released upon exit
cleanup() {
    local exit_code=$?
    flock -u 200 || true
    exit "${exit_code}"
}
trap cleanup EXIT INT TERM

cd "${ROOT_DIR}"
echo "[START] [$(date '+%Y-%m-%d %H:%M:%S')] Starting automated OSPF topology discovery..."
"${VENV_PYTHON}" main.py "$@"
echo "[DONE]  [$(date '+%Y-%m-%d %H:%M:%S')] OSPF topology discovery completed."
