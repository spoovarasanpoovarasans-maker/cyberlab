#!/usr/bin/env bash
# Run the control plane directly on the host (Docker must be running).
set -euo pipefail

cd "$(dirname "$0")/.."

: "${CYBERLAB_BIND_IP:=127.0.0.1}"
: "${CYBERLAB_CONTROL_PORT:=8443}"

PYTHON="python"
if [ -x ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
fi

exec "$PYTHON" -m uvicorn app.main:app \
    --host "${CYBERLAB_BIND_IP}" \
    --port "${CYBERLAB_CONTROL_PORT}" \
    --reload
