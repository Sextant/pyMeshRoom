#!/usr/bin/env bash
# Start one manual pyMeshRoom test process from this checkout.
# This script never starts over an active systemd service.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/start-pymeshroom.sh [--config NAME] [--log PATH]

Start a manually managed pyMeshRoom process for testing. NAME is relative to
meshroom/ and defaults to meshroom.json. The matching stop script manages only
the PID created here; it never stops meshroom.service.
EOF
}

CONFIG_NAME="meshroom.json"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LOG_FILE="$ROOT/meshroom/meshroom.log"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG_NAME="${2:?--config requires a name}"; shift 2 ;;
    --log) LOG_FILE="${2:?--log requires a path}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$CONFIG_NAME" in
  /*|*".."*) echo "--config must be a safe path relative to meshroom/." >&2; exit 2 ;;
esac

PYTHON="$ROOT/.venv/bin/python"
SERVER="$ROOT/meshroom/meshroom.py"
CONFIG="$ROOT/meshroom/$CONFIG_NAME"
PID_FILE="$ROOT/meshroom/meshroom.pid"

[[ "$(uname -s)" == "Linux" ]] || { echo "This script supports Linux only." >&2; exit 1; }
[[ -x "$PYTHON" ]] || { echo "Virtual environment missing. Run ./scripts/install-pymeshroom.sh first." >&2; exit 1; }
[[ -f "$CONFIG" ]] || { echo "Configuration not found: $CONFIG" >&2; exit 1; }
"$PYTHON" -m json.tool "$CONFIG" >/dev/null

if command -v systemctl >/dev/null && systemctl is-active --quiet meshroom.service; then
  echo "Refusing to start: meshroom.service is active. Stop the service first, or use it instead." >&2
  exit 1
fi

if [[ -f "$PID_FILE" ]]; then
  PID="$(<"$PID_FILE")"
  if [[ "$PID" =~ ^[0-9]+$ ]] && kill -0 "$PID" 2>/dev/null; then
    echo "Refusing to start: manual pyMeshRoom PID $PID is already recorded." >&2
    exit 1
  fi
  rm -f "$PID_FILE"
fi

# Refuse rather than risking two servers on the same serial modem or web port.
if pgrep -f "$SERVER" >/dev/null; then
  echo "Refusing to start: a pyMeshRoom process from this checkout is already running." >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_FILE")"
cd "$ROOT/meshroom"
nohup "$PYTHON" "$SERVER" --config "$CONFIG_NAME" >>"$LOG_FILE" 2>&1 &
PID=$!
printf '%s\n' "$PID" > "$PID_FILE"
sleep 1

if kill -0 "$PID" 2>/dev/null; then
  echo "Manual pyMeshRoom started (PID $PID). Log: $LOG_FILE"
else
  rm -f "$PID_FILE"
  echo "pyMeshRoom exited during startup. Recent log output:" >&2
  tail -n 20 "$LOG_FILE" >&2 || true
  exit 1
fi
