#!/usr/bin/env bash
# Stop only the manual pyMeshRoom process started by start-pymeshroom.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SERVER="$ROOT/meshroom/meshroom.py"
PID_FILE="$ROOT/meshroom/meshroom.pid"

[[ -f "$PID_FILE" ]] || {
  echo "No manually started pyMeshRoom PID file exists. meshroom.service is never stopped by this script."
  exit 0
}

PID="$(<"$PID_FILE")"
if [[ ! "$PID" =~ ^[0-9]+$ ]] || ! kill -0 "$PID" 2>/dev/null; then
  rm -f "$PID_FILE"
  echo "Removed stale manual pyMeshRoom PID file."
  exit 0
fi

CMDLINE="$(tr '\0' ' ' <"/proc/$PID/cmdline" 2>/dev/null || true)"
case "$CMDLINE" in
  *"$SERVER"*) ;;
  *)
    echo "Refusing to stop PID $PID: it is not the recorded pyMeshRoom server process." >&2
    exit 1
    ;;
esac

echo "Stopping manual pyMeshRoom PID $PID..."
kill -TERM "$PID"
for _ in {1..10}; do
  kill -0 "$PID" 2>/dev/null || {
    rm -f "$PID_FILE"
    echo "Stopped."
    exit 0
  }
  sleep 1
done

echo "Process did not exit within 10 seconds; it was left running. Inspect the log or stop it deliberately." >&2
exit 1
