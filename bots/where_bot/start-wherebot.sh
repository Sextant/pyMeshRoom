#!/bin/sh
# Starts WhereBot in the background with nohup. Usage: ./start-wherebot.sh [config.yaml]
# Logs go to where_bot.log and the process id to where_bot.pid, both in this directory.
DIR=$(cd "$(dirname "$0")" && pwd)
PIDFILE="$DIR/where_bot.pid"
LOG="$DIR/where_bot.log"
PYTHON=${PYTHON:-python3}

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "WhereBot is already running (pid $(cat "$PIDFILE"))"
    exit 1
fi
CONFIG=${1:-$DIR/where_bot.yaml}
if [ ! -f "$CONFIG" ]; then
    echo "no config at $CONFIG (copy where_bot.example.yaml to where_bot.yaml and fill it in)"
    exit 1
fi
CONFIG=$(cd "$(dirname "$CONFIG")" && pwd)/$(basename "$CONFIG")

cd "$DIR" || exit 1
nohup "$PYTHON" -u "$DIR/where_bot.py" "$CONFIG" >>"$LOG" 2>&1 &
echo $! >"$PIDFILE"
sleep 1
if kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "WhereBot started (pid $(cat "$PIDFILE")), logging to $LOG"
else
    rm -f "$PIDFILE"
    echo "WhereBot exited straight away; the end of $LOG:"
    tail -n 5 "$LOG"
    exit 1
fi
