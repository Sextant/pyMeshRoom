#!/bin/sh
# Stops the WhereBot that start-wherebot.sh started.
DIR=$(cd "$(dirname "$0")" && pwd)
PIDFILE="$DIR/where_bot.pid"

if [ ! -f "$PIDFILE" ]; then
    echo "WhereBot isn't running (no $PIDFILE)"
    exit 1
fi
PID=$(cat "$PIDFILE")
if ! kill -0 "$PID" 2>/dev/null; then
    echo "WhereBot isn't running (pid $PID is gone)"
    rm -f "$PIDFILE"
    exit 1
fi
kill "$PID"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$PID" 2>/dev/null || break
    sleep 1
done
if kill -0 "$PID" 2>/dev/null; then
    echo "WhereBot didn't stop after 10 s: killing it"
    kill -9 "$PID"
fi
rm -f "$PIDFILE"
echo "WhereBot stopped (pid $PID)"
