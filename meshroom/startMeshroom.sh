#!/usr/bin/env bash

cd "$(dirname "$0")" || exit 1

if pgrep -f "python3 meshroom.py" >/dev/null; then
    echo "meshroom already running (PID $(pgrep -f 'python3 meshroom.py'))"
    exit 1
fi

nohup python3 meshroom.py --config meshroom.json &
sleep 1

if pgrep -f "python3 meshroom.py" >/dev/null; then
    echo "meshroom started (PID $!)"
else
    echo "meshroom failed to start, check meshroom.log"
    tail -n 20 meshroom.log
    exit 1
fi
