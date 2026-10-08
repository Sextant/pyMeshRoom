#!/usr/bin/env bash

meshroomPID=$(pgrep -f "python3 meshroom.py")

if [ -z "$meshroomPID" ]; then
    echo "meshroom not running"
else
    echo "Stopping meshroom (PID $meshroomPID)..."
    kill -TERM $meshroomPID

    # Wait up to 10 seconds for a clean exit
    for i in {1..10}; do
        pgrep -f "python3 meshroom.py" >/dev/null || { echo "Stopped."; exit 0; }
        sleep 1
    done

    echo "Didn't exit gracefully, forcing..."
    kill -KILL $meshroomPID
fi
