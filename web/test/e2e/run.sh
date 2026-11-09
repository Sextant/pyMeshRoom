#!/bin/sh
# End to end: a real pyMeshRoom on a fake radio, and this app in Chromium (Playwright).
#   web/test/e2e/run.sh            # the dev page (src/ modules)
#   web/test/e2e/run.sh built      # the built single file, opened from disk
# Needs python3 with cryptography, and node with playwright (npm i -D playwright && npx playwright install chromium).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
PYMESHROOM=$(cd "${PYMESHROOM:-$ROOT/..}" && pwd)
export PYMESHROOM
WORK=$(mktemp -d)
python3 -u "$HERE/devserver.py" "$PYMESHROOM" 9101 "$WORK" > "$WORK/dev.log" 2>&1 &
DEV=$!
(cd "$ROOT" && exec python3 -m http.server 9100 --bind 127.0.0.1 > /dev/null 2>&1) &
WEB=$!
trap 'kill $DEV $WEB 2>/dev/null' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do grep -q TOKEN "$WORK/dev.log" 2>/dev/null && break; sleep 1; done
if [ "${1:-}" = built ]; then
  (cd "$ROOT" && node build.mjs)
  PAGE="file://$PYMESHROOM/meshroom/data/meshcore-web.html"
else
  PAGE="http://127.0.0.1:9100/index.html"
fi
node "$HERE/e2e.cjs" "$PAGE" "$WORK"
echo "screenshots: $WORK/shot-*.png"
