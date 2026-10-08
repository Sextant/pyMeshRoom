#!/usr/bin/env bash
# Safely update an existing pyMeshRoom checkout on Linux.
# Private configuration and room data are intentionally never touched by Git.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/update-pymeshroom.sh [options]

Update this clean pyMeshRoom main checkout, refresh core Python dependencies,
validate the selected private configuration, and run tests.

Options:
  --config PATH       Configuration path relative to meshroom/ (default: meshroom.json)
  --restart           Restart meshroom.service after a successful update
  --skip-tests        Do not run the automated test suite
  -h, --help          Show this help

The script refuses to update a checkout with modified tracked files. It does
not overwrite configuration or room-data files; those are outside Git.
EOF
}

CONFIG_NAME="meshroom.json"
RESTART_SERVICE=0
RUN_TESTS=1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG_NAME="${2:?--config requires a path}"; shift 2 ;;
    --restart) RESTART_SERVICE=1; shift ;;
    --skip-tests) RUN_TESTS=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$(uname -s)" == "Linux" ]] || { echo "This updater supports Linux only." >&2; exit 1; }
command -v git >/dev/null || { echo "Install Git first." >&2; exit 1; }
[[ -f "$ROOT/meshroom/meshroom.py" ]] || { echo "Run this from a complete pyMeshRoom checkout." >&2; exit 1; }
[[ -x "$ROOT/.venv/bin/python" ]] || { echo "Virtual environment missing. Run ./scripts/install-pymeshroom.sh first." >&2; exit 1; }

case "$CONFIG_NAME" in
  /*|*".."*) echo "--config must be a safe path relative to meshroom/." >&2; exit 2 ;;
esac
CONFIG="$ROOT/meshroom/$CONFIG_NAME"

cd "$ROOT"
[[ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" == "true" ]] || {
  echo "This directory is not a Git checkout." >&2; exit 1;
}
[[ "$(git branch --show-current)" == "main" ]] || {
  echo "Refusing to update: switch this checkout to main first." >&2; exit 1;
}
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || {
  echo "Refusing to update: commit, stash, or discard modified tracked files first." >&2; exit 1;
}

echo "Updating pyMeshRoom in $ROOT"
BEFORE="$(git rev-parse --short HEAD)"
git fetch origin main
REMOTE_MAIN="$(git rev-parse FETCH_HEAD)"
git merge-base --is-ancestor HEAD "$REMOTE_MAIN" || {
  echo "Refusing to update: local main has commits not contained in origin/main." >&2; exit 1;
}
git merge --ff-only "$REMOTE_MAIN"
AFTER="$(git rev-parse --short HEAD)"
echo "Code: $BEFORE -> $AFTER"

echo "Refreshing core Python dependencies"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip pyserial cryptography

if [[ -e "$CONFIG" ]]; then
  "$ROOT/.venv/bin/python" -m json.tool "$CONFIG" >/dev/null
  echo "Configuration preserved and valid: $CONFIG"
  if [[ "$RESTART_SERVICE" == 1 ]]; then
    CONFIG_MODE="$(stat -c '%a' "$CONFIG")"
    if (( (8#$CONFIG_MODE & 077) != 0 )); then
      echo "Refusing to restart: restrict $CONFIG to its owner (for example: chmod 600 $CONFIG)." >&2
      exit 1
    fi
  fi
else
  echo "No configuration found at $CONFIG (run the installer to create one)."
  [[ "$RESTART_SERVICE" == 0 ]] || {
    echo "Refusing to restart: the selected configuration does not exist." >&2; exit 1;
  }
fi

if [[ "$RUN_TESTS" == 1 ]]; then
  echo "Running automated tests"
  "$ROOT/.venv/bin/python" -m unittest discover -s tests -v
fi

if [[ "$RESTART_SERVICE" == 1 ]]; then
  command -v systemctl >/dev/null || { echo "--restart requires systemd." >&2; exit 1; }
  command -v sudo >/dev/null || { echo "--restart requires sudo." >&2; exit 1; }
  sudo systemctl restart meshroom.service
  sudo systemctl --no-pager --full status meshroom.service
fi

echo "Update complete. Private configuration and room data were not changed."
