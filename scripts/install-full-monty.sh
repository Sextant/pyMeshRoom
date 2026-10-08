#!/usr/bin/env bash
# Bootstrap an existing feature/the-full-monty checkout on Linux.
# It never overwrites an existing configuration or installs a service unless asked.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/install-full-monty.sh [options]

Bootstrap this checkout in a Python virtual environment and create a private
configuration if one does not already exist.

Options:
  --config PATH       Configuration path relative to meshroom/ (default: meshroom.json)
  --data-dir PATH     Data directory used only for a newly created configuration
                      (default: <checkout>/data)
  --service           Install and enable a systemd meshroom.service for this checkout
  --replace-service   Required with --service if meshroom.service already exists
  --user USER         Service account (default: current user)
  --skip-tests        Do not run the automated test suite
  -h, --help          Show this help

The script leaves RF-first defaults intact: MQTT Observer, MQTT Augmentation,
Virtual Repeater, and repeater relaying are all disabled. Edit the private
configuration before operating a live modem.
EOF
}

CONFIG_NAME="meshroom.json"
INSTALL_SERVICE=0
REPLACE_SERVICE=0
RUN_TESTS=1
SERVICE_USER="${SUDO_USER:-$USER}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DATA_DIR="$ROOT/data"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG_NAME="${2:?--config requires a path}"; shift 2 ;;
    --data-dir) DATA_DIR="${2:?--data-dir requires a path}"; shift 2 ;;
    --service) INSTALL_SERVICE=1; shift ;;
    --replace-service) REPLACE_SERVICE=1; shift ;;
    --user) SERVICE_USER="${2:?--user requires a user}"; shift 2 ;;
    --skip-tests) RUN_TESTS=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$(uname -s)" == "Linux" ]] || { echo "This installer supports Linux only." >&2; exit 1; }
command -v python3 >/dev/null || { echo "Install Python 3 and python3-venv first." >&2; exit 1; }
command -v git >/dev/null || { echo "Install Git first." >&2; exit 1; }
[[ -f "$ROOT/meshroom/meshroom.py" ]] || { echo "Run this from a complete MeshRoom checkout." >&2; exit 1; }

case "$CONFIG_NAME" in
  /*|*".."*) echo "--config must be a safe path relative to meshroom/." >&2; exit 2 ;;
esac
CONFIG="$ROOT/meshroom/$CONFIG_NAME"
EXAMPLE="$ROOT/meshroom/meshroom.json.example"
mkdir -p "$ROOT/meshroom" "$DATA_DIR"
chmod 700 "$DATA_DIR"

echo "Creating or updating virtual environment in $ROOT/.venv"
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip pyserial cryptography paho-mqtt

if [[ ! -e "$CONFIG" ]]; then
  echo "Creating private configuration: $CONFIG"
  cp "$EXAMPLE" "$CONFIG"
  "$ROOT/.venv/bin/python" - "$CONFIG" "$DATA_DIR" <<'PY'
import json, sys
path, data_dir = sys.argv[1:]
with open(path, encoding="utf-8") as file:
    config = json.load(file)
config["system"]["data_dir"] = data_dir
with open(path, "w", encoding="utf-8") as file:
    json.dump(config, file, indent=2)
    file.write("\n")
PY
  chmod 600 "$CONFIG"
else
  echo "Keeping existing configuration unchanged: $CONFIG"
fi

"$ROOT/.venv/bin/python" -m json.tool "$CONFIG" >/dev/null
echo "Configuration JSON is valid. Edit it before connecting a live modem: $CONFIG"

if [[ "$RUN_TESTS" == 1 ]]; then
  echo "Running automated tests"
  (cd "$ROOT" && .venv/bin/python -m unittest discover -s tests -v)
fi

if [[ "$INSTALL_SERVICE" == 1 ]]; then
  SERVICE_FILE="/etc/systemd/system/meshroom.service"
  if [[ -e "$SERVICE_FILE" && "$REPLACE_SERVICE" != 1 ]]; then
    echo "$SERVICE_FILE already exists. Inspect it first; rerun with --service --replace-service to replace it." >&2
    exit 1
  fi
  command -v sudo >/dev/null || { echo "--service requires sudo." >&2; exit 1; }
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    echo "Service user does not exist: $SERVICE_USER" >&2; exit 1
  fi
  sudo tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=MeshRoom RF-first Room Server
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
SupplementaryGroups=dialout
WorkingDirectory=$ROOT/meshroom
ExecStart=$ROOT/.venv/bin/python meshroom.py --config $CONFIG_NAME
Restart=on-failure
RestartSec=10
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable --now meshroom.service
  sudo systemctl --no-pager --full status meshroom.service
fi

cat <<EOF

Bootstrap complete.
Next: edit $CONFIG (room name, serial device, location, passwords, and dashboard bind address),
then run: cd "$ROOT/meshroom" && ../.venv/bin/python meshroom.py --config "$CONFIG_NAME"
EOF
