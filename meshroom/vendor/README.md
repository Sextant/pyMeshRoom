# Bundled third-party code

| Package | Version | Source | License |
|---|---|---|---|
| `paho/` (paho-mqtt) | 2.1.0 | `paho_mqtt-2.1.0.tar.gz` from PyPI (sha256 `12d6e751...1723834`), `src/paho/` unmodified | EPL-2.0 or EDL-1.0, at your choice: see `paho-mqtt-license/` |

Only the optional outbound MQTT Observer (`meshroom_observer.py`) uses paho-mqtt. It prefers an installed paho-mqtt
(the project's `.venv`, pip, or Debian's `python3-paho-mqtt`) and falls back to this copy, so a checkout that keeps
`meshroom/vendor/` next to `meshroom.py` needs no separate paho install. To update: replace `paho/` with `src/paho/`
from a newer release and refresh `paho-mqtt-license/` from the same release.
