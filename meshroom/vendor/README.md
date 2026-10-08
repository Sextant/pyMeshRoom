# Bundled third-party code

| Package | Version | Source | License |
|---|---|---|---|
| `paho/` (paho-mqtt) | 2.1.0 | [`paho_mqtt-2.1.0.tar.gz`](https://files.pythonhosted.org/packages/39/15/0a6214e76d4d32e7f663b109cf71fb22561c2be0f701d67f93950cd40542/paho_mqtt-2.1.0.tar.gz), SHA-256 `12d6e7511d4137555a3f6ea167ae846af2c7357b10bc6fa4f7c3968fc1723834`; `src/paho/` unmodified | EPL-2.0 or EDL-1.0, at your choice: see `paho-mqtt-license/` |

Only the optional outbound MQTT Observer (`meshroom_observer.py`) uses paho-mqtt. It prefers an installed paho-mqtt
(the project's `.venv`, pip, or Debian's `python3-paho-mqtt`) and falls back to this copy, so a checkout that keeps
`meshroom/vendor/` next to `meshroom.py` needs no separate paho install. To update: replace `paho/` with `src/paho/`
from a newer release and refresh `paho-mqtt-license/` from the same release.
