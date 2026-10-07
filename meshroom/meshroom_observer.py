"""Optional MQTT observer bridge for MeshRoom.

The observer receives copies of KISS RX packets from MeshRoom. It never opens
or owns the serial port, so observer/network failures cannot block radio I/O.
"""

import base64
import json
import logging
import queue
import threading
import time
from datetime import datetime, timezone

log = logging.getLogger("meshroom.observer")

BROKERS = {
    "gomesh": ("mqtt.gomesh.dev", 443, "mqtt.gomesh.dev"),
    "meshmapper": ("mqtt.meshmapper.net", 443, "mqtt.meshmapper.net"),
}


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_auth_token(identity, public_key, audience, ttl=3600):
    """Create a MeshCore MQTT token; the modem-backed identity does the signing."""
    now = int(time.time())
    header = {"alg": "Ed25519", "typ": "JWT"}
    payload = {
        "publicKey": public_key.upper(),
        "iat": now,
        "exp": now + ttl,
        "aud": audience,
        "client": "meshroom-observer",
    }
    head = _b64url(json.dumps(header, separators=(",", ":")).encode())
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signed = (head + "." + body).encode()
    signature = identity.sign(signed)
    return head + "." + body + "." + signature.hex().upper()


class ObserverBridge:
    """Non-blocking handoff between MeshRoom RX and MQTT observer workers."""

    def __init__(self, cfg, identity):
        self.cfg = cfg
        self.identity = identity
        self.public_key = identity.pub_key.hex().upper()
        self.iata = str(getattr(cfg, "observer_iata", "SJC")).upper()
        self.q = queue.Queue(maxsize=max(10, int(getattr(cfg, "observer_queue_max", 1000))))
        self.dropped = 0
        self.started = time.time()
        self.running = True
        self.clients = {}
        self.connected = {}
        self.last_error = {}
        self.thread = threading.Thread(target=self._run, name="mqtt-observer", daemon=True)
        self.thread.start()

    def submit_rx(self, raw, snr, rssi):
        """Queue an RX observation without ever waiting on network I/O."""
        item = (bytes(raw), float(snr), int(rssi), time.time())
        try:
            self.q.put_nowait(item)
        except queue.Full:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 100 == 0:
                log.warning("observer queue full; dropped %d packet(s)", self.dropped)

    def close(self):
        self.running = False
        try:
            self.q.put_nowait(None)
        except queue.Full:
            pass
        self.thread.join(timeout=5)
        for client in self.clients.values():
            try:
                client.loop_stop()
                client.disconnect()
            except Exception:
                pass

    def _enabled(self):
        out = []
        if getattr(self.cfg, "observer_gomesh", True):
            out.append("gomesh")
        if getattr(self.cfg, "observer_meshmapper", True):
            out.append("meshmapper")
        return out

    def _connect(self, name, mqtt):
        host, port, audience = BROKERS[name]
        token = make_auth_token(self.identity, self.public_key, audience)
        client_id = ("meshcore_" + self.public_key[:12] + "_" + name)[:60]
        try:
            client = mqtt.Client(
                mqtt.CallbackAPIVersion.VERSION2,
                client_id=client_id, clean_session=True, transport="websockets"
            )
        except (AttributeError, TypeError):
            client = mqtt.Client(client_id=client_id, clean_session=True, transport="websockets")
        client.username_pw_set("v1_" + self.public_key, token)
        client.tls_set()
        client.ws_set_options(path="/")

        def on_connect(c, userdata, flags, reason_code, properties=None):
            try:
                ok = int(reason_code) == 0
            except (TypeError, ValueError):
                ok = reason_code == 0
            self.connected[name] = ok
            self.last_error[name] = "" if ok else "connect rc=%s" % reason_code
            if ok:
                log.info("observer %s connected to %s", name, host)

        def on_disconnect(c, userdata, *args):
            self.connected[name] = False
            log.warning("observer %s disconnected", name)

        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        self.clients[name] = client
        self.connected[name] = False
        try:
            client.connect_async(host, port, keepalive=60)
            client.loop_start()
        except Exception as e:
            self.last_error[name] = str(e)
            log.error("observer %s connection setup failed: %s", name, e)

    def _topic(self, kind):
        return "meshcore/%s/%s/%s" % (self.iata, self.public_key, kind)

    @staticmethod
    def _packet_metadata(raw):
        """Extract fields required by the standard MeshCore observer payload."""
        if not raw:
            return 0, "?", 0
        header = raw[0]
        route_type = header & 0x03
        packet_type = (header >> 2) & 0x0F
        route = ("F", "F", "D", "D")[route_type]
        i = 1 + (4 if route_type in (0, 3) else 0)
        if i >= len(raw):
            return packet_type, route, 0
        path_len = raw[i]
        hash_size = (path_len >> 6) + 1
        path_bytes = (path_len & 63) * hash_size
        payload_len = max(0, len(raw) - i - 1 - path_bytes)
        return packet_type, route, payload_len

    def _publish_packet(self, name, raw, snr, rssi, received_at):
        client = self.clients.get(name)
        if client is None or not self.connected.get(name):
            return False
        ptype, route, payload_len = self._packet_metadata(raw)
        dt = datetime.fromtimestamp(received_at, timezone.utc)
        message = {
            "origin": str(self.cfg.name),
            "origin_id": self.public_key,
            "timestamp": dt.isoformat(),
            "type": "PACKET",
            "direction": "rx",
            "time": dt.strftime("%H:%M:%S"),
            "date": dt.strftime("%m/%d/%Y"),
            "len": str(len(raw)),
            "packet_type": str(ptype),
            "route": route,
            "payload_len": str(payload_len),
            "raw": raw.hex().upper(),
            "SNR": str(snr),
            "RSSI": str(rssi),
        }
        try:
            result = client.publish(self._topic("packets"), json.dumps(message), qos=0, retain=True)
            if getattr(result, "rc", 0) == 0:
                return True
            self.last_error[name] = "publish rc=%s" % result.rc
        except Exception as e:
            self.last_error[name] = str(e)
        return False

    def _run(self):
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.last_error["observer"] = "paho-mqtt missing"
            log.error("observer enabled but paho-mqtt is missing")
            return

        for name in self._enabled():
            self._connect(name, mqtt)

        while self.running:
            try:
                item = self.q.get(timeout=1.0)
            except queue.Empty:
                continue
            if item is None:
                break
            raw, snr, rssi, received_at = item
            # Broker failures are independent: one destination cannot suppress the other.
            for name in list(self.clients):
                self._publish_packet(name, raw, snr, rssi, received_at)
