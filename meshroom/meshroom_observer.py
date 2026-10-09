"""Optional MQTT observer bridge for MeshRoom.

The observer receives copies of KISS RX packets from MeshRoom. It never opens
or owns the serial port, so observer/network failures cannot block radio I/O.
"""

import base64
import json
import logging
import os
import queue
import sys
import threading
import time
from datetime import datetime, timezone

log = logging.getLogger("meshroom.observer")

VENDOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")


def import_paho():
    """Load installed paho-mqtt, or the bundled 2.1.0 fallback when absent."""
    try:
        import paho.mqtt.client as mqtt
        where = "installed"
    except ImportError:
        if not os.path.isdir(os.path.join(VENDOR_DIR, "paho")):
            raise
        if VENDOR_DIR not in sys.path:
            sys.path.append(VENDOR_DIR)  # do not shadow an installed package
        import paho.mqtt.client as mqtt
        where = "bundled"
    import paho.mqtt
    log.info("paho-mqtt %s (%s)", getattr(paho.mqtt, "__version__", "?"), where)
    return mqtt

LEGACY_BROKERS = {
    "gomesh": {"id": "gomesh", "name": "GoMesh", "host": "mqtt.gomesh.dev", "port": 443,
               "audience": "mqtt.gomesh.dev", "ws_path": "/", "tls": True, "tls_verify": True,
               "topic_prefix": "meshcore"},
    "meshmapper": {"id": "meshmapper", "name": "MeshMapper", "host": "mqtt.meshmapper.net", "port": 443,
                   "audience": "mqtt.meshmapper.net", "ws_path": "/", "tls": True, "tls_verify": True,
                   "topic_prefix": "meshcore"},
}
STATUS_INTERVAL = 60


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

    def __init__(self, cfg, identity, start=True):
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
        self.last_publish = {}
        self.last_rx = 0.0
        self.rf_total = 0
        self.rf_peak_ppm = 0
        self.rf_buckets = {}                         # UTC epoch minute -> received RF packet count
        self.broker_stats = {name: {"attempts": 0, "accepted": 0, "failures": 0,
                                    "payload_bytes": 0, "last_success": 0.0}
                             for name in self._servers()}
        self._lock = threading.Lock()
        self._refresh = threading.Event()
        # Paho reconnects its own network loop, but a reconnect needs a new
        # modem-signed JWT.  The callback only queues this work; the observer
        # worker owns stopping and replacing clients.
        self._reconnect = threading.Event()
        self._reconnect_brokers = set()
        self.thread = None
        if start:
            self.thread = threading.Thread(target=self._run, name="mqtt-observer", daemon=True)
            self.thread.start()

    def submit_rx(self, raw, snr, rssi):
        """Queue an RX observation without ever waiting on network I/O."""
        received_at = time.time()
        # Count actual KISS RX observations once, before MQTT/reporting gates.
        # This short locked section only updates in-memory integers and buckets.
        minute = int(received_at // 60)
        with self._lock:
            self.rf_total += 1
            self.rf_buckets[minute] = self.rf_buckets.get(minute, 0) + 1
            self.rf_peak_ppm = max(self.rf_peak_ppm, self.rf_buckets[minute])
            for old_minute in tuple(self.rf_buckets):
                if old_minute < minute - 59:
                    del self.rf_buckets[old_minute]
            self.last_rx = received_at
        # Do not enqueue at all when packet reporting is disabled.  This is a
        # receive-path-only operation: no network or serial work happens here.
        if not (getattr(self.cfg, "observer_enabled", False) and
                getattr(self.cfg, "observer_packets", True) and
                getattr(self.cfg, "observer_rx", True)):
            return
        item = (bytes(raw), float(snr), int(rssi), received_at)
        try:
            self.q.put_nowait(item)
        except queue.Full:
            with self._lock:
                self.dropped += 1
                dropped = self.dropped
            if dropped == 1 or dropped % 100 == 0:
                log.warning("observer queue full; dropped %d packet(s)", dropped)

    def close(self):
        self.running = False
        try:
            self.q.put_nowait(None)
        except queue.Full:
            pass
        if self.thread:
            self.thread.join(timeout=5)
        for name, client in list(self.clients.items()):
            try:
                # A clean shutdown does not invoke MQTT's last will, so make
                # the retained observer state accurate before disconnecting.
                self._publish_status(name, online=False, client=client)
                client.loop_stop()
                client.disconnect()
            except Exception:
                pass

    def _enabled(self):
        if not getattr(self.cfg, "observer_enabled", False):
            return []
        return [name for name, spec in self._servers().items() if spec["enabled"]]

    def _servers(self):
        """Configured standard MeshCore observer destinations, keyed by stable id.

        `None` means an older config: retain its two legacy switches. A saved
        list, including an empty list, is authoritative and supports deletion.
        """
        raw = getattr(self.cfg, "observer_servers", None)
        if raw is None:
            raw = []
            for name, spec in LEGACY_BROKERS.items():
                item = dict(spec)
                item["enabled"] = bool(getattr(self.cfg, "observer_" + name, True))
                raw.append(item)
        out = {}
        for item in raw if isinstance(raw, list) else []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("id") or "").strip().lower()
            if not name or name in out:
                continue
            spec = dict(item)
            spec["id"] = name
            spec["name"] = str(item.get("name") or name)
            spec["enabled"] = bool(item.get("enabled", True))
            out[name] = spec
        return out

    def status(self):
        """A stable, lock-protected diagnostics snapshot for the dashboard."""
        with self._lock:
            brokers = {
                name: {
                    "enabled": name in self._enabled(),
                    "connected": bool(self.connected.get(name)),
                    "last_publish": self.last_publish.get(name, 0.0),
                    "last_error": self.last_error.get(name, ""),
                }
                for name in self._servers()
            }
            return {
                "enabled": bool(getattr(self.cfg, "observer_enabled", False)),
                "iata": self.iata,
                "status": bool(getattr(self.cfg, "observer_status", True)),
                "packets": bool(getattr(self.cfg, "observer_packets", True)),
                "rx": bool(getattr(self.cfg, "observer_rx", True)),
                "public_key": self.public_key,
                "queue_depth": self.q.qsize(),
                "queue_max": self.q.maxsize,
                "dropped": self.dropped,
                "uptime": max(0, int(time.time() - self.started)),
                "last_rx": self.last_rx,
                "last_error": self.last_error.get("observer", ""),
                "brokers": brokers,
                "servers": [dict(id=s["id"], name=s["name"], enabled=s["enabled"], host=s["host"],
                                  port=int(s["port"]), audience=s["audience"], ws_path=s.get("ws_path", "/"),
                                  tls=bool(s.get("tls", True)), tls_verify=bool(s.get("tls_verify", True)),
                                  topic_prefix=s.get("topic_prefix", "meshcore"))
                            for s in self._servers().values()],
            }

    def statistics(self):
        """Admin-only traffic snapshot. Counts are local observations/submissions, not broker delivery."""
        minute = int(time.time() // 60)
        with self._lock:
            for old_minute in tuple(self.rf_buckets):
                if old_minute < minute - 59:
                    del self.rf_buckets[old_minute]
            buckets = [self.rf_buckets.get(m, 0) for m in range(minute - 59, minute + 1)]
            brokers = {name: dict(values, connected=bool(self.connected.get(name)),
                                  last_error=self.last_error.get(name, ""))
                       for name, values in self.broker_stats.items()}
            return {
                "enabled": bool(getattr(self.cfg, "observer_enabled", False)),
                "uptime": max(0, int(time.time() - self.started)),
                "rf_total": self.rf_total,
                "rf_current_ppm": buckets[-1],
                "rf_peak_ppm": self.rf_peak_ppm,
                "rf_last_60m": sum(buckets),
                "rf_per_minute": buckets,
                "queue_depth": self.q.qsize(),
                "queue_max": self.q.maxsize,
                "dropped": self.dropped,
                "brokers": brokers,
            }

    def _status_message(self, online=True):
        snapshot = self.status()
        return json.dumps({
            "origin": str(self.cfg.name),
            "origin_id": self.public_key,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "online": bool(online),
            "queue_depth": snapshot["queue_depth"],
            "queue_max": snapshot["queue_max"],
            "dropped": snapshot["dropped"],
            "uptime": snapshot["uptime"],
        }, separators=(",", ":"))

    def _record_error(self, name, message):
        with self._lock:
            self.last_error[name] = str(message)

    def _set_connected(self, name, value):
        with self._lock:
            self.connected[name] = bool(value)

    def _record_attempt(self, name, payload):
        with self._lock:
            stats = self.broker_stats.setdefault(name, {"attempts": 0, "accepted": 0, "failures": 0,
                                                         "payload_bytes": 0, "last_success": 0.0})
            stats["attempts"] += 1
            stats["payload_bytes"] += len(payload.encode())

    def _record_publish_result(self, name, accepted):
        when = time.time()
        with self._lock:
            stats = self.broker_stats.setdefault(name, {"attempts": 0, "accepted": 0, "failures": 0,
                                                         "payload_bytes": 0, "last_success": 0.0})
            if accepted:
                stats["accepted"] += 1
                stats["last_success"] = when
                self.last_publish[name] = when
            else:
                stats["failures"] += 1

    def refresh(self):
        """Apply changed observer settings from the worker, never the RX path."""
        self._refresh.set()

    def _queue_token_refresh(self, name):
        """Request a replacement client with a freshly signed MQTT JWT."""
        with self._lock:
            self._reconnect_brokers.add(name)
        self._reconnect.set()

    def _take_token_refreshes(self):
        if not self._reconnect.is_set():
            return set()
        with self._lock:
            names = set(self._reconnect_brokers)
            self._reconnect_brokers.clear()
            self._reconnect.clear()
        return names

    def _disconnect(self, name, offline=True):
        client = self.clients.pop(name, None)
        if client is None:
            return
        if offline:
            self._publish_status(name, online=False, client=client)
        try:
            client.disconnect()
            client.loop_stop()
        except Exception as e:
            self._record_error(name, e)
        self._set_connected(name, False)

    def _sync_clients(self, mqtt, rebuild=False):
        """Reconcile broker settings in the observer worker thread."""
        self.iata = str(getattr(self.cfg, "observer_iata", "SJC")).upper()
        self.q.maxsize = max(10, int(getattr(self.cfg, "observer_queue_max", 1000)))
        specs = self._servers()
        enabled = set(self._enabled())
        with self._lock:
            for name in specs:
                self.broker_stats.setdefault(name, {"attempts": 0, "accepted": 0, "failures": 0,
                                                     "payload_bytes": 0, "last_success": 0.0})
        if rebuild:
            for name in list(self.clients):
                self._disconnect(name)
        else:
            for name in list(self.clients):
                if name not in enabled:
                    self._disconnect(name)
        for name in enabled:
            if name not in self.clients:
                self._connect(name, specs[name], mqtt)

    def _refresh_tokens(self, mqtt, names):
        """Replace selected clients so their next CONNECT uses a fresh JWT."""
        specs = self._servers()
        enabled = set(self._enabled())
        for name in names:
            if name not in enabled or name not in specs:
                continue
            self._disconnect(name, offline=False)
            self._connect(name, specs[name], mqtt)

    def _connect(self, name, spec, mqtt):
        host, port, audience = spec["host"], int(spec["port"]), spec["audience"]
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
        if spec.get("tls", True):
            client.tls_set()
            if not spec.get("tls_verify", True):
                client.tls_insecure_set(True)
        client.ws_set_options(path=spec.get("ws_path", "/"))
        client.reconnect_delay_set(min_delay=1, max_delay=60)
        if getattr(self.cfg, "observer_status", True):
            client.will_set(self._topic(name, "status"), self._status_message(False), qos=0, retain=True)

        def on_connect(c, userdata, flags, reason_code, properties=None):
            try:
                ok = int(reason_code) == 0
            except (TypeError, ValueError):
                ok = reason_code == 0
            self._set_connected(name, ok)
            self._record_error(name, "" if ok else "connect rc=%s" % reason_code)
            if ok:
                log.info("observer %s connected to %s", name, host)
                self._publish_status(name)
            elif self.running and self.clients.get(name) is c:
                log.warning("observer %s rejected its MQTT token; refreshing it", name)
                self._queue_token_refresh(name)

        def on_disconnect(c, userdata, *args):
            self._set_connected(name, False)
            log.warning("observer %s disconnected", name)
            # A broker evaluates JWT credentials at CONNECT time.  Do not let
            # Paho retry indefinitely with the token created for an earlier
            # connection; replace this client in the worker with a new token.
            if self.running and self.clients.get(name) is c:
                self._queue_token_refresh(name)

        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        self.clients[name] = client
        self._set_connected(name, False)
        try:
            client.connect_async(host, port, keepalive=60)
            client.loop_start()
        except Exception as e:
            self._record_error(name, e)
            log.error("observer %s connection setup failed: %s", name, e)

    def _topic(self, name, kind):
        spec = self._servers().get(name, {})
        prefix = str(spec.get("topic_prefix") or "meshcore").strip("/")
        return "%s/%s/%s/%s" % (prefix, self.iata, self.public_key, kind)

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
        if name not in self._enabled() or client is None or not self.connected.get(name):
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
        payload = json.dumps(message)
        try:
            self._record_attempt(name, payload)
            result = client.publish(self._topic(name, "packets"), payload, qos=0, retain=True)
            if getattr(result, "rc", 0) == 0:
                self._record_publish_result(name, True)
                return True
            self._record_publish_result(name, False)
            self._record_error(name, "publish rc=%s" % result.rc)
        except Exception as e:
            self._record_publish_result(name, False)
            self._record_error(name, e)
        return False

    def _publish_status(self, name, online=True, client=None):
        if not getattr(self.cfg, "observer_status", True):
            return False
        client = client or self.clients.get(name)
        if client is None or (online and (name not in self._enabled() or not self.connected.get(name))):
            return False
        payload = self._status_message(online)
        try:
            self._record_attempt(name, payload)
            result = client.publish(self._topic(name, "status"), payload, qos=0, retain=True)
            if getattr(result, "rc", 0) == 0:
                self._record_publish_result(name, True)
                return True
            self._record_publish_result(name, False)
            self._record_error(name, "status publish rc=%s" % result.rc)
        except Exception as e:
            self._record_publish_result(name, False)
            self._record_error(name, e)
        return False

    def _run(self):
        try:
            mqtt = import_paho()
        except ImportError:
            self._record_error("observer", "paho-mqtt missing")
            log.error("observer enabled but paho-mqtt is missing (not installed, and meshroom/vendor/paho not found)")
            return

        self._sync_clients(mqtt)

        next_status = time.monotonic() + STATUS_INTERVAL
        while self.running:
            if self._refresh.is_set():
                self._refresh.clear()
                self._sync_clients(mqtt, rebuild=True)
            reconnects = self._take_token_refreshes()
            if reconnects:
                self._refresh_tokens(mqtt, reconnects)
            try:
                item = self.q.get(timeout=1.0)
            except queue.Empty:
                item = None
            if item is None:
                if not self.running:
                    break
            else:
                raw, snr, rssi, received_at = item
                # Broker failures are independent: one destination cannot suppress the other.
                for name in list(self.clients):
                    self._publish_packet(name, raw, snr, rssi, received_at)
            if time.monotonic() >= next_status:
                for name in list(self.clients):
                    self._publish_status(name)
                next_status = time.monotonic() + STATUS_INTERVAL
