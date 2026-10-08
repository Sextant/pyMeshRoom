import base64
import json
import pathlib
import sys
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "meshroom"))
from meshroom_observer import ObserverBridge, make_auth_token


class FakeIdentity:
    pub_key = bytes.fromhex("11" * 32)

    def __init__(self):
        self.inputs = []

    def sign(self, message):
        self.inputs.append(message)
        return bytes.fromhex("AA" * 64)


def config(**overrides):
    values = dict(name="Test Room", observer_enabled=True, observer_iata="SJC",
                  observer_queue_max=10, observer_status=True, observer_packets=True,
                  observer_rx=True, observer_gomesh=True, observer_meshmapper=True)
    values.update(overrides)
    return SimpleNamespace(**values)


class ObserverTests(unittest.TestCase):
    def test_bundled_paho_is_used_when_none_is_installed(self):
        import subprocess
        meshroom_dir = str(pathlib.Path(__file__).resolve().parents[1] / "meshroom")
        # -S hides site-packages, so import_paho() must use meshroom/vendor.
        code = ("import sys; sys.path.insert(0, %r); import meshroom_observer as m; c = m.import_paho(); "
                "import paho.mqtt; print(c.__file__); print(paho.mqtt.__version__); "
                "print(hasattr(c, 'CallbackAPIVersion'))" % meshroom_dir)
        out = subprocess.run([sys.executable, "-I", "-S", "-c", code], capture_output=True,
                             text=True, check=True).stdout.split()
        self.assertTrue(out[0].startswith(str(pathlib.Path(meshroom_dir) / "vendor" / "paho")), out[0])
        self.assertEqual(out[1:], ["2.1.0", "True"])

    def test_custom_observer_server_replaces_legacy_destinations(self):
        cfg = config(observer_servers=[{"id": "regional", "name": "Regional", "enabled": True,
                                        "host": "mqtt.example.org", "port": 443, "audience": "mqtt.example.org",
                                        "ws_path": "/mqtt", "tls": True, "tls_verify": True, "topic_prefix": "meshcore"}])
        bridge = ObserverBridge(cfg, FakeIdentity(), start=False)
        self.assertEqual(bridge._enabled(), ["regional"])
        self.assertEqual(bridge._topic("regional", "packets"), "meshcore/SJC/" + bridge.public_key + "/packets")

    def test_token_uses_modem_signature_and_standard_encoding(self):
        identity = FakeIdentity()
        token = make_auth_token(identity, identity.pub_key.hex(), "mqtt.gomesh.dev", ttl=90)
        header, payload, signature = token.split(".")
        decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        self.assertEqual(json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))["alg"], "Ed25519")
        self.assertEqual(decoded["publicKey"], identity.pub_key.hex().upper())
        self.assertEqual(decoded["aud"], "mqtt.gomesh.dev")
        self.assertEqual(signature, "AA" * 64)
        self.assertEqual(identity.inputs, [(header + "." + payload).encode()])

    def test_packet_metadata_for_flood_and_direct(self):
        # Header: flood packet type 5, one one-byte path hop, then two-byte payload.
        self.assertEqual(ObserverBridge._packet_metadata(bytes([0x15, 0x01, 0xA0, 0xBE, 0xEF])), (5, "F", 2))
        # Header: direct packet type 2, zero hops, then three-byte payload.
        self.assertEqual(ObserverBridge._packet_metadata(bytes([0x0A, 0x00, 1, 2, 3])), (2, "D", 3))

    def test_submit_is_bounded_and_disabled_observer_is_inert(self):
        bridge = ObserverBridge(config(observer_queue_max=10), FakeIdentity(), start=False)
        try:
            for _ in range(11):
                bridge.submit_rx(b"x", 1.5, -90)
            self.assertEqual(bridge.q.qsize(), 10)
            self.assertEqual(bridge.status()["dropped"], 1)
        finally:
            bridge.close()

        bridge = ObserverBridge(config(observer_enabled=False), FakeIdentity(), start=False)
        try:
            bridge.submit_rx(b"x", 1.5, -90)
            self.assertEqual(bridge.q.qsize(), 0)
        finally:
            bridge.close()

    def test_rf_statistics_count_each_kiss_rx_once_and_expire_old_buckets(self):
        bridge = ObserverBridge(config(observer_packets=False), FakeIdentity(), start=False)
        try:
            bridge.submit_rx(b"one", 1.0, -90)
            bridge.submit_rx(b"two", 2.0, -91)
            self.assertEqual(bridge.q.qsize(), 0)  # packet reporting is gated off
            stats = bridge.statistics()
            self.assertEqual(stats["rf_total"], 2)
            self.assertEqual(stats["rf_current_ppm"], 2)
            self.assertEqual(stats["rf_last_60m"], 2)
            self.assertEqual(stats["rf_peak_ppm"], 2)
            with bridge._lock:
                bridge.rf_buckets[int(time.time() // 60) - 60] = 99
            stats = bridge.statistics()
            self.assertEqual(stats["rf_last_60m"], 2)
            self.assertEqual(len(stats["rf_per_minute"]), 60)
        finally:
            bridge.close()

    def test_broker_statistics_are_independent_local_submissions(self):
        class Client:
            def __init__(self, rc):
                self.rc = rc

            def publish(self, *args, **kwargs):
                return SimpleNamespace(rc=self.rc)

        bridge = ObserverBridge(config(), FakeIdentity(), start=False)
        try:
            bridge.clients = {"gomesh": Client(0), "meshmapper": Client(5)}
            bridge.connected = {"gomesh": True, "meshmapper": True}
            self.assertTrue(bridge._publish_packet("gomesh", b"\x0a\x00x", 1.5, -90, time.time()))
            self.assertFalse(bridge._publish_packet("meshmapper", b"\x0a\x00x", 1.5, -90, time.time()))
            stats = bridge.statistics()["brokers"]
            self.assertEqual(stats["gomesh"]["attempts"], 1)
            self.assertEqual(stats["gomesh"]["accepted"], 1)
            self.assertEqual(stats["gomesh"]["failures"], 0)
            self.assertGreater(stats["gomesh"]["payload_bytes"], 0)
            self.assertEqual(stats["meshmapper"]["attempts"], 1)
            self.assertEqual(stats["meshmapper"]["accepted"], 0)
            self.assertEqual(stats["meshmapper"]["failures"], 1)
        finally:
            bridge.close()

    def test_status_exposes_queue_and_broker_diagnostics(self):
        bridge = ObserverBridge(config(), FakeIdentity(), start=False)
        try:
            bridge.connected["gomesh"] = True
            bridge.last_publish["gomesh"] = time.time()
            bridge.last_error["meshmapper"] = "connection refused"
            status = bridge.status()
            self.assertEqual(status["iata"], "SJC")
            self.assertTrue(status["brokers"]["gomesh"]["connected"])
            self.assertEqual(status["brokers"]["meshmapper"]["last_error"], "connection refused")
        finally:
            bridge.close()

    def test_clean_close_publishes_retained_offline_status(self):
        class Client:
            def __init__(self):
                self.messages = []

            def publish(self, topic, payload, qos, retain):
                self.messages.append((topic, json.loads(payload), qos, retain))
                return SimpleNamespace(rc=0)

            def loop_stop(self):
                pass

            def disconnect(self):
                pass

        bridge = ObserverBridge(config(), FakeIdentity(), start=False)
        client = Client()
        bridge.clients["gomesh"] = client
        bridge.connected["gomesh"] = True
        bridge.close()
        self.assertEqual(len(client.messages), 1)
        self.assertFalse(client.messages[0][1]["online"])
        self.assertTrue(client.messages[0][3])


if __name__ == "__main__":
    unittest.main()
