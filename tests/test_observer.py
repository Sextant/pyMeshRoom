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
