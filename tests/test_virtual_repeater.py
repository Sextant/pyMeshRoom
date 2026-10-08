import pathlib
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "meshroom"))
from meshroom import DEFAULT_CONFIG, Packet, PT_ADVERT, RepeaterIdentity, VirtualRepeater, repeater_changes


class VirtualRepeaterTests(unittest.TestCase):
    def relay(self, **overrides):
        cfg = SimpleNamespace(repeater_relay=True, repeater_airtime_pct=100,
                              repeater_regions=[], repeater_scope_mode="allow",
                              repeater_loop_detect="minimal")
        for key, value in overrides.items():
            setattr(cfg, key, value)
        relay = VirtualRepeater.__new__(VirtualRepeater)
        relay.room = SimpleNamespace(cfg=cfg)
        relay.pub = b"R" * 32
        relay.stats = {"drop_off": 0, "drop_hops": 0, "drop_scope": 0, "drop_loop": 0}
        relay._region_cache = (None, [])
        return relay
    def test_repeater_is_disabled_by_default(self):
        self.assertFalse(DEFAULT_CONFIG["repeater_enabled"])
        self.assertEqual(DEFAULT_CONFIG["repeater_key"], "")
        self.assertEqual(DEFAULT_CONFIG["repeater_name"], "pyMeshRoom Virtual Repeater")

    def test_access_defaults_do_not_grant_administration(self):
        self.assertEqual(DEFAULT_CONFIG["admin_password"], "")
        self.assertEqual(DEFAULT_CONFIG["room_password"], "")
        self.assertEqual(DEFAULT_CONFIG["web_password"], "")

    def test_identity_is_deterministic_and_not_the_room_identity(self):
        first = RepeaterIdentity(bytes(range(32)))
        second = RepeaterIdentity(bytes(range(32)))
        self.assertEqual(first.pub_key, second.pub_key)
        self.assertEqual(len(first.pub_key), 32)

    def test_key_validation_rejects_wrong_lengths(self):
        with self.assertRaises(ValueError):
            RepeaterIdentity(b"x" * 31)

    def test_admin_accepts_a_valid_private_key_without_exposing_it(self):
        key = bytes(range(32)).hex()
        changes = repeater_changes({"private_key": key})
        self.assertEqual(changes, {"repeater_key": key})
        with self.assertRaises(ValueError):
            repeater_changes({"private_key": "not-a-private-key"})

    def test_admin_changes_keep_relay_independent(self):
        changes = repeater_changes({"enabled": False, "relay": True,
                                    "airtime_cap": 25, "loop_detect": "strict"})
        self.assertEqual(changes["repeater_enabled"], False)
        self.assertEqual(changes["repeater_relay"], True)
        self.assertEqual(changes["repeater_airtime_pct"], 25)
        self.assertEqual(changes["repeater_loop_detect"], "strict")

    def test_admin_changes_reject_invalid_scope(self):
        with self.assertRaises(ValueError):
            repeater_changes({"scope_mode": "everywhere"})

    def test_relay_kill_switch_rejects_forwarding(self):
        relay = self.relay(repeater_relay=False)
        self.assertFalse(relay.allow_forward(Packet(PT_ADVERT, b"x" * 100)))
        self.assertEqual(relay.stats["drop_off"], 1)

    def test_loop_detection_rejects_own_path(self):
        relay = self.relay(repeater_loop_detect="strict")
        packet = Packet(PT_ADVERT, b"x" * 100)
        packet.path_len = 1
        packet.path = b"R"
        self.assertTrue(relay.looped(packet))
