import pathlib
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "meshroom"))
from meshroom import DEFAULTS, Packet, PT_ADVERT, VirtualRepeater, repeater_changes


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
        self.assertFalse(DEFAULTS["repeater_enabled"])
        self.assertEqual(DEFAULTS["repeater_key"], "")

    def test_identity_is_deterministic_and_not_the_room_identity(self):
        first = RepeaterIdentity(bytes(range(32)))
        second = RepeaterIdentity(bytes(range(32)))
        self.assertEqual(first.pub_key, second.pub_key)
        self.assertEqual(len(first.pub_key), 32)

    def test_key_validation_rejects_wrong_lengths(self):
        with self.assertRaises(ValueError):
            RepeaterIdentity(b"x" * 31)

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
        relay = self.relay()
        packet = Packet(PT_ADVERT, b"x" * 100)
        packet.path_len = 1
        packet.path = b"R"
        self.assertTrue(relay.looped(packet))
