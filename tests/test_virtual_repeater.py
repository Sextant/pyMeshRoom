import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "meshroom"))
from meshroom import DEFAULTS, RepeaterIdentity, repeater_changes


class VirtualRepeaterTests(unittest.TestCase):
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

