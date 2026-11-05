import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "meshroom"))
import meshroom as mr
from test_virtual_companion import Harness


class RepeaterMapTests(unittest.TestCase):
    """The dashboard map leaves out repeaters that haven't been heard for MAP_MAX_AGE_S (72 hours)."""

    def setUp(self):
        self.h = Harness(lat=36.6, lon=-121.9)

    def tearDown(self):
        self.h.close()

    def add(self, pub, last, lat, lon):
        room = self.h.room
        room.repeaters[pub] = dict(name="R" + pub[:2].hex(), lat=lat, lon=lon, adv_ts=0, last_advert=last)
        room.heard[pub[:2]] = dict(last=last, w=1.0, t=last, last_direct=last, snr=5.0, disc=0, out_snr=None)
        room._rpt_idx = None

    def test_repeaters_not_heard_for_72_hours_are_left_off_the_map(self):
        now = mr.now_s()
        fresh, old, edge = b"\x11\x22" + b"\x01" * 30, b"\x33\x44" + b"\x02" * 30, b"\x55\x66" + b"\x03" * 30
        self.add(fresh, now - 3600, 36.7, -121.8)                     # heard an hour ago
        self.add(old, now - mr.MAP_MAX_AGE_S - 3600, 40.0, -100.0)    # last heard 73 hours ago, far away
        self.add(edge, now - mr.MAP_MAX_AGE_S + 60, 36.5, -121.7)     # just inside 72 hours
        room = self.h.room
        room.edges[(old[:2], b"")] = [5.0, now, None]
        room.edges[(fresh[:2], b"")] = [5.0, now, None]
        room.publish_map()
        rpts = {r["hash"]: r for r in room.web_map["repeaters"]}
        self.assertTrue(rpts[mr.hexs(fresh[:2])]["on_map"])
        self.assertTrue(rpts[mr.hexs(edge[:2])]["on_map"])
        old_row = rpts.get(mr.hexs(old[:2]))
        self.assertTrue(old_row is None or old_row["on_map"] is False)
        drawn = {e["a"] for e in room.web_map["edges"]}
        self.assertIn(mr.hexs(fresh[:2]), drawn)
        self.assertNotIn(mr.hexs(old[:2]), drawn)                     # no links to it either


if __name__ == "__main__":
    unittest.main()
