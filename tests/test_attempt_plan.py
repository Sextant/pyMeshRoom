"""Push attempts: ACK timers, the attempt plan, attempt bits in turn, late ACK credit, the push pace's local
samples and the dashboard's push status."""
import os
import pathlib
import sys
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "meshroom"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import meshroom as mr
from test_virtual_companion import Harness

R44, R55, R33 = b"\x44\xc3", b"\x55\xb2", b"\x33\xa1"


class AttemptTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.room = self.h.room
        pub = os.urandom(32)
        m = self.m = mr.Member(pub)
        m.secret = os.urandom(32)
        m.last_activity = m.last_heard = int(time.time())
        self.room.members[pub] = m
        self.r1 = self.room.learn_route(m, 0x41, R44, proven=True)            # 1 hop, good
        self.r1.s, self.r1.n, self.r1.t = 8.0, 9.0, int(time.time())
        self.room.update_current(m)
        self.author = os.urandom(32)

    def tearDown(self):
        self.h.close()

    def post(self, text="hello"):
        self.room.store_post(self.author, text)
        return self.room.max_issued

    def push(self, ts, text="hello"):
        self.room.push_post(self.m, ts, self.author, text)
        return self.m.pending_ack

    def time_out(self):
        self.m.ack_timeout = 0
        self.room.check_ack_timeouts()

    def status(self):
        self.room.publish_web_state()
        x = next(x for x in self.room.web_state["members"] if x["key"] == mr.hexs(self.m.pub[:6]))
        return x["push"], x["retries"]

    def test_ack_waits(self):
        self.assertEqual(mr.ack_wait(None, 300), 30.0)
        self.assertAlmostEqual(mr.ack_wait(0x41, 267), (500 + (267 * 6 + 250) * 2) / 1000.0)
        self.assertEqual(mr.ack_wait(0x41 | 40, 2000), mr.DIRECT_ACK_MAX_S)

    def test_plan_is_top_routes_then_two_floods(self):
        r2 = self.room.learn_route(self.m, 0x42, R55 + R33, proven=True)
        r2.s, r2.n, r2.t = 6.0, 9.0, int(time.time())
        kinds = ["flood" if e["plen"] is None else e["path"] for e in self.room.build_plan(self.m)]
        self.assertEqual(kinds[:2], [R44, R55 + R33])
        self.assertEqual(kinds[-2:], ["flood", "flood"])
        self.assertEqual(kinds.count(R44), 1)
        self.assertLessEqual(len(kinds), mr.PLAN_ROUTES + mr.PLAN_FLOODS)
        retry = ["flood" if e["plen"] is None else e["path"] for e in self.room.build_plan(self.m, retry=True)]
        self.assertEqual(retry, [R44, "flood", "flood"])

    def test_attempt_bits_and_late_acks(self):
        ts = self.post()
        acks = []
        for _ in range(5):
            acks.append(self.push(ts))
            self.time_out()
        self.assertEqual(len(set(acks[:4])), 4, "4 attempts, 4 different ACKs")
        self.assertEqual(acks[4], acks[0], "the 5th reuses the 1st's")
        self.assertEqual(sum(1 for r in self.m.ack_map.values() if r["post"] == ts), 4)
        self.room.process_ack(acks[1])                              # attempt 2's late ACK: delivered
        self.assertTrue(self.m.push_delivered)
        self.assertEqual(self.m.sync_since, ts)
        delivered, late = self.room.stats["delivered"], self.room.stats["late_acks"]
        self.room.process_ack(acks[2])                              # another attempt got through too
        self.assertEqual(self.room.stats["delivered"], delivered, "delivery counted once")
        self.assertEqual(self.room.stats["late_acks"], late + 1, "its route is credited")
        self.room.process_ack(acks[2])
        self.assertEqual(self.room.stats["late_acks"], late + 1, "the same ACK again: counted once")
        for r in self.m.ack_map.values():
            r["until"] = 0
        self.room.check_ack_timeouts()
        self.assertEqual(self.m.ack_map, {})

    def test_late_ack_corrects_its_pace_sample(self):
        ts = self.post()
        ack = self.push(ts)
        sample = self.m.pace_sample
        self.assertIsNotNone(sample, "first attempt over 1 hop: counted toward the pace")
        self.time_out()
        self.assertIs(sample["ok"], False)
        self.room.process_ack(ack)
        self.assertIs(sample["ok"], True)

    def test_pace_ignores_routes_over_two_hops(self):
        self.m.routes.clear()
        r3 = self.room.learn_route(self.m, 0x43, R44 + R55 + R33, proven=True)
        r3.s, r3.n, r3.t = 30.0, 30.0, int(time.time())
        self.room.update_current(self.m)
        self.room.mrpts.pop(self.m.pub[:8], None)
        self.push(self.post())
        self.assertEqual(self.m.inflight["path"], R44 + R55 + R33)
        self.assertIsNone(self.m.pace_sample)

    def test_private_message_second_ack_counts_once(self):
        self.room.store_post(self.author, "psst", to=self.m.pub)
        ts = self.room.max_issued
        a1 = self.push(ts, "psst")
        self.time_out()
        a2 = self.push(ts, "psst")
        self.room.process_ack(a2)
        delivered = self.room.stats["delivered"]
        self.room.process_ack(a1)                                   # (a private message doesn't move sync_since)
        self.assertEqual(self.room.stats["delivered"], delivered)

    def test_push_status(self):
        self.m.sync_since = self.room.max_issued
        self.assertEqual(self.status()[0], "synced")
        ts = self.post()
        self.assertEqual(self.status()[0], "queued")
        self.push(ts)
        self.assertEqual(self.status()[0], "sent")
        self.time_out()
        self.push(ts)
        self.assertEqual(self.status(), ("retry", 1))
        self.time_out()
        self.push(ts)
        self.assertEqual(self.status(), ("retry", 2))
        self.room.process_ack(self.m.pending_ack)
        self.assertEqual(self.status()[0], "synced")


if __name__ == "__main__":
    unittest.main()
