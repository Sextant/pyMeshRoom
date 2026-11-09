"""Antenna test tool (tools/antenna_test): discovery, trace scoring and the web UI, against simulated repeaters."""
import json
import pathlib
import queue
import random
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools" / "antenna_test"))
import antenna_test as at  # noqa: E402

mr = at.mr


class FakeRadio:
    """Repeaters around us: pub key -> (chance a trace comes back, TX SNR, RX SNR). Some may miss discovery."""

    settings = "test radio"

    def __init__(self, repeaters, deaf=()):
        self.repeaters = repeaters
        self.deaf = set(deaf)                                # never answer discovery
        self.rx = queue.Queue()
        self.sent = []
        self.rng = random.Random(1)

    def recv(self, timeout):
        try:
            return self.rx.get(timeout=timeout)
        except queue.Empty:
            return None

    def _later(self, raw, snr):
        threading.Timer(0.01, lambda: self.rx.put((raw, snr, -90))).start()

    def send(self, raw):
        pkt = mr.Packet.parse(raw)
        self.sent.append(pkt.ptype)
        assert pkt.route_type == mr.ROUTE_DIRECT and pkt.path_len == 0
        if pkt.ptype == mr.PT_CONTROL:
            tag = pkt.payload[2:6]
            for pub, (_, tx, rx) in self.repeaters.items():
                if pub in self.deaf:
                    continue
                rep = mr.Packet(mr.PT_CONTROL, bytes([0x90 | mr.ADV_TYPE_REPEATER]) + struct.pack("b", int(tx * 4)) + tag + pub)
                rep.header = (rep.header & ~0x03) | mr.ROUTE_DIRECT
                self._later(rep.encode(), rx)
        elif pkt.ptype == mr.PT_TRACE:
            h = pkt.payload[9:11]
            for pub, (p, tx, rx) in self.repeaters.items():
                if pub[:2] == h and self.rng.random() < p:
                    rep = mr.Packet(mr.PT_TRACE, pkt.payload)
                    rep.header = pkt.header
                    rep.path, rep.path_len = struct.pack("b", int(tx * 4)), 1
                    self._later(rep.encode(), rx)


def pub(n):
    return bytes([n, n]) + bytes(30)


def wait_done(test, limit=20):
    end = time.time() + limit
    while time.time() < end:
        if test.state()["phase"] in ("done", "error"):
            return
        time.sleep(0.02)
    raise AssertionError("test did not finish")


class AntennaTestTests(unittest.TestCase):
    def make(self, radio, **kw):
        args = dict(discover_s=0.15, discover_every_s=0.05, rounds=20, interval_s=0.0, trace_timeout_s=0.1, grace_s=0.05)
        args.update(kw)
        return at.AntennaTest(radio, **args)

    def test_scores_sum_across_repeaters(self):
        radio = FakeRadio({pub(1): (1.0, 6.0, 8.5), pub(2): (1.0, -3.0, -1.0), pub(3): (0.0, 0, 0)})
        t = self.make(radio)
        self.assertTrue(t.start())
        self.assertFalse(t.start())                          # one run at a time
        wait_done(t)
        s = t.state()
        self.assertEqual(s["phase"], "done")
        self.assertEqual(s["discovered"], 3)
        self.assertEqual(s["total"], 2.0)                    # two always answered; the silent one isn't listed
        self.assertEqual([r["id"] for r in s["repeaters"]], ["0101", "0202"])
        r1 = s["repeaters"][0]
        self.assertEqual((r1["tx_snr"], r1["rx_snr"], r1["ok"], r1["sent"], r1["success"], r1["score"]), (6.0, 8.5, 20, 20, 1.0, 1.0))
        self.assertEqual(radio.sent.count(mr.PT_TRACE), 60)

    def test_partial_answers_score_point_05_each(self):
        radio = FakeRadio({pub(n): (0.5, 1.0, 2.0) for n in range(1, 6)})
        t = self.make(radio)
        t.start()
        wait_done(t)
        s = t.state()
        for r in s["repeaters"]:
            self.assertAlmostEqual(r["score"], r["ok"] * 0.05)
        self.assertAlmostEqual(s["total"], sum(r["ok"] for r in s["repeaters"]) * 0.05, places=2)
        self.assertTrue(1.0 < s["total"] < 4.0)

    def test_only_discovered_repeaters_are_traced(self):
        radio = FakeRadio({pub(1): (1.0, 1, 1), pub(2): (1.0, 1, 1)}, deaf={pub(2)})
        t = self.make(radio, rounds=3)
        t.start()
        wait_done(t)
        s = t.state()
        self.assertEqual([r["id"] for r in s["repeaters"]], ["0101"])
        self.assertEqual(s["total"], round(3 / 3.0, 2))
        self.assertTrue(any("FINAL SCORE 1.00" in c["text"] for c in s["console"]))

    def test_no_repeaters(self):
        t = self.make(FakeRadio({}))
        t.start()
        wait_done(t)
        s = t.state()
        self.assertEqual((s["phase"], s["total"], s["repeaters"]), ("done", 0, []))

    def test_web_ui_start_and_state(self):
        with tempfile.TemporaryDirectory() as d:
            t = self.make(FakeRadio({pub(7): (1.0, 2.5, 4.0)}), rounds=2, results_dir=d)
            srv = at.serve(t, "127.0.0.1", 0)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            base = "http://127.0.0.1:%d/" % srv.server_address[1]
            try:
                page = urllib.request.urlopen(base).read().decode()
                self.assertIn(">Start</button>", page)
                self.assertIn("Avg TX SNR", page)
                r = urllib.request.urlopen(urllib.request.Request(base + "api/start", method="POST"))
                self.assertEqual(r.status, 200)
                wait_done(t)
                s = json.loads(urllib.request.urlopen(base + "api/state").read())
                self.assertEqual(s["total"], 1.0)
                self.assertEqual(s["repeaters"][0]["tx_snr"], 2.5)
                seq = s["seq"]
                s2 = json.loads(urllib.request.urlopen(base + "api/state?since=%d" % seq).read())
                self.assertEqual(s2["console"], [])            # console is fetched incrementally
                saved = list(pathlib.Path(d).glob("antenna_test_*.json"))
                self.assertEqual(len(saved), 1)
                self.assertEqual(json.loads(saved[0].read_text())["total"], 1.0)
            finally:
                srv.shutdown()
                srv.server_close()

    def test_trace_packet_format(self):
        pkt = mr.Packet.parse(at.trace_packet(b"\x01\x02\x03\x04", b"\xab\xcd"))
        self.assertEqual(pkt.ptype, mr.PT_TRACE)
        self.assertEqual(pkt.payload, b"\x01\x02\x03\x04" + bytes(4) + b"\x01\xab\xcd")   # 2-byte route entries
        d = mr.Packet.parse(at.discovery_packet(b"\x09\x08\x07\x06"))
        self.assertEqual(d.payload[:6], bytes([0x80, 1 << mr.ADV_TYPE_REPEATER]) + b"\x09\x08\x07\x06")


if __name__ == "__main__":
    unittest.main()
