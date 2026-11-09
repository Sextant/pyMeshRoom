"""KaaS: API keys (hashed), the websocket stream, clients' sends (checks, rate limit, airtime cap, priority), the
dashboard's key endpoints, and the Python client in client/ talking to a real room over a real websocket."""
import io
import json
import os
import pathlib
import socket
import sys
import threading
import time
import unittest
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "meshroom"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "client"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import meshroom as mr
from meshroom import Packet
from test_virtual_companion import Harness

import meshroom_kaas as kc


class FakeConn:
    def __init__(self, key, receive=True, send=True):
        self.key_id, self.can_receive, self.can_send = key, receive, send
        self.web = None
        self.closed, self.inflight, self.msgs = False, 1, []
        self.cv = threading.Lock()

    def put(self, text):
        self.msgs.append(json.loads(text))

    def send_json(self, obj):
        self.msgs.append(obj)

    def close(self, code=1000, reason=""):
        self.closed = (code, reason)

    def results(self):
        return [m for m in self.msgs if m["type"] == "send_result"]


def flood(ptype, payload):
    p = Packet(ptype, payload)
    p.header |= mr.ROUTE_FLOOD
    return p.encode()


class KeyAndFrameTests(unittest.TestCase):
    def test_key_spec(self):
        spec = mr.kaas_key_spec({"receive": True, "send": False, "description": " bot ", "expires": None})
        self.assertEqual(spec, dict(receive=True, send=False, description="bot", expires=None))
        for bad in ({"receive": False, "send": False}, {"receive": "yes", "send": True}, {"receive": True, "send": True, "expires": 5},
                    {"receive": True, "send": True, "description": "x" * 81}):
            with self.assertRaises(ValueError):
                mr.kaas_key_spec(bad)

    def test_only_a_hash_is_kept(self):
        h = Harness()
        try:
            hub = h.room.kaas
            token, entry = hub.new_key(mr.kaas_key_spec({"receive": True, "send": True}))
            self.assertTrue(token.startswith("kaas_"))
            self.assertNotIn(token, json.dumps(entry))
            hub.event(("kaas_key_add", entry))
            with open(h.cfg.path) as f:
                self.assertNotIn(token, f.read())
            self.assertEqual(hub.find(token)["id"], entry["id"])
            self.assertIsNone(hub.find(token + "x"))
            self.assertIsNone(hub.find("nope"))
        finally:
            h.close()

    def test_websocket_frames_round_trip(self):
        for n in (0, 5, 125, 126, 300, 70000):
            data = os.urandom(n)
            op, got = mr.ws_read(io.BytesIO(mr.ws_frame(2, data, mask=True)), 1 << 20)
            self.assertEqual((op, got), (2, data))
        with self.assertRaises(ValueError):
            mr.ws_read(io.BytesIO(mr.ws_frame(1, b"x")), 100)               # clients must mask
        with self.assertRaises(ValueError):
            mr.ws_read(io.BytesIO(mr.ws_frame(1, bytes(200), mask=True)), 100)
        parts = io.BytesIO(bytes([0x01, 0x82]) + bytes(4) + b"ab" + mr.ws_frame(9, b"p", mask=True) + bytes([0x80, 0x81]) + bytes(4) + b"c")
        ctl = []
        self.assertEqual(mr.ws_read(parts, 100, on_control=lambda op, d: ctl.append(op)), (1, b"abc"))
        self.assertEqual(ctl, [9])


class SendTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness(kaas_send_burst=3, kaas_send_window_s=20)
        self.hub = self.h.room.kaas
        _, self.key = self.hub.new_key(mr.kaas_key_spec({"receive": True, "send": True}))
        self.hub.event(("kaas_key_add", self.key))
        self.conn = FakeConn(self.key["id"])

    def tearDown(self):
        self.h.close()

    def send(self, raw):
        self.conn.inflight += 1
        self.hub.send(self.conn, raw, len(self.conn.msgs))
        return self.conn.results()[-1]

    def test_checks_and_rate_limit(self):
        self.assertEqual(self.send(b"\x01")["reason"], "not a valid MeshCore packet")
        advert = self.h.room.make_advert()
        advert.header |= mr.ROUTE_FLOOD
        self.assertIn("node on this radio", self.send(advert.encode())["reason"])
        for _ in range(3):                                  # a burst of 3...
            self.assertEqual(self.send(flood(mr.PT_GRP_TXT, os.urandom(40)))["status"], "queued")
        r = self.send(flood(mr.PT_GRP_TXT, os.urandom(40)))   # ...then nothing until the first leaves the 20 s window
        self.assertEqual(r["status"], "dropped")
        self.assertIn("rate limit", r["reason"])
        self.assertGreater(r["retry_after"], 19)
        self.hub.last_send[self.key["id"]][0] -= 20.0
        self.assertEqual(self.send(flood(mr.PT_GRP_TXT, os.urandom(40)))["status"], "queued")
        for _ in range(3):                                  # ACKs and path returns: no limit
            self.assertEqual(self.send(flood(mr.PT_ACK, os.urandom(4)))["status"], "queued")
        self.assertEqual(self.send(flood(mr.PT_PATH, os.urandom(40)))["status"], "queued")

    def test_held_by_the_airtime_limits_too_long(self):
        """Users' packets come out of their share of airtime; one that has to wait too long is dropped, and the
        client is told."""
        air = self.h.room.air
        air.refill()
        air.pool, air.own["kaas"] = -1e9, -1e9                  # (spent, for a long while)
        old = dict(mr.TX_STALE_S)
        mr.TX_STALE_S["kaas"] = 0.3
        try:
            self.assertEqual(self.send(flood(mr.PT_ACK, os.urandom(4)))["status"], "queued")
            self.assertTrue(self.h.pump(lambda: self.conn.results()[-1]["status"] != "queued", 5))
        finally:
            mr.TX_STALE_S.update(old)
        r = self.conn.results()[-1]
        self.assertEqual(r["status"], "dropped")
        self.assertIn("airtime", r["reason"])
        self.assertEqual(air.dropped["kaas"], 1)
        self.assertFalse(self.h.room.txq)

    def test_revoked_or_expired_key(self):
        self.hub.conns = [self.conn]
        self.hub.event(("kaas_key_del", self.key["id"]))
        self.assertEqual(self.conn.closed, (4001, "key revoked"))
        self.conn = FakeConn(self.key["id"])                # (a send that was already on its way)
        self.assertEqual(self.send(flood(mr.PT_ACK, os.urandom(4)))["reason"], "key revoked or expired")
        _, k2 = self.hub.new_key(mr.kaas_key_spec({"receive": True, "send": True, "expires": time.time() + 60}))
        self.hub.event(("kaas_key_add", k2))
        self.h.cfg.set("kaas_keys", [dict(k2, expires=int(time.time()) - 1)])
        c2 = FakeConn(k2["id"])
        self.hub.conns = [c2]
        self.hub.periodic()
        self.assertEqual(c2.closed, (4002, "key expired"))

    def test_sent_after_everything_else_and_streamed(self):
        room = self.h.room
        reader, writer = FakeConn("r", send=False), FakeConn("w", receive=False)
        self.hub.conns = [reader, writer, self.conn]
        self.send(flood(mr.PT_GRP_TXT, os.urandom(40)))
        room.send_flood(room.make_ack(os.urandom(4)))       # the room's own, queued after it
        room.tx_busy_until = 0
        room.service_tx()
        self.assertEqual(Packet.parse(self.h.modem.sent[-1]).ptype, mr.PT_ACK, "the room's packet goes first")
        room.tx_busy_until = 0
        room.service_tx()
        self.assertEqual(Packet.parse(self.h.modem.sent[-1]).ptype, mr.PT_GRP_TXT)
        self.assertEqual(self.conn.results()[-1]["status"], "sent")
        self.assertEqual([m["ptype"] for m in reader.msgs], ["ack", "grp_txt"])
        self.assertEqual(reader.msgs[0]["dir"], "tx")
        self.assertEqual(writer.msgs, [], "can't receive: no stream")
        room.on_rx(flood(mr.PT_ADVERT, os.urandom(120)), 7.5, -88)
        self.assertEqual((reader.msgs[-1]["dir"], reader.msgs[-1]["snr"], reader.msgs[-1]["rssi"]), ("rx", 7.5, -88))


class KeyStatsTests(unittest.TestCase):
    def test_counts_per_key_24h_and_total_and_saved(self):
        h = Harness()
        try:
            hub = h.room.kaas
            _, key = hub.new_key(mr.kaas_key_spec({"receive": True, "send": True}))
            hub.event(("kaas_key_add", key))
            conn = mr.KaasConn(hub, None, None, key, "test")
            hub.conns = [conn]
            for _ in range(3):
                hub.publish("rx", flood(mr.PT_ADVERT, os.urandom(120)), 5.0, -90)
            conn.inflight = 2
            hub.send(conn, flood(mr.PT_GRP_TXT, os.urandom(40)), 1)       # accepted: sent
            hub.send(conn, b"\x01", 2)                                    # refused: an error
            hub.on_message(conn, {"type": "bogus"})                       # an error
            self.assertEqual(hub.key_stats(key["id"]), {"rx": [3, 3], "tx": [1, 1], "err": [2, 2]})
            old = int(time.time() // 3600) - 30                           # a day and more ago: total only
            hub.kstats[key["id"]]["hours"][old] = [10, 0, 0]
            hub.kstats[key["id"]]["total"][0] += 10
            self.assertEqual(hub.key_stats(key["id"])["rx"], [3, 13])
            row = hub.key_rows()[0]
            self.assertEqual(row["stats"]["err"], [2, 2])
            hub.save_stats()
            again = mr.KaasHub(h.room)
            self.assertEqual(again.key_stats(key["id"]), {"rx": [3, 13], "tx": [1, 1], "err": [2, 2]})
            self.assertNotIn(old, again.kstats[key["id"]]["hours"], "old hours are pruned when saved")
            hub.event(("kaas_key_del", key["id"]))
            self.assertNotIn(key["id"], hub.kstats, "a revoked key's stats go with it")
        finally:
            h.close()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class WebTestCase(unittest.TestCase):
    """A room on a fake radio with its dashboard on a free port: the key endpoints and a real websocket."""

    def setUp(self):
        self.port = free_port()
        self.h = Harness(web_password="adminpw", room_password="hello", kaas_send_window_s=0.5,
                         push_quiet_ms=0, push_pace_start_ms=300, push_pace_min_ms=300)
        self.h.cfg.set("web_port", self.port)
        self.h.cfg.set("web_bind", "127.0.0.1")
        self.web = mr.WebUI(self.h.room, self.h.events)
        self.base = "http://127.0.0.1:%d" % self.port
        self.url = "ws://127.0.0.1:%d/api/v1/kaas" % self.port
        self.cookie = None

    def tearDown(self):
        self.h.room.kaas.close_all()
        self.web.server.shutdown()
        self.web.server.server_close()
        self.h.close()

    def http(self, method, path, body=None):
        req = urllib.request.Request(self.base + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", **({"Cookie": self.cookie} if self.cookie else {})})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                if r.headers.get("Set-Cookie"):
                    self.cookie = r.headers["Set-Cookie"].split(";")[0]
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def make_key(self, receive=True, send=True):
        code, d = self.http("POST", "/api/v1/kaas/keys", {"receive": receive, "send": send, "description": "test"})
        self.assertEqual(code, 200, d)
        self.h.pump(lambda: self.h.room.kaas.find(d["token"]) is not None, 5)
        return d["token"]


class EndToEndTests(WebTestCase):
    """The dashboard's key endpoints and the Python client, over a real websocket."""

    def test_keys_need_the_admin(self):
        self.assertEqual(self.http("GET", "/api/v1/kaas/keys")[0], 401)
        self.assertEqual(self.http("POST", "/api/v1/kaas/keys", {"receive": True, "send": True})[0], 401)
        self.http("POST", "/api/login", {"password": "adminpw"})
        token = self.make_key(receive=True, send=False)
        code, d = self.http("GET", "/api/v1/kaas/keys")
        self.assertEqual(code, 200)
        self.assertEqual([(k["receive"], k["send"], k["description"]) for k in d["keys"]], [(True, False, "test")])
        self.assertNotIn(token, json.dumps(d))
        with self.assertRaises(kc.HandshakeError) as e:
            kc.KaasClient(self.url, "kaas_wrong").connect()
        self.assertEqual(e.exception.status, "401")

    def test_api_keys_get_no_browser_ticket(self):
        """Browsers log in by signing (test_web_login): an API key is for bots, with Authorization: Bearer."""
        self.http("POST", "/api/login", {"password": "adminpw"})
        token = self.make_key()
        req = urllib.request.Request(self.base + "/api/v1/kaas/ticket", method="POST", data=b"",
                                     headers={"Authorization": "Bearer " + token})
        with self.assertRaises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, timeout=10)
        self.assertIn(e.exception.code, (401, 404))                   # (no such endpoint: the dashboard's login)
        with self.assertRaises(kc.HandshakeError):
            kc.ws.WebSocket.connect(self.url + "?ticket=kt_made_up", {}, 10)
        hello = self.h.run_client(kc.KaasClient(self.url, token).connect)
        self.assertEqual(hello["type"], "hello")

    def test_stream_then_revoke(self):
        self.http("POST", "/api/login", {"password": "adminpw"})
        token = self.make_key(receive=True, send=False)
        r = self.h.add_room("Surf")
        c = kc.KaasClient(self.url, token)
        hello = self.h.run_client(c.connect)
        self.assertIsNone(hello["nodes"]["room"])                       # the server is the host: its rooms are Rooms
        self.assertEqual(hello["nodes"]["tenants"], [mr.hexs(r.id.pub_key)])
        self.assertEqual(hello["names"], {mr.hexs(r.id.pub_key): "Surf"})
        self.assertFalse(hello["key"]["send"])
        got = []
        c.on_packet(got.append)
        raw = flood(mr.PT_GRP_TXT, os.urandom(40))
        self.h.events.put(("rxraw", raw))
        self.assertTrue(self.h.pump(lambda: got, 10))
        self.assertEqual((got[0].encode(), got[0].dir, got[0].snr), (raw, "rx", 6.0))
        res = self.h.run_client(lambda: c.send(raw))
        self.assertEqual((res.status, res["reason"]), ("dropped", "this key can't send"))
        kid = self.h.room.kaas.find(token)["id"]
        self.assertEqual(self.http("POST", "/api/v1/kaas/keys/%s/revoke" % kid, {})[0], 200)
        self.assertTrue(self.h.pump(lambda: c.closed.is_set(), 10))
        self.assertEqual(c.close_reason.code, 4001)
        with self.assertRaises(kc.HandshakeError):
            kc.KaasClient(self.url, token).connect()

    def test_bot_joins_the_room_posts_and_dms(self):
        self.http("POST", "/api/login", {"password": "adminpw"})
        token = self.make_key()
        a_client, b_client = kc.KaasClient(self.url, token), kc.KaasClient(self.url, token)
        self.h.run_client(a_client.connect)
        self.h.run_client(b_client.connect)
        a = kc.Node(a_client, kc.Identity.generate(), "BotA")
        b = kc.Node(b_client, kc.Identity.generate(), "BotB")
        r = self.h.add_room()
        room_pub = r.id.pub_key
        posts, dms = [], []

        def join():
            with self.assertRaises(kc.LoginFailed):
                a.join_room(room_pub, "wrong", timeout=3)
            return a.join_room(room_pub, "hello")
        room = self.h.run_client(join)
        self.assertTrue(room.logged_in)
        self.assertIn(a.id.pub, r.members)
        room.on_post(lambda rm, author, text, ts: posts.append(text))
        self.h.events.put(("t_say", r.key, "welcome bots"))
        self.assertTrue(self.h.pump(lambda: "welcome bots" in posts, 30), posts)
        m = r.members[a.id.pub]
        self.assertTrue(self.h.pump(lambda: m.sync_since >= r.max_issued, 15), "the room got the bot's ACK")
        self.assertTrue(self.h.run_client(lambda: room.post("hi from a bot")))
        self.assertIn("hi from a bot", [p[2] for p in r.posts])
        # two bots on the same radio: an advert, then a DM and its ACK, through the air both ways
        b.on_dm(lambda c, text, ts: dms.append((c.pub, text)))
        self.h.run_client(lambda: a.advert(flood=True))
        self.assertTrue(self.h.pump(lambda: b.find("BotA") is not None, 10))
        self.assertTrue(self.h.run_client(lambda: a.send_dm(b.id.pub, "psst")))
        self.assertTrue(self.h.pump(lambda: dms, 10))
        self.assertEqual(dms, [(a.id.pub, "psst")])
        # channels
        heard = []
        b.on_channel(lambda ch, who, text, ts: heard.append((ch.name, who, text)))
        b.add_channel("#bots")
        res = self.h.run_client(lambda: a.send_channel(a.add_channel("#bots"), "beep"))
        self.assertTrue(self.h.pump(lambda: heard, 10), res)
        self.assertEqual(heard, [("#bots", "BotA", "beep")])
        a_client.close()
        b_client.close()


class RouteQueryTests(WebTestCase):
    def test_near_and_routes(self):
        room = self.h.room
        node = os.urandom(32)
        a, b = bytes.fromhex("44c3"), bytes.fromhex("55b2")
        for _ in range(3):
            room.observe_near(node, a)
        room.observe_near(node, b)
        room.observe_near(node, b"")
        room.repeaters[a + os.urandom(30)] = dict(name="Seaside", lat=0, lon=0, adv_ts=0, last_advert=1)
        room.build_rpt_index()
        rr = mr.RptRoute(0x42, b + a, mr.now_s())
        rr.w = 5.0
        room.rroutes[a] = {(0x42, b + a): rr}
        self.http("POST", "/api/login", {"password": "adminpw"})
        token = self.make_key(receive=False, send=True)        # any key may ask
        c = kc.KaasClient(self.url, token)
        self.h.run_client(c.connect)
        near = self.h.run_client(lambda: c.near(node.hex()))
        self.assertEqual([(x.get("id"), x.get("name"), x.get("direct", False)) for x in near],
                         [("44c3", "Seaside", False), ("55b2", None, False), (room.id.pub_key[:2].hex(), room.cfg.name, True)])
        self.assertAlmostEqual(near[0]["share"], 0.6, places=2)
        self.assertEqual(len(self.h.run_client(lambda: c.near(node, limit=1))), 1)
        routes = self.h.run_client(lambda: c.routes("44c3"))
        self.assertEqual(len(routes), 1)
        self.assertEqual((routes[0]["path_len"], routes[0]["hops"], routes[0]["names"]), (0x42, ["55b2", "44c3"], [None, "Seaside"]))
        self.assertEqual(bytes.fromhex(routes[0]["path"]), b + a)
        self.assertEqual(self.h.run_client(lambda: c.routes("99aa")), [])
        with self.assertRaises(kc.RequestError):
            self.h.run_client(lambda: c.near("abcd"))
        room.learn_name(os.urandom(32), 5, "Platinum")         # an older namesake nobody routes through
        room.learn_name(node, 10, "Platinum")
        for name in ("@[platinum]", "platinum", " @[ PLATINUM ] "):
            self.assertEqual(self.h.run_client(lambda: c.near(name)), near)
        with self.assertRaises(kc.RequestError):
            self.h.run_client(lambda: c.near("@[nobody]"))
        c.close()

    def test_paths_from_this_radio(self):
        """Direct paths to a node: built from the repeaters that hear it, and measured ones when it's a member."""
        room = self.h.room
        node = os.urandom(32)
        a, b = bytes.fromhex("44c3"), bytes.fromhex("55b2")
        for _ in range(4):
            room.observe_near(node, a)
        rr = mr.RptRoute(0x42, b + a, mr.now_s())
        rr.w = 5.0
        room.rroutes[a] = {(0x42, b + a): rr}
        self.http("POST", "/api/login", {"password": "adminpw"})
        c = kc.KaasClient(self.url, self.make_key(receive=False, send=True))
        self.h.run_client(c.connect)
        built = self.h.run_client(lambda: c.paths(node))
        self.assertEqual([(p["path_len"], p["hops"], p["source"]) for p in built], [(0x42, ["55b2", "44c3"], "map")])
        m = room.put_member(node)                                       # delivered to before, along another route
        for _ in range(5):
            room.learn_route(m, 0x41, bytes.fromhex("66a1"), proven=True)
        measured = self.h.run_client(lambda: c.paths(node))
        self.assertIn(("66a1", "measured"), [(p["path"], p["source"]) for p in measured])
        self.assertEqual(self.h.run_client(lambda: c.paths(os.urandom(32))), [])     # never heard: nothing to suggest
        with self.assertRaises(kc.RequestError):
            self.h.run_client(lambda: c.paths("abcd"))
        c.close()


class RouteSuggestTests(WebTestCase):
    def test_route_between_two_nodes(self):
        room = self.h.room
        A, B, C, D, E = (bytes.fromhex(x) for x in ("a1a1", "b2b2", "c3c3", "d4d4", "e5e5"))
        src, dst = os.urandom(32), os.urandom(32)
        room.observe_near(src, A)
        room.observe_near(dst, D)
        room.learn_name(dst, 10, "Platinum")
        now = mr.now_s()
        room.edges.update({(A, B): [3.0, now, 5.0], (B, D): [3.0, now, 5.0],     # strong, both ways seen
                           (A, C): [1.0, now, -12.0], (C, D): [1.0, now, None],  # weak, low SNR
                           (E, D): [3.0, now, None]})                            # A -> E never seen
        room.edges[(B, A)] = [3.0, now, None]
        room.repeaters[B + os.urandom(30)] = dict(name="Seaside", lat=0, lon=0, adv_ts=0, last_advert=1)
        room.build_rpt_index()
        self.http("POST", "/api/login", {"password": "adminpw"})
        c = kc.KaasClient(self.url, self.make_key(receive=False, send=True))
        self.h.run_client(c.connect)
        res = self.h.run_client(lambda: c.route(src, "@[platinum]"))
        self.assertEqual(res["to"], {"node": dst[:8].hex(), "name": "Platinum"})
        routes = res["routes"]
        self.assertEqual([r["hops"] for r in routes], [["a1a1", "b2b2", "d4d4"], ["a1a1", "c3c3", "d4d4"]])
        self.assertEqual(routes[0]["names"], [None, "Seaside", None])
        self.assertEqual((routes[0]["path_len"], routes[0]["path"]), (0x43, "a1a1b2b2d4d4"))
        self.assertGreater(routes[0]["score"], routes[1]["score"])
        self.assertAlmostEqual(routes[0]["score"], ((1 - 0.5 ** 3) * mr.ROUTE_HOP_COST) ** 2, places=2)
        self.assertEqual(len(self.h.run_client(lambda: c.route(src, dst, limit=1))["routes"]), 1)
        # repeater ids work as ends; a link only seen the other way still counts, at half
        res = self.h.run_client(lambda: c.route("d4d4", "a1a1"))
        self.assertEqual(res["routes"][0]["hops"], ["d4d4", "b2b2", "a1a1"])
        self.assertEqual(self.h.run_client(lambda: c.route("a1a1", "a1a1"))["routes"][0]["hops"], ["a1a1"])
        # busy links don't all max out: what counts is how a link compares with its repeater's strongest one
        room.edges.update({(A, B): [400.0, now, None], (A, C): [100.0, now, None], (B, D): [300.0, now, None],
                           (C, D): [300.0, now, None]})
        room._link_graph = None                                   # (edited by hand: the 30 s cache doesn't know)
        busy = self.h.run_client(lambda: c.route("a1a1", "d4d4"))["routes"]
        self.assertEqual([r["hops"] for r in busy], [["a1a1", "b2b2", "d4d4"], ["a1a1", "c3c3", "d4d4"]])
        self.assertAlmostEqual(busy[0]["score"], mr.ROUTE_HOP_COST ** 2, places=2)
        self.assertAlmostEqual(busy[1]["score"], 0.5 * mr.ROUTE_HOP_COST ** 2, places=2)
        for bad in (("@[nobody]", dst), (os.urandom(8), dst), (src, "zz")):
            with self.assertRaises(kc.RequestError):
                self.h.run_client(lambda: c.route(*bad))
        with self.assertRaises(kc.RequestError):
            self.h.run_client(lambda: c.route(src, dst, limit=6))
        c.close()


class ClientIdentityTests(unittest.TestCase):
    def test_identity_matches_the_server(self):
        seed = os.urandom(32)
        ours, theirs = kc.Identity(seed), mr.RepeaterIdentity(seed)
        self.assertEqual(ours.pub, theirs.pub_key)
        self.assertEqual(ours.sign(b"msg"), theirs.sign(b"msg"))
        other = kc.Identity.generate()
        self.assertEqual(ours.shared_secret(other.pub), other.shared_secret(ours.pub))
        self.assertEqual(kc.Identity(ours.private_key.hex()).pub, ours.pub)
        self.assertEqual(kc.hashtag_channel_key("bots"), mr.hashlib.sha256(b"#bots").digest()[:16])


if __name__ == "__main__":
    unittest.main()
