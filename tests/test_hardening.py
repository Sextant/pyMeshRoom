"""Hardening from the 2026-10-28 security review: the dashboard never builds script from names, a websocket upgrade
that fails leaves no session behind, web logins are only for this server's own names, and the HTTP service keeps
answering through slow, huge or wrong requests."""
import json
import pathlib
import socket
import struct
import sys
import threading
import time
import types
import unittest
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "meshroom"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "client"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import meshroom as mr
from test_web_login import WebHelpers, channel_msg

import meshroom_kaas as kc


class DashboardTests(unittest.TestCase):
    def test_no_names_inside_inline_script(self):
        """A member's name (from their own advert) is data, never part of an onclick's JavaScript."""
        import re
        handlers = re.findall(r'on[a-z]+="([^"]*)"', mr.DASHBOARD_HTML)
        self.assertTrue(handlers)
        self.assertEqual([h for h in handlers if "esc(" in h or ".name" in h], [])

    def test_escaping_covers_quotes(self):
        i = mr.DASHBOARD_HTML.index("esc=s=>")
        self.assertIn("&#39;", mr.DASHBOARD_HTML[i:i + 200])
        self.assertIn("&#96;", mr.DASHBOARD_HTML[i:i + 200])


class HardeningTests(WebHelpers):
    def raw(self, data, linger=False, read=True):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        s.sendall(data)
        if linger:                                                    # a reset: no FIN, nothing read
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.close()
            return None
        head = s.recv(200).decode(errors="replace") if read else ""
        s.close()
        return head

    def get_ok(self):
        with urllib.request.urlopen(self.base + "/api/state", timeout=10) as r:
            return r.status == 200

    def test_dashboard_headers(self):
        with urllib.request.urlopen(self.base + "/", timeout=10) as r:
            csp, xfo = r.headers.get("Content-Security-Policy", ""), r.headers.get("X-Frame-Options")
        self.assertIn("connect-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual(xfo, "DENY")

    def test_an_upgrade_reset_midway_leaves_no_session(self):
        """Resetting the connection while the server writes its 101 used to keep the session's slot until a restart."""
        self.enable(web_max_clients=4)
        for _ in range(40):
            t = self.login(kc.Identity.generate())[1]["ticket"]
            self.raw(("GET /api/v1/kaas?ticket=%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
                      % (t, self.host)).encode(), linger=True)
        hub = self.h.room.kaas
        self.assertTrue(self.h.pump(lambda: not any(c.web for c in hub.conns), 10), len(hub.conns))
        c = self.connect(self.login(kc.Identity.generate())[1]["ticket"])           # a real user still gets in
        self.assertEqual(c.hello["type"], "hello")
        c.ws.close()

    def test_logins_only_for_this_servers_names(self):
        """A login signed for another name is refused, even with that name as Host (a relay); the admin can allow a
        name the server really goes by, from the refused list."""
        self.enable()
        me = kc.Identity.generate()

        def login_as(host, headers=None):
            code, d = self.post("/api/v1/web/challenge")
            msg = mr.web_login_message(host, d["challenge"], me.pub.hex())
            body = dict(pub=me.pub.hex(), signature=me.sign(msg).hex(), challenge=d["challenge"], host=host)
            return self.post("/api/v1/web/login", body, headers)
        self.assertEqual(login_as(self.host)[0], 200)                               # its own ip:port
        self.assertEqual(login_as("evil.example.net", {"Host": "evil.example.net"})[0], 401)
        self.assertEqual(login_as("mesh.example.com", {"X-Forwarded-Host": "mesh.example.com"})[0], 401)
        users = self.http("GET", "/api/v1/web/users")[1]
        self.assertEqual({r["host"] for r in users["refused_hosts"]}, {"evil.example.net", "mesh.example.com"})
        self.assertEqual(self.http("POST", "/api/v1/web/settings", {"web_hosts": ["Mesh.Example.com"]})[0], 200)
        self.h.pump(lambda: self.h.cfg.web_hosts == ["mesh.example.com"], 5)
        self.assertEqual(login_as("mesh.example.com")[0], 200)
        self.assertEqual(self.http("POST", "/api/v1/web/settings", {"web_hosts": ["<script>"]})[0], 400)

    def test_huge_and_slow_bodies(self):
        """A huge body is refused unread; bodies that never arrive hold their own threads, not the request slots."""
        line = "POST /api/v1/web/challenge HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\n" % self.host
        self.assertIn(" 413 ", self.raw((line + "Content-Length: 1000000000\r\n\r\n").encode()))
        hung = []
        for _ in range(20):
            s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            s.sendall((line + "Content-Length: 100\r\n\r\n").encode())       # ...and the 100 bytes never come
            hung.append(s)
        time.sleep(0.3)
        self.assertTrue(self.get_ok())
        for s in hung:
            s.close()

    def test_wrong_passwords_dont_turn_everyone_away(self):
        """The one-second brake on a wrong password no longer holds a request slot."""
        def wrong():
            req = urllib.request.Request(self.base + "/api/login", data=b'{"password":"nope"}', method="POST",
                                         headers={"Content-Type": "application/json"})
            try:
                urllib.request.urlopen(req, timeout=10)
            except urllib.error.HTTPError:
                pass
        ts = [threading.Thread(target=wrong) for _ in range(24)]
        for t in ts:
            t.start()
        time.sleep(0.4)                                               # (all of them inside their second)
        self.assertTrue(self.get_ok())
        for t in ts:
            t.join()

    def ask(self, c, msg):
        c.ws.send_text(json.dumps(msg))
        got = lambda: next((m for m in c.msgs if m.get("id") == msg["id"]), None)
        self.assertTrue(self.h.pump(lambda: got() is not None, 10), c.msgs)
        return got()

    def test_query_budget(self):
        """Queries are answered by the radio's main loop: each key gets a budget, shared by its connections."""
        self.enable()
        me = kc.Identity.generate()
        c = self.connect(self.login(me)[1]["ticket"])
        self.assertIn("at most 31", self.ask(c, {"type": "nodes", "id": 0, "days": 365})["error"])
        for i in range(1, 4):
            self.assertEqual(self.ask(c, {"type": "nodes", "id": i, "days": 7})["type"], "nodes_result")
        other = self.connect(self.login(me)[1]["ticket"])                         # (the same key, another tab)
        self.assertEqual(self.ask(other, {"type": "nodes", "id": 9, "days": 7})["type"], "nodes_result")
        self.assertIn("at most 4 a minute", self.ask(c, {"type": "nodes", "id": 10, "days": 7})["error"])
        for i in range(11, 41):
            self.ask(c, {"type": "routes", "id": i, "repeater": "a1a1"})
        self.assertIn("at most 30 a minute", self.ask(c, {"type": "routes", "id": 41, "repeater": "a1a1"})["error"])
        fresh = self.connect(self.login(kc.Identity.generate())[1]["ticket"])     # another key: its own budget
        self.assertEqual(self.ask(fresh, {"type": "nodes", "id": 1, "days": 7})["type"], "nodes_result")

    def test_challenges_cant_be_used_up_or_reused(self):
        self.enable()
        for _ in range(600):                                                       # (the old pool held 256)
            code, d = self.post("/api/v1/web/challenge")
        self.assertEqual(code, 200)
        me = kc.Identity.generate()
        msg = mr.web_login_message(self.host, d["challenge"], me.pub.hex())
        body = dict(pub=me.pub.hex(), signature=me.sign(msg).hex(), challenge=d["challenge"], host=self.host)
        self.assertEqual(self.post("/api/v1/web/login", body)[0], 200)
        self.assertIn("used already", self.post("/api/v1/web/login", body)[1]["error"])
        hub = self.h.room.kaas
        forged = d["challenge"][:-4] + ("AAAA" if not d["challenge"].endswith("AAAA") else "BBBB")
        self.assertIsNone(hub.challenge_expiry(forged))
        old = struct.pack(">Q", int(time.time()) - 1) + bytes(12)
        stale = mr.WEB_CHALLENGE_PREFIX + __import__("base64").urlsafe_b64encode(
            old + __import__("hmac").new(hub.challenge_key, old, "sha256").digest()[:16]).rstrip(b"=").decode()
        self.assertIsNone(hub.challenge_expiry(stale))

    def test_tickets_per_key(self):
        self.enable()
        me = kc.Identity.generate()
        codes = [self.login(me)[0] for _ in range(mr.KAAS_TICKETS_PER_KEY + 1)]
        self.assertEqual(codes, [200] * mr.KAAS_TICKETS_PER_KEY + [503])
        self.assertEqual(self.login(kc.Identity.generate())[0], 200)                 # another key isn't affected

    def test_an_address_with_many_failures_is_locked_out(self):
        """Counted per address; behind a proxy (a private address) per the address it forwarded for."""
        def wrong(addr):
            req = urllib.request.Request(self.base + "/api/login", data=b'{"password":"nope"}', method="POST",
                                         headers={"Content-Type": "application/json", "X-Forwarded-For": addr})
            try:
                urllib.request.urlopen(req, timeout=10)
            except urllib.error.HTTPError as e:
                return e.code
        for batch in (mr.FAIL_LIMIT // 2, mr.FAIL_LIMIT - mr.FAIL_LIMIT // 2):    # (under the 16 requests at once,
            ts = [threading.Thread(target=wrong, args=("203.0.113.9",)) for _ in range(batch)]   # so none is "busy")
            for t in ts:
                t.start()
            for t in ts:
                t.join()
        self.assertEqual(wrong("203.0.113.9"), 429)
        self.assertEqual(wrong("198.51.100.7"), 401)                                # someone else behind the proxy

    def test_ban_by_key_address_or_both(self):
        """The ban popup chooses: the key, the address it last logged in from (via the proxy's X-Forwarded-For), or
        both. An address ban refuses everything from that address, whatever key."""
        self.enable()
        def login_from(addr, ident):
            h = {"X-Forwarded-For": addr}
            code, d = self.post("/api/v1/web/challenge", headers=h)
            if code != 200:
                return code
            msg = mr.web_login_message(self.host, d["challenge"], ident.pub.hex())
            return self.post("/api/v1/web/login", dict(pub=ident.pub.hex(), signature=ident.sign(msg).hex(),
                                                       challenge=d["challenge"], host=self.host, name="X"), h)[0]
        hub, a, b = self.h.room.kaas, kc.Identity.generate(), kc.Identity.generate()
        self.assertEqual(login_from("203.0.113.5", a), 200)
        self.assertEqual(login_from("203.0.113.5", b), 200)
        self.assertTrue(self.h.pump(lambda: hub.wusers.get(a.pub.hex(), {}).get("ip") == "203.0.113.5", 5))
        rows = {r["pub"]: r for r in self.http("GET", "/api/v1/web/users")[1]["users"]}
        self.assertEqual((rows[a.pub.hex()]["ip"], rows[a.pub.hex()]["ip_shared"]), ("203.0.113.5", 1))
        # neither: refused
        self.assertEqual(self.http("POST", "/api/v1/web/users/%s/ban" % a.pub.hex(), {"key": False, "ip": False})[0], 400)
        # key only: the address still works for another key
        self.assertEqual(self.http("POST", "/api/v1/web/users/%s/ban" % a.pub.hex(), {"key": True, "ip": False})[0], 200)
        self.assertTrue(self.h.pump(lambda: hub.web_banned(a.pub.hex()), 5))
        self.assertEqual(login_from("203.0.113.5", b), 200)
        # address only: every key from it is refused, other addresses aren't
        self.assertEqual(self.http("POST", "/api/v1/web/users/%s/ban" % b.pub.hex(), {"key": False, "ip": True})[0], 200)
        self.assertTrue(self.h.pump(lambda: hub.web_ip_banned("203.0.113.5"), 5))
        self.assertFalse(hub.web_banned(b.pub.hex()))
        self.assertEqual(login_from("203.0.113.5", kc.Identity.generate()), 403)
        self.assertEqual(login_from("198.51.100.7", b), 200)
        d = self.http("GET", "/api/v1/web/users")[1]
        self.assertEqual([x["ip"] for x in d["banned_ips"]], ["203.0.113.5"])
        self.assertEqual(self.http("POST", "/api/v1/web/ips/not-an-ip/ban")[0], 400)
        self.assertEqual(self.http("POST", "/api/v1/web/ips/203.0.113.5/unban")[0], 200)
        self.assertTrue(self.h.pump(lambda: not hub.web_ip_banned("203.0.113.5"), 5))
        self.assertEqual(login_from("203.0.113.5", b), 200)

    def xff_login(self, addr, ident=None):
        """A web login through a proxy, for the visitor at addr: (status of the challenge or login, ticket)."""
        ident, h = ident or kc.Identity.generate(), {"X-Forwarded-For": addr}
        code, d = self.post("/api/v1/web/challenge", headers=h)
        if code != 200:
            return code, None
        msg = mr.web_login_message(self.host, d["challenge"], ident.pub.hex())
        code, d = self.post("/api/v1/web/login", dict(pub=ident.pub.hex(), signature=ident.sign(msg).hex(),
                                                      challenge=d["challenge"], host=self.host, name="X"), h)
        return code, d.get("ticket")

    def test_logins_per_address(self):
        """A visitor's address may ask for IP_LOGINS_PER_MIN logins a minute; the LAN isn't limited (nor a proxy
        that doesn't say who it forwarded for)."""
        self.enable()
        codes = [self.xff_login("203.0.113.20")[0] for _ in range(mr.IP_LOGINS_PER_MIN + 1)]
        self.assertEqual(codes, [200] * mr.IP_LOGINS_PER_MIN + [429])
        self.assertEqual(self.xff_login("203.0.113.21")[0], 200)                 # someone else
        self.assertEqual({self.xff_login("10.1.2.3")[0] for _ in range(mr.IP_LOGINS_PER_MIN + 2)}, {200})

    def test_web_sessions_and_websockets_per_address(self):
        self.enable()
        addr, h = "203.0.113.30", {"X-Forwarded-For": "203.0.113.30"}
        tickets = [self.xff_login(addr)[1] for _ in range(mr.IP_WEB_SESSIONS + 1)]
        socks = [kc.ws.WebSocket.connect(self.url + "?ticket=" + t, h, 10) for t in tickets[:-1]]
        with self.assertRaises(kc.ws.HandshakeError) as e:
            kc.ws.WebSocket.connect(self.url + "?ticket=" + tickets[-1], h, 10)
        self.assertEqual(e.exception.status, "429")
        self.assertEqual(self.h.room.kaas.ticket_status(tickets[-1]), "too_many")
        socks.pop().close()                                                         # one closes: room for another
        self.assertTrue(self.h.pump(lambda: self.h.room.kaas.web_sessions_from(addr) < mr.IP_WEB_SESSIONS, 5))
        socks.append(kc.ws.WebSocket.connect(self.url + "?ticket=" + self.xff_login("203.0.113.31")[1],
                                             {"X-Forwarded-For": "203.0.113.31"}, 10))
        for s in socks:
            s.close()
        old = mr.IP_WS_PER_MIN
        mr.IP_WS_PER_MIN = 0                                                        # (every one counted so far is over)
        try:
            with self.assertRaises(kc.ws.HandshakeError) as e:
                kc.ws.WebSocket.connect(self.url + "?ticket=x", {"X-Forwarded-For": "203.0.113.32"}, 10)
            self.assertEqual(e.exception.status, "429")
        finally:
            mr.IP_WS_PER_MIN = old

    def test_messages_per_connection(self):
        """KAAS_MSG_RATE a second in bursts of KAAS_MSG_BURST: past that, an error each; far past it, disconnected."""
        self.enable()
        c = self.connect(self.login(kc.Identity.generate())[1]["ticket"])
        for i in range(mr.KAAS_MSG_BURST * 3):
            try:
                c.ws.send_text(json.dumps({"type": "ping", "id": i}))
            except OSError:
                break
        self.assertTrue(c.closed.wait(10))
        self.assertEqual(c.close_reason.code, 1008)
        self.assertIn("too many messages", json.dumps(c.msgs))
        self.assertGreaterEqual(sum(1 for m in c.msgs if m.get("type") == "pong"), mr.KAAS_MSG_BURST - 2)

    def test_stats_of_forgotten_web_keys_are_pruned(self):
        hub = self.h.room.kaas
        hub.kstats[mr.WEB_ID_PREFIX + "ab" * 32] = {"total": [1, 0, 0], "hours": {}}
        hub.kstats_dirty = True
        hub.save_stats()
        self.assertNotIn(mr.WEB_ID_PREFIX + "ab" * 32, hub.kstats)

    def test_a_web_flood_starts_with_no_hops(self):
        self.enable()
        me = kc.Identity.generate()
        self.heard_on_air(me, "Me")
        c = self.connect(self.login(me)[1]["ticket"])
        p = kc.Packet.parse(channel_msg("Me: hi"))
        p.path_len, p.path = 3, b"\x11\x22\x33"                                 # (as if it had come 3 hops)
        r = self.send(c, p.encode(), 1)
        self.assertIn("no hops", r.get("reason", ""))
        self.assertEqual(self.send(c, channel_msg("Me: hi"), 2)["status"], "sent")

    def test_wrong_room_passwords_from_a_key_are_limited(self):
        self.enable()
        me = kc.Identity.generate()
        self.heard_on_air(me, "Me")
        c = self.connect(self.login(me)[1]["ticket"])
        room = self.h.add_room().id.pub_key.hex()
        for i in range(mr.ROOM_LOGIN_FAILS):
            self.assertIn("wrong password", self.ask(c, {"type": "room", "id": i, "room": room, "password": "nope"})["error"])
        self.assertIn("too many", self.ask(c, {"type": "room", "id": 99, "room": room, "password": "hello"})["error"])

    def test_cookies_and_other_sites(self):
        def post(path, body, headers):
            req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json", **headers})
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    return r.status, r.headers.get("Set-Cookie", "")
            except urllib.error.HTTPError as e:
                return e.code, e.headers.get("Set-Cookie", "")
        code, cookie = post("/api/login", {"password": "adminpw"}, {"X-Forwarded-Proto": "https"})
        self.assertEqual(code, 200)
        self.assertIn("; Secure", cookie)                                           # (TLS at a proxy on this LAN)
        self.assertNotIn("Secure", post("/api/login", {"password": "adminpw"}, {})[1])
        self.assertEqual(post("/api/login", {"password": "adminpw"}, {"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(post("/api/login", {"password": "adminpw"}, {"Origin": self.base})[0], 200)
        self.assertEqual(post("/api/login", {"password": "adminpw"}, {"Sec-Fetch-Site": "cross-site", "Origin": "null"})[0], 403)
        self.assertEqual(post("/api/login", {"password": "adminpw"}, {"Sec-Fetch-Site": "same-origin", "Origin": "null"})[0], 200)
        self.enable()
        self.assertEqual(post("/api/v1/web/challenge", {}, {"Origin": "https://anywhere.example"})[0], 200)  # (public)

    def test_ack_ingest_is_off_by_default(self):
        self.assertFalse(mr.DEFAULT_CONFIG["mqtt_ack_ingest"])

    def test_a_tenant_cant_take_a_switched_off_companions_key(self):
        key = "11" * 32
        self.h.cfg.set("companion_key", key)
        pub = mr.RepeaterIdentity(bytes.fromhex(key)).pub_key
        self.assertIsNone(self.h.room.vc)
        self.assertIn(pub, self.h.room.own_node_keys())
        self.http("POST", "/api/login", {"password": "adminpw"})
        code, d = self.http("POST", "/api/tenants", {"name": "Copy", "path": "copy", "private_key": key,
                                                       "web_password": "tenantpw1"})
        self.assertEqual(code, 400, d)
        self.assertIn("already used", d["error"])

    def test_the_observer_needs_a_region_code(self):
        """No IATA code by default: the observer can't be turned on (or start) until one is set."""
        self.assertEqual(mr.DEFAULT_CONFIG["observer_iata"], "")
        self.http("POST", "/api/login", {"password": "adminpw"})
        r = self.h.add_room("Surf")
        self.assertEqual(self.http("POST", "/api/observer", {"observer_identity": r.key})[0], 200)
        self.h.cfg.set("observer_identity", r.key)                               # (the main loop applies it)
        code, d = self.http("POST", "/api/observer", {"observer_enabled": True})
        self.assertEqual(code, 400)
        self.assertIn("IATA region code", d["error"])
        self.assertEqual(self.http("POST", "/api/observer", {"observer_iata": "sj"})[0], 400)
        self.assertEqual(self.http("POST", "/api/observer", {"observer_enabled": True, "observer_iata": "mry"})[0], 200)
        sys.path.insert(0, str(pathlib.Path(mr.__file__).parent))
        import meshroom_observer
        with self.assertRaises(ValueError):
            meshroom_observer.ObserverBridge(types.SimpleNamespace(observer_iata=""), self.h.room.id, start=False)

    def test_the_observer_reports_as_the_repeater_or_a_room(self):
        """It can't be enabled until it's told who it reports as; the choices are the virtual repeater (while on)
        and the rooms, never the host's own key."""
        self.http("POST", "/api/login", {"password": "adminpw"})
        code, d = self.http("POST", "/api/observer", {"observer_enabled": True, "observer_iata": "SJC"})
        self.assertEqual(code, 400)
        self.assertIn("reports as", d["error"])
        self.assertEqual(self.h.room.observer_choices(), [])
        self.assertEqual(self.http("POST", "/api/observer", {"observer_identity": "repeater"})[0], 400)   # (off)
        r = self.h.add_room("Surf")
        self.assertEqual([c["label"] for c in self.h.room.observer_choices()], ["Room: Surf"])
        self.assertEqual(self.http("POST", "/api/observer", {"observer_identity": "ab" * 32})[0], 400)
        self.assertEqual(self.http("POST", "/api/observer", {"observer_identity": r.key, "observer_enabled": True,
                                                             "observer_iata": "SJC"})[0], 200)
        self.h.cfg.set("observer_identity", r.key)                               # (the main loop applies it)
        ident, name = self.h.room.observer_who()
        self.assertEqual((ident.pub_key, name), (r.id.pub_key, "Surf"))
        self.h.room.tenant_delete(r.id.pub_key)                                    # its room is gone: nobody
        self.assertIsNone(self.h.room.observer_who())
        sys.path.insert(0, str(pathlib.Path(mr.__file__).parent))
        import meshroom_observer
        b = meshroom_observer.ObserverBridge(types.SimpleNamespace(observer_iata="SJC", observer_queue_max=100,
                                                                   observer_servers=None, observer_gomesh=True,
                                                                   observer_meshmapper=True, name="host"),
                                             r.id, start=False, name="Surf")
        self.assertEqual(json.loads(b._status_message())["origin"], "Surf")       # its name, not the host's

    def test_message_of_the_day(self):
        """Off by default; when on, web sessions get it in hello (API keys never do)."""
        self.enable()
        c = self.connect(self.login(kc.Identity.generate())[1]["ticket"])
        self.assertIsNone(c.hello["motd"])
        self.assertEqual(self.http("POST", "/api/v1/web/settings", {"motd": " Welcome!\r\nBe nice. ", "motd_enabled": True})[0], 200)
        self.h.pump(lambda: self.h.cfg.web_motd_enabled, 5)
        c = self.connect(self.login(kc.Identity.generate())[1]["ticket"])
        self.assertEqual(c.hello["motd"], "Welcome!\nBe nice.")
        users = self.http("GET", "/api/v1/web/users")[1]
        self.assertEqual((users["motd_enabled"], users["motd"]), (True, "Welcome!\nBe nice."))
        bot = kc.KaasClient(self.url, self.make_key())
        self.assertIsNone(self.h.run_client(bot.connect)["motd"])
        bot.close()
        self.assertEqual(self.http("POST", "/api/v1/web/settings", {"motd": "x" * 1001})[0], 400)


class TopLinksTests(unittest.TestCase):
    def test_up_to_25_with_the_virtual_repeater_among_them(self):
        from test_virtual_companion import Harness
        h = Harness()
        try:
            room = h.room
            for i in range(30):
                hsh = bytes([0x10 + i, i])
                room.probe_snr(hsh, 5.0, 4.0, 300, discovery=True)
                st = room.probe_stats(hsh)
                st["tr_n"], st["tr_s"] = 10.0, 10.0 - (i % 5)
            rows = room.top_links()
            self.assertEqual(len(rows), 25)
            rel = [100 - r["loss"] for r in rows]
            self.assertEqual(rel, sorted(rel, reverse=True))                  # most reliable first
            room.vr = types.SimpleNamespace(pub=b"\xee" * 32)
            rows = room.top_links()
            self.assertEqual(len(rows), 25)
            self.assertTrue(rows[0].get("virtual"))
        finally:
            room.vr = None
            h.close()


class RepeaterTableTests(unittest.TestCase):
    def test_capped_keeping_the_recent_and_our_own(self):
        ours = b"\x01" * 32
        t = mr.RepeaterTable(lambda pub: pub == ours)
        t[ours] = dict(last_advert=0)
        for i in range(mr.REPEATERS_MAX + 500):
            t[i.to_bytes(32, "big")] = dict(last_advert=1000 + i)
        self.assertLessEqual(len(t), mr.REPEATERS_MAX)
        self.assertIn(ours, t)                                                     # (its advert is the oldest)
        newest = (mr.REPEATERS_MAX + 499).to_bytes(32, "big")
        self.assertIn(newest, t)
        self.assertNotIn((0).to_bytes(32, "big"), t)
        t[newest] = dict(last_advert=5)                                            # (an update isn't an addition)
        self.assertIn(newest, t)


class CompanionHardeningTests(unittest.TestCase):
    """The virtual companion's port has no login (a trusted LAN only), but what reaches it can't forge the node's
    adverts, stall the radio's main loop, or make the radio flood the mesh."""

    def setUp(self):
        from test_virtual_companion import Harness, RawClient
        self.h, self.Raw = Harness(companion_enabled=True, room_password=""), RawClient
        self.vc = self.h.room.vc

    def tearDown(self):
        self.h.close()

    def sign(self, c, data):
        c.call(bytes([mr.CMD_SIGN_START]), mr.RESP_SIGN_START)
        c.call(bytes([mr.CMD_SIGN_DATA]) + data, mr.RESP_OK, mr.RESP_ERR)
        return c.call(bytes([mr.CMD_SIGN_FINISH]), mr.RESP_SIGNATURE, mr.RESP_ERR)

    def test_wont_sign_an_advert_or_a_web_login(self):
        def client():
            c = self.Raw(self.h.port)
            self.assertEqual(self.sign(c, b"anything else")[0], mr.RESP_SIGNATURE)
            advert = self.vc.pub + struct.pack("<I", int(time.time()) + 315360000) + bytes([0x82]) + b"PWNED"
            self.assertEqual(self.sign(c, advert)[0], mr.RESP_ERR)
            login = mr.web_login_message("mesh.example.com", "wc_x", self.vc.pub.hex())
            self.assertEqual(self.sign(c, login)[0], mr.RESP_ERR)
            c.close()
        self.h.run_client(client)

    def test_transmissions_are_budgeted(self):
        def client():
            c = self.Raw(self.h.port)
            self.assertEqual(c.call(bytes([mr.CMD_SEND_SELF_ADVERT, 1]), mr.RESP_OK, mr.RESP_ERR)[0], mr.RESP_OK)
            self.assertEqual(c.call(bytes([mr.CMD_SEND_SELF_ADVERT, 1]), mr.RESP_OK, mr.RESP_ERR)[0], mr.RESP_ERR)
            sent = [c.call(bytes([mr.CMD_SEND_CHANNEL_TXT_MSG, 0, 0]) + struct.pack("<I", int(time.time())) + b"hi %d" % i,
                           mr.RESP_OK, mr.RESP_ERR)[0] for i in range(mr.VC_TX_BURST + 3)]
            self.assertEqual(sent.count(mr.RESP_OK), mr.VC_TX_BURST - 1)            # (the advert took one)
            c.close()
        self.h.run_client(client)

    def test_an_app_that_doesnt_read_is_dropped_not_waited_for(self):
        """Replies are queued for a writer thread: the main loop never waits on the app's socket."""
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
        sock.connect(("127.0.0.1", self.h.port))
        frame = b"<" + struct.pack("<H", 2) + bytes([mr.CMD_DEVICE_QUERY, 3])
        t0 = time.monotonic()

        def flood():
            try:
                sock.sendall(frame * 40000)               # ...and never read a reply (past what socket buffers hold)
            except OSError:
                pass
        threading.Thread(target=flood, daemon=True).start()
        longest = [0.0]
        end = time.monotonic() + 40
        while time.monotonic() < end and (self.vc.link.client is not None or time.monotonic() - t0 < 1):
            a = time.monotonic()
            self.h.pump(lambda: False, 0.05)
            longest[0] = max(longest[0], time.monotonic() - a)
        self.assertIsNone(self.vc.link.client)                                      # dropped...
        self.assertLess(longest[0], 1.0)                                            # ...with no main-loop stall
        sock.close()

    def test_name_and_position_changes_dont_rewrite_the_config_each_time(self):
        saves = []
        real = self.h.cfg.save
        self.h.cfg.save = lambda: (saves.append(1), real())[1]

        def client():
            c = self.Raw(self.h.port)
            for i in range(50):
                c.call(bytes([mr.CMD_SET_ADVERT_NAME]) + b"Name %d" % i, mr.RESP_OK)
                c.call(bytes([mr.CMD_SET_ADVERT_LATLON]) + struct.pack("<ii", i, i), mr.RESP_OK)
            c.close()
        self.h.run_client(client)
        self.assertLessEqual(len(saves), 2)
        self.assertEqual(self.h.cfg.companion_name, "Name 49")
        self.h.room.vc.close()                                                      # (closing saves what's pending)
        self.assertEqual(mr.Config(self.h.cfg.path).data["companion_name"], "Name 49")
        self.h.room.vc = None


if __name__ == "__main__":
    unittest.main()
