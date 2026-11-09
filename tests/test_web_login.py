"""MeshCore Web logins: signing with the node's private key instead of an API key. Challenges, the host check, pending
(receive-only) until the key is heard on the air or the admin allows it, what a web session may send, kick and ban,
the dashboard's endpoints, the node directory behind it, and a separate connection limit from bots."""
import json
import os
import pathlib
import struct
import sys
import time
import unittest
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "meshroom"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "client"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import meshroom as mr
from test_kaas import WebTestCase, flood
from test_virtual_companion import Harness

import meshroom_kaas as kc
from meshroom_kaas.crypto import PUBLIC_CHANNEL_KEY, encrypt_then_mac, channel_hash


def advert(ident, name, ts=None, lat=None, lon=None):
    """A signed flood advert for ident, as a MeshCore app sends it."""
    flags, body = mr.ADV_TYPE_CHAT | 0x80, b""
    if lat is not None:
        flags |= 0x10
        body = struct.pack("<ii", int(lat * 1e6), int(lon * 1e6))
    app = bytes([flags]) + body + name.encode()
    tsb = struct.pack("<I", ts or int(time.time()))
    return flood(mr.PT_ADVERT, ident.pub + tsb + ident.sign(ident.pub + tsb + app) + app)


def check(stored, pw):
    return bool(stored) and mr.check_web_password(pw, stored)


def channel_msg(text):
    data = struct.pack("<I", int(time.time())) + b"\0" + text.encode()
    return flood(mr.PT_GRP_TXT, bytes([channel_hash(PUBLIC_CHANNEL_KEY)]) +
                 encrypt_then_mac(PUBLIC_CHANNEL_KEY + bytes(16), data))


class WebHelpers(WebTestCase):
    """Logging in by signing, connecting, sending: for the tests below."""

    def setUp(self):
        super().setUp()
        self.host = "127.0.0.1:%d" % self.port

    def post(self, path, body=None, headers=None):
        req = urllib.request.Request(self.base + path, method="POST", data=json.dumps(body or {}).encode(),
                                     headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def enable(self, **extra):
        self.http("POST", "/api/login", {"password": "adminpw"})
        self.assertEqual(self.http("POST", "/api/v1/web/settings", dict(web_login=True, **extra))[0], 200)
        self.h.pump(lambda: self.h.cfg.web_login, 5)

    def login(self, ident, name="Tester", host=None, tamper=None):
        code, d = self.post("/api/v1/web/challenge")
        self.assertEqual(code, 200, d)
        host = host or self.host
        msg = mr.web_login_message(host, d["challenge"], ident.pub.hex())
        body = dict(pub=ident.pub.hex(), signature=ident.sign(msg).hex(), challenge=d["challenge"], host=host, name=name)
        if tamper:
            tamper(body)
        return self.post("/api/v1/web/login", body)

    def connect(self, ticket):
        c = kc.KaasClient(self.url + "?ticket=" + ticket, "")
        c.ws = kc.ws.WebSocket.connect(self.url + "?ticket=" + ticket, {}, 10)
        c.hello = json.loads(c.ws.recv()[1])
        c.closed.clear()
        msgs = []
        c.on_packet(lambda p: None)
        import threading

        def reader():
            try:
                while True:
                    op, data = c.ws.recv()
                    msgs.append(json.loads(data))
            except kc.Closed as e:
                c.close_reason = e
            except OSError:
                pass
            finally:
                c.closed.set()
        threading.Thread(target=reader, daemon=True).start()
        c.msgs = msgs
        return c

    def send(self, c, raw, rid):
        c.ws.send_text(json.dumps({"type": "send", "id": rid, "raw": raw.hex()}))

        def done():
            return next((m for m in c.msgs if m.get("type") == "send_result" and m.get("id") == rid
                         and m.get("status") != "queued"), None)
        self.assertTrue(self.h.pump(lambda: done() is not None, 10), c.msgs)
        return done()

    def heard_on_air(self, ident, name):
        self.h.events.put(("rxraw", advert(ident, name)))
        self.assertTrue(self.h.pump(lambda: self.h.room.heard_on_rf(ident.pub) is not None, 10))



class WebLoginTests(WebHelpers):

    def test_off_by_default(self):
        self.assertFalse(self.h.cfg.web_login)
        self.assertEqual(self.post("/api/v1/web/challenge")[0], 403)
        self.assertEqual(self.post("/api/v1/web/login", {})[0], 403)

    def test_challenge_signature_and_host_are_checked(self):
        self.enable()
        me = kc.Identity.generate()
        other = kc.Identity.generate()
        self.assertEqual(self.login(me, tamper=lambda b: b.update(signature=other.sign(b"x").hex()))[0], 401)
        self.assertEqual(self.login(me, tamper=lambda b: b.update(pub=other.pub.hex()))[0], 401)
        code, d = self.login(me, host="evil.example.com")
        self.assertEqual(code, 401)
        self.assertIn("evil.example.com", d["error"])
        self.assertEqual(self.login(me, tamper=lambda b: b.update(challenge="wc_made_up"))[0], 401)
        code, ch = self.post("/api/v1/web/challenge")
        sig = me.sign(mr.web_login_message(self.host, ch["challenge"], me.pub.hex())).hex()
        body = dict(pub=me.pub.hex(), signature=sig, challenge=ch["challenge"], host=self.host)
        self.assertEqual(self.post("/api/v1/web/login", body)[0], 200)
        self.assertEqual(self.post("/api/v1/web/login", body)[0], 401)         # a challenge works once
        room_id = self.h.room.id

        class RoomIdent:                                                     # (the room's own key may not log in)
            pub = room_id.pub_key
            sign = staticmethod(room_id.sign)
        self.assertEqual(self.login(RoomIdent)[0], 403)

    def test_proxy_host(self):
        """Behind a proxy the browser signs the public host name: it has to be one the admin listed in web_hosts."""
        self.enable(web_hosts=["mesh.example.com"])
        me = kc.Identity.generate()
        code, d = self.post("/api/v1/web/challenge")
        msg = mr.web_login_message("mesh.example.com", d["challenge"], me.pub.hex())
        body = dict(pub=me.pub.hex(), signature=me.sign(msg).hex(), challenge=d["challenge"], host="mesh.example.com")
        self.assertEqual(self.post("/api/v1/web/login", body, {"Host": "mesh.example.com"})[0], 200)

    def test_pending_until_heard_then_sends_as_itself(self):
        self.enable()
        me = kc.Identity.generate()
        code, d = self.login(me, "Alice")
        self.assertEqual((code, d["state"], d["send"]), (200, "pending", False))
        c = self.connect(d["ticket"])
        self.assertEqual((c.hello["key"]["web"], c.hello["key"]["pub"], c.hello["key"]["send"]), (True, me.pub.hex(), False))
        self.h.events.put(("rxraw", channel_msg("Bob: hi")))                 # a pending user still receives
        self.assertTrue(self.h.pump(lambda: any(m.get("type") == "packet" for m in c.msgs), 10))
        r = self.send(c, channel_msg("Alice: hello"), 1)
        self.assertEqual(r["status"], "dropped")
        self.assertIn("heard", r["reason"])
        self.heard_on_air(me, "Alice")                                       # her own radio adverts: now she may send
        self.assertTrue(self.h.pump(lambda: any(m.get("type") == "access" and m["send"] for m in c.msgs), 10), c.msgs)
        self.assertEqual(self.send(c, channel_msg("Alice: hello"), 2)["status"], "sent")
        self.assertEqual(self.send(c, advert(me, "Alice"), 3)["status"], "sent")
        someone = kc.Identity.generate()
        r = self.send(c, advert(someone, "Mallory"), 4)
        self.assertEqual((r["status"], r["reason"]), ("dropped", "an advert must be for your own key"))
        dm = mr.Packet(mr.PT_TXT_MSG, bytes([0x42, someone.pub[0] ^ (0 if someone.pub[0] != me.pub[0] else 1)]) + bytes(18))
        dm.header |= mr.ROUTE_FLOOD
        r = self.send(c, dm.encode(), 5)
        self.assertEqual((r["status"], r["reason"]), ("dropped", "a message must be from your own key"))
        trace = mr.Packet(mr.PT_TRACE, bytes(12))
        trace.header |= mr.ROUTE_DIRECT
        r = self.send(c, trace.encode(), 6)
        self.assertEqual((r["status"], r["reason"]), ("dropped", "web sessions can't send trace packets"))
        rows = self.http("GET", "/api/v1/web/users")[1]["users"]
        self.assertEqual([(u["pub"], u["name"], u["advert_name"], u["send"], u["connected"]) for u in rows],
                         [(me.pub.hex(), "Alice", "Alice", True, 1)])
        self.assertGreaterEqual(rows[0]["stats"]["tx"][1], 2)
        self.assertGreaterEqual(rows[0]["stats"]["rx"][1], 1)
        c.ws.close()

    def test_an_advert_sent_through_the_api_isnt_heard_on_the_air(self):
        """Only this radio's own reception counts: a bot's API key can't make a key look heard."""
        self.enable()
        token = self.make_key()
        bot = kc.KaasClient(self.url, token)
        self.h.run_client(bot.connect)
        newbie = kc.Identity.generate()
        res = self.h.run_client(lambda: bot.send(advert(newbie, "Newbie")))
        self.assertIn(res.status, ("sent", "local"))
        self.h.pump(lambda: False, 0.5)
        self.assertIsNone(self.h.room.heard_on_rf(newbie.pub))
        self.assertEqual(self.login(newbie)[1]["state"], "pending")
        bot.close()

    def test_admin_allow_kick_ban(self):
        self.enable()
        me = kc.Identity.generate()
        c = self.connect(self.login(me, "Newbie")[1]["ticket"])
        self.assertFalse(c.hello["key"]["send"])
        self.assertEqual(self.http("POST", "/api/v1/web/users/%s/allow" % me.pub.hex(), {})[0], 200)
        self.assertTrue(self.h.pump(lambda: any(m.get("type") == "access" and m["send"] for m in c.msgs), 10))
        self.assertEqual(self.send(c, channel_msg("Newbie: thanks"), 1)["status"], "sent")
        self.http("POST", "/api/v1/web/users/%s/kick" % me.pub.hex(), {})
        self.assertTrue(self.h.pump(lambda: c.closed.is_set(), 10))
        self.assertEqual(c.close_reason.code, 4005)
        code, d = self.login(me, "Newbie")                                  # kicked, not banned: back in, still allowed
        self.assertEqual((code, d["state"]), (200, "allowed"))
        c = self.connect(d["ticket"])
        self.http("POST", "/api/v1/web/users/%s/ban" % me.pub.hex(), {})
        self.assertTrue(self.h.pump(lambda: c.closed.is_set(), 10))
        self.assertEqual(c.close_reason.code, 4003)
        self.assertEqual(self.login(me)[0], 403)
        users = self.http("GET", "/api/v1/web/users")[1]
        self.assertEqual([b["pub"] for b in users["banned"]], [me.pub.hex()])
        self.assertEqual(users["banned"][0]["name"], "Newbie")
        self.assertNotIn(me.pub.hex(), self.h.cfg.web_approved)              # a ban also takes back "allow send"
        self.http("POST", "/api/v1/web/users/%s/unban" % me.pub.hex(), {})
        self.assertTrue(self.h.pump(lambda: not self.h.cfg.web_banned, 5))
        self.assertEqual(self.login(me)[1]["state"], "pending")

    def test_turning_logins_off_disconnects(self):
        self.enable()
        c = self.connect(self.login(kc.Identity.generate())[1]["ticket"])
        self.http("POST", "/api/v1/web/settings", {"web_login": False})
        self.assertTrue(self.h.pump(lambda: c.closed.is_set(), 10))
        self.assertEqual(c.close_reason.code, 4004)

    def test_admin_endpoints_need_the_admin(self):
        self.assertEqual(self.http("GET", "/api/v1/web/users")[0], 401)
        self.assertEqual(self.http("POST", "/api/v1/web/settings", {"web_login": True})[0], 401)
        self.assertEqual(self.http("POST", "/api/v1/web/users/%s/allow" % ("ab" * 32), {})[0], 401)
        self.assertFalse(self.h.cfg.web_login)

    def test_users_sorted_by_most_recently_active(self):
        self.enable()
        a, b = kc.Identity.generate(), kc.Identity.generate()
        self.login(a, "A")
        hub = self.h.room.kaas
        hub.wusers[a.pub.hex()]["last"] -= 100
        self.login(b, "B")
        names = [u["name"] for u in self.http("GET", "/api/v1/web/users")[1]["users"]]
        self.assertEqual(names, ["B", "A"])

    def test_meshcore_web_is_served(self):
        """pyMeshRoom serves the built app at /meshcore-web/, never in a frame, and no tenant room can take the path."""
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", "/meshcore-web")
        r = c.getresponse()
        r.read()
        self.assertEqual((r.status, r.getheader("Location")), (301, "meshcore-web/"))
        c.request("GET", "/meshcore-web/", headers={"Accept-Encoding": "gzip"})
        r = c.getresponse()
        import gzip
        body = gzip.decompress(r.read()).decode()
        self.assertEqual(r.status, 200)
        self.assertTrue(r.getheader("Content-Type").startswith("text/html"))
        self.assertEqual((r.getheader("X-Frame-Options"), r.getheader("Content-Security-Policy")), ("DENY", "frame-ancestors 'none'"))
        self.assertIn("<title>MeshCore Web</title>", body)
        self.assertIn("script-src 'sha256-", body)                         # the built file, with its pinned CSP
        c.close()
        with self.assertRaisesRegex(ValueError, "already in use"):
            mr.tenant_spec({"name": "Web", "path": "meshcore-web", "web_password": "x" * 12})

    def test_page_password(self):
        """With a page password, /meshcore-web/ shows a password form, and the login API wants it (or the cookie)."""
        import http.client
        self.enable()
        self.assertEqual(self.http("POST", "/api/v1/web/settings", {"page_password": "abc"})[0], 400)   # too short
        self.assertEqual(self.http("POST", "/api/v1/web/settings", {"page_password": "open sesame"})[0], 200)
        self.assertTrue(self.h.pump(lambda: self.h.cfg.web_page_password, 5))
        self.assertTrue(self.h.cfg.web_page_password.startswith("pbkdf2_sha256$"))           # only a hash is kept
        self.assertTrue(self.http("GET", "/api/v1/web/users")[1]["page_password"])

        def get(path, cookie=None, body=None):
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            hdrs = {"Cookie": cookie} if cookie else {}
            if body is None:
                c.request("GET", path, headers=hdrs)
            else:
                c.request("POST", path, body=body, headers=dict(hdrs, **{"Content-Type": "application/x-www-form-urlencoded"}))
            r = c.getresponse()
            out = (r.status, r.getheader("Set-Cookie"), r.getheader("Location"), r.read().decode())
            c.close()
            return out
        code, _, _, page = get("/meshcore-web/")
        self.assertEqual(code, 200)
        self.assertIn('name="password"', page)
        self.assertNotIn("script-src 'sha256-", page)                                       # not the app
        self.assertEqual(get("/meshcore-web/unlock", body="password=wrong")[0], 401)
        code, cookie, where, _ = get("/meshcore-web/unlock", body="password=open+sesame")
        self.assertEqual((code, where), (303, "./"))
        self.assertIn("HttpOnly", cookie)
        cookie = cookie.split(";")[0]
        self.assertIn("script-src 'sha256-", get("/meshcore-web/", cookie)[3])               # the app now

        me = kc.Identity.generate()
        code, d = self.post("/api/v1/web/challenge")
        self.assertEqual((code, d.get("page_password")), (401, True))                       # no cookie, no password
        code, d = self.post("/api/v1/web/challenge", {"page_password": "open sesame"})
        self.assertEqual(code, 200)                                                         # (a page served elsewhere)
        msg = mr.web_login_message(self.host, d["challenge"], me.pub.hex())
        body = dict(pub=me.pub.hex(), signature=me.sign(msg).hex(), challenge=d["challenge"], host=self.host, page_password="open sesame")
        self.assertEqual(self.post("/api/v1/web/login", body)[0], 200)
        self.assertEqual(self.post("/api/v1/web/challenge", headers={"Cookie": cookie})[0], 200)   # (the page's cookie)

        self.http("POST", "/api/v1/web/settings", {"page_password": "a new one"})            # a new password: the old
        self.assertTrue(self.h.pump(lambda: check(self.h.cfg.web_page_password, "a new one"), 5))   # sessions end
        self.assertIn('name="password"', get("/meshcore-web/", cookie)[3])
        self.http("POST", "/api/v1/web/settings", {"page_password": ""})
        self.assertTrue(self.h.pump(lambda: not self.h.cfg.web_page_password, 5))
        self.assertIn("script-src 'sha256-", get("/meshcore-web/")[3])                       # removed: open again
        self.assertEqual(self.post("/api/v1/web/challenge")[0], 200)

    def test_web_sessions_have_their_own_limit(self):
        self.enable(web_max_clients=1)
        tickets = [self.login(kc.Identity.generate())[1]["ticket"] for _ in range(2)]   # both while there was room
        first = self.connect(tickets[0])
        with self.assertRaises(kc.HandshakeError) as e:
            self.connect(tickets[1])
        self.assertEqual(e.exception.status, "503")
        self.assertEqual(self.post("/api/v1/web/ticket", {"ticket": tickets[1]})[1]["outcome"], "full")
        bot = kc.KaasClient(self.url, self.make_key())                        # a bot still gets in
        self.assertEqual(self.h.run_client(bot.connect)["type"], "hello")
        bot.close()
        first.ws.close()


class PageSessionTests(unittest.TestCase):
    def test_page_sessions_are_signed_not_stored(self):
        """So they outlive a restart (nothing to lose), and a new page password ends them all."""
        stored = mr.hash_web_password("letmein")
        tok = mr.web_page_session(stored)
        self.assertTrue(mr.web_page_session_ok(tok, stored))
        exp, mac = tok.split(".")
        self.assertFalse(mr.web_page_session_ok("%d.%s" % (int(exp) + 86400, mac), stored))     # stretched
        self.assertFalse(mr.web_page_session_ok(exp + "." + "0" * 64, stored))
        self.assertFalse(mr.web_page_session_ok(tok, mr.hash_web_password("letmein")))       # a new password (salt)
        self.assertFalse(mr.web_page_session_ok(mr.web_page_session(stored, now=time.time() - 31 * 86400), stored))
        self.assertFalse(mr.web_page_session_ok("junk", stored))
        self.assertFalse(mr.web_page_session_ok(tok, ""))


class LocalRoomTests(WebHelpers):
    """A web login reads and posts to a room on this server through the server, leaving the member's over-the-air
    state (sync point, route, activity) to their radio: the same key on a companion app."""

    def request(self, c, msg, want):
        c.ws.send_text(json.dumps(msg))
        got = lambda: next((m for m in c.msgs if m.get("id") == msg["id"]), None)
        self.assertTrue(self.h.pump(lambda: got() is not None, 10), c.msgs)
        m = got()
        self.assertEqual(m["type"], want, m)
        return m

    def live(self, c, text):
        self.assertTrue(self.h.pump(lambda: any(m.get("type") == "room_post" and m["text"] == text for m in c.msgs), 10), c.msgs)
        return next(m for m in c.msgs if m.get("type") == "room_post" and m["text"] == text)

    def test_room_through_the_server(self):
        self.enable()
        r, me = self.h.add_room(), kc.Identity.generate()
        room = r.id.pub_key.hex()
        companion = r.put_member(me.pub)                                      # their companion app logged in already
        companion.perms, companion.secret = mr.PERM_READ_WRITE, r.id.shared_secret(me.pub)
        companion.sync_since, companion.last_activity = 1234, 999
        r.learn_route(companion, 1, b"\x11", proven=True)                     # (their radio's route)
        r.store_post(r.id.pub_key, "before")
        self.heard_on_air(me, "Me")
        c = self.connect(self.login(me)[1]["ticket"])
        a = self.request(c, {"type": "room", "id": 1, "room": room}, "room_result")   # (a member: no password)
        self.assertEqual(([p["text"] for p in a["posts"]], a["can_post"]), (["before"], True))
        r.store_post(me.pub, "from my companion")                            # the same key, from their radio
        self.assertEqual(self.live(c, "from my companion")["author"], me.pub.hex())
        b = self.request(c, {"type": "room_post", "id": 2, "room": room, "text": " from the web "}, "room_post_result")
        self.assertEqual((b["status"], r.posts[-1][1:3]), ("posted", (me.pub, "from the web")))
        self.assertEqual(self.live(c, "from the web")["ts"], b["ts"])
        self.assertEqual(self.request(c, {"type": "room_post", "id": 3, "room": room, "text": "from the web"},
                                      "room_post_result")["status"], "duplicate")
        self.assertEqual((companion.sync_since, companion.out_path, companion.out_path_len, companion.last_activity),
                         (1234, b"\x11", 1, 999))                            # their radio's state, untouched
        again = self.request(c, {"type": "room", "id": 4, "room": room, "since": b["ts"] - 1}, "room_result")
        self.assertEqual([p["text"] for p in again["posts"]], ["from the web"])
        self.assertIn("not a room", self.request(c, {"type": "room", "id": 5, "room": "ab" * 32}, "error")["error"])

    def test_joining_from_the_web(self):
        self.enable()
        r = self.h.add_room()
        room = r.id.pub_key.hex()
        guest = kc.Identity.generate()
        c = self.connect(self.login(guest)[1]["ticket"])
        self.assertEqual(c.hello["key"]["pending_message"], mr.DEFAULT_CONFIG["web_unknown_key_message"])
        self.assertIn("heard on this radio", self.request(c, {"type": "room", "id": 0, "room": room, "password": "hello"},
                                                         "error")["error"])   # pending: not even reading a room
        self.assertNotIn(guest.pub, r.members)
        c.ws.close()
        self.heard_on_air(guest, "Guest")
        c = self.connect(self.login(guest)[1]["ticket"])
        self.assertTrue(self.request(c, {"type": "room", "id": 1, "room": room, "password": "nope"}, "error").get("refused"))
        self.assertNotIn(guest.pub, r.members)
        ok = self.request(c, {"type": "room", "id": 2, "room": room, "password": "hello"}, "room_result")
        m = r.members[guest.pub]
        self.assertEqual((ok["can_post"], m.role, m.last_activity), (True, mr.PERM_READ_WRITE, 0))
        self.assertFalse(r.push_eligible(m))                                 # no radio: the room never pushes to it
        r.bans[guest.pub] = "test"
        self.assertIn("banned", self.request(c, {"type": "room", "id": 4, "room": room}, "error")["error"])

    def test_api_keys_log_in_over_the_air(self):
        self.http("POST", "/api/login", {"password": "adminpw"})
        bot = kc.KaasClient(self.url, self.make_key())
        self.h.run_client(bot.connect)
        bot.ws.send_text(json.dumps({"type": "room", "id": 1, "room": self.h.room.id.pub_key.hex()}))
        self.assertTrue(self.h.pump(lambda: False, 1.0) is False)
        bot.close()


class WebsocketDiagnosisTests(WebHelpers):
    """A browser isn't told why its websocket didn't open: the server keeps what became of each ticket, and logs it."""

    def raw_upgrade(self, ticket, headers):
        import socket
        s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        s.sendall(("GET /api/v1/kaas?ticket=%s HTTP/1.1\r\nHost: %s\r\n%s"
                   "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n" % (
                       ticket, self.host, "".join("%s: %s\r\n" % kv for kv in headers))).encode())
        head = s.recv(1000).decode(errors="replace")
        s.close()
        return head.split("\r\n")[0]

    def outcome(self, ticket):
        return self.post("/api/v1/web/ticket", {"ticket": ticket})[1]["outcome"]

    def test_ticket_outcomes(self):
        self.enable()
        t = self.login(kc.Identity.generate())[1]["ticket"]
        self.assertEqual(self.outcome(t), "waiting")              # (a proxy or the browser stopped it)
        with self.assertLogs("meshroom", "WARNING") as logs:
            self.assertIn(" 426 ", self.raw_upgrade(t, []))       # a proxy dropped Upgrade and Connection
        self.assertIn("reverse proxy", logs.output[0])
        self.assertEqual(self.outcome(t), "no_upgrade")
        t = self.login(kc.Identity.generate())[1]["ticket"]       # a proxy sending two Connection headers is fine,
        line = self.raw_upgrade(t, [("Upgrade", "websocket"), ("Connection", "keep-alive"), ("Connection", "Upgrade")])
        self.assertEqual(line, "HTTP/1.1 101 Switching Protocols")   # and the 101 is HTTP/1.1, as proxies want
        self.assertEqual(self.outcome(t), "connected")
        t = self.login(kc.Identity.generate())[1]["ticket"]
        hub = self.h.room.kaas
        hub.tickets[t] = (hub.tickets[t][0], time.monotonic() - 1)
        self.assertEqual(self.outcome(t), "unused")              # expired before reaching us: still never reached
        self.assertEqual(self.outcome("kt_made_up"), "unknown")

    def test_a_full_server_says_so_at_login(self):
        self.enable(web_max_clients=1)
        first = self.connect(self.login(kc.Identity.generate())[1]["ticket"])
        code, d = self.login(kc.Identity.generate())
        self.assertEqual((code, d.get("full")), (503, True), d)
        first.ws.close()
        self.assertTrue(self.h.pump(lambda: not any(c.web for c in self.h.room.kaas.conns), 10))
        self.assertEqual(self.login(kc.Identity.generate())[0], 200)


def dm(to_hash, from_hash, n=0):
    return flood(mr.PT_TXT_MSG, bytes([to_hash, from_hash]) + bytes([n]) * 18)


class BacklogTests(WebHelpers):
    """MeshCore Web's catch-up: channel messages and DMs kept (once each, from RF or MQTT), numbered, and replayed to
    web users after they reconnect."""

    def setUp(self):
        super().setUp()
        self.enable()

    def replay(self, c, since, channels, me):
        c.ws.send_text(json.dumps({"type": "replay", "id": "r", "since": since, "channels": channels, "me": me}))
        self.assertTrue(self.h.pump(lambda: any(m.get("type") in ("replay_done", "error") for m in c.msgs), 10), c.msgs)
        done = next(m for m in c.msgs if m.get("type") in ("replay_done", "error"))
        got = [p for m in c.msgs if m.get("type") == "replay_batch" for p in m["packets"]]
        c.msgs.clear()
        return done, got

    def flush(self):
        hub = self.h.room.kaas
        hub.bk_next_flush = 0
        hub.backlog_periodic()
        self.h.room.store.execmany([("SELECT 1", None)])
        time.sleep(0.3)                                     # (the writer thread)

    def test_kept_once_numbered_and_replayed(self):
        hub = self.h.room.kaas
        me = kc.Identity.generate()
        c = self.connect(self.login(me, "Away")[1]["ticket"])
        pub_ch = channel_hash(PUBLIC_CHANNEL_KEY)
        live = channel_msg("Bob: hello")
        self.h.events.put(("rxraw", live))
        self.assertTrue(self.h.pump(lambda: any(m.get("type") == "packet" for m in c.msgs), 10))
        first = next(m for m in c.msgs if m.get("type") == "packet")
        self.assertEqual(first["seq"], hub.bk_seq)                         # live packets carry their number
        seq0 = first["seq"]
        c.ws.close()
        self.h.pump(lambda: not any(x.web for x in hub.conns), 5)
        # while they're away: a channel message twice (two repeaters), the same one from MQTT, a DM to them,
        # a DM to someone else, a channel they're not in
        missed = channel_msg("Carol: while you were away")
        self.h.events.put(("rxraw", missed))
        self.h.events.put(("rxraw", missed))
        self.h.room.observer_event(("obs", "backlog", missed, 5.0))
        to_me = dm(me.pub[0], 0x42)
        self.h.events.put(("rxraw", to_me))
        self.h.events.put(("rxraw", dm(me.pub[0] ^ 0xFF, 0x42)))
        other = flood(mr.PT_GRP_TXT, bytes([pub_ch ^ 1]) + bytes(18))
        self.h.events.put(("rxraw", other))
        self.h.pump(lambda: hub.bk_seq >= seq0 + 4, 5)
        self.flush()
        self.assertEqual(self.h.room.store.read("SELECT COUNT(*) FROM backlog WHERE seq > ?", (seq0,))[0][0], 4)
        rows = self.http("GET", "/api/v1/web/users")[1]
        self.assertEqual(rows["users"][0]["missed"], 4)                    # (packets since they were last connected)
        self.assertEqual((rows["backlog"]["days"], rows["backlog"]["mqtt"]), (30, False))
        c = self.connect(self.login(me, "Away")[1]["ticket"])
        done, got = self.replay(c, seq0, [pub_ch], me.pub[0])
        self.assertEqual([bytes.fromhex(p["raw"]) for p in got], [missed, to_me])
        self.assertEqual(done["last"], hub.bk_seq)
        done, got = self.replay(c, None, [pub_ch], me.pub[0])               # a first visit: from now on
        self.assertEqual((got, done["last"], done["count"]), ([], hub.bk_seq, 0))
        c.ws.close()

    def test_purge_delete_bots_prune_and_mqtt(self):
        hub = self.h.room.kaas
        me = kc.Identity.generate()
        c = self.connect(self.login(me, "Away")[1]["ticket"])
        seq0 = hub.bk_seq
        c.ws.close()
        self.h.pump(lambda: not any(x.web for x in hub.conns), 5)
        self.h.events.put(("rxraw", channel_msg("Bob: old news")))
        self.h.pump(lambda: hub.bk_seq > seq0, 5)
        self.flush()
        self.assertEqual(self.http("POST", "/api/v1/web/users/%s/purge" % me.pub.hex(), {})[0], 200)
        self.h.pump(lambda: hub.wusers[me.pub.hex()]["floor"] == hub.bk_seq, 5)
        c = self.connect(self.login(me, "Away")[1]["ticket"])
        done, got = self.replay(c, seq0, [channel_hash(PUBLIC_CHANNEL_KEY)], me.pub[0])
        self.assertEqual(got, [])                                          # purged: synced up to then
        token = self.make_key()                                            # a bot can't replay
        bot = kc.KaasClient(self.url, token)
        self.h.run_client(bot.connect)
        with self.assertRaises(kc.RequestError):
            self.h.run_client(lambda: bot._request("replay", 5, since=0, channels=[], me=1))
        # MQTT: kept, and to web users live, only when ticked
        far = channel_msg("Zed: from far away")
        self.h.room.observer_event(("obs", "backlog", far, 1.0))
        self.h.pump(lambda: False, 0.3)
        self.assertFalse(any(m.get("dir") == "mqtt" for m in c.msgs))
        self.http("POST", "/api/v1/web/settings", {"web_backlog_mqtt": True, "web_backlog_days": 7})
        self.h.pump(lambda: self.h.cfg.web_backlog_mqtt, 5)
        self.h.room.observer_event(("obs", "backlog", far, 1.0))
        self.assertTrue(self.h.pump(lambda: any(m.get("dir") == "mqtt" for m in c.msgs), 5))
        self.h.events.put(("rxraw", far))                                  # then heard on RF too: not again
        n = hub.bk_seq
        self.h.pump(lambda: False, 0.3)
        self.assertEqual(hub.bk_seq, n)
        self.flush()
        self.h.room.store.execmany([("UPDATE backlog SET ts = ts - 8 * 86400 WHERE seq <= ?", [(seq0 + 1,)])])
        hub.bk_next_prune = 0
        self.flush()
        self.assertEqual(self.h.room.store.read("SELECT COUNT(*) FROM backlog WHERE seq <= ?", (seq0 + 1,))[0][0], 0)
        self.http("POST", "/api/v1/web/users/%s/allow" % me.pub.hex(), {})
        self.h.pump(lambda: me.pub.hex() in (self.h.cfg.web_approved or []), 5)
        self.assertEqual(self.http("POST", "/api/v1/web/users/%s/delete" % me.pub.hex(), {})[0], 200)
        self.assertTrue(self.h.pump(lambda: c.closed.is_set(), 5))
        self.assertNotIn(me.pub.hex(), hub.wusers)
        self.assertNotIn(me.pub.hex(), self.h.cfg.web_approved or [])
        bot.close()


class NodesRequestTests(WebTestCase):
    def test_nodes_request(self):
        """KaaS "nodes": the directory, most recently heard first, for contact lists and maps."""
        self.http("POST", "/api/login", {"password": "adminpw"})
        token = self.make_key(receive=True, send=False)
        a, b = kc.Identity.generate(), kc.Identity.generate()
        self.h.events.put(("rxraw", advert(a, "Alice", lat=36.5, lon=-121.9)))
        self.h.pump(lambda: a.pub in self.h.room.nodes, 5)
        self.h.events.put(("rxraw", advert(b, "Bob")))
        self.h.pump(lambda: b.pub in self.h.room.nodes, 5)
        self.h.room.nodes[a.pub]["rf"] -= 10
        c = kc.KaasClient(self.url, token)
        self.h.run_client(c.connect)
        rows = self.h.run_client(c.nodes)
        self.assertEqual([(r["pub"], r["name"], r["type"]) for r in rows], [(b.pub.hex(), "Bob", "chat"), (a.pub.hex(), "Alice", "chat")])
        self.assertEqual((rows[1]["lat"], rows[1]["lon"]), (36.5, -121.9))
        self.h.room.nodes[a.pub]["rf"] -= 2 * 86400
        self.assertEqual([r["name"] for r in self.h.run_client(lambda: c.nodes(days=1))], ["Bob"])
        with self.assertRaises(kc.RequestError):
            self.h.run_client(lambda: c.nodes(days=0))

        # what the room kept before the directory existed: the repeater map, members, and the name cache (8-byte keys)
        r, now = self.h.room, int(time.time())
        rpt, member, named = kc.Identity.generate(), kc.Identity.generate(), kc.Identity.generate()
        r.repeaters[rpt.pub] = dict(name="Seaside", lat=36.6, lon=-121.9, adv_ts=now, last_advert=now - 100)
        m = mr.Member(member.pub)
        m.last_heard = now - 200
        r.members[member.pub] = m
        r.names[member.pub[:8]] = (now - 300, "Dana")
        r.names[named.pub[:8]] = (now - 400, "Eve")
        r.names[a.pub[:8]] = (now, "Alice")                                   # (known in full: not listed twice)
        rows = self.h.run_client(lambda: c.nodes(days=30))
        by = {x["pub"]: x for x in rows}
        self.assertEqual((by[rpt.pub.hex()]["type"], by[rpt.pub.hex()]["name"], by[rpt.pub.hex()]["lat"]), ("repeater", "Seaside", 36.6))
        self.assertEqual((by[member.pub.hex()]["type"], by[member.pub.hex()]["name"]), ("chat", "Dana"))
        self.assertEqual(by[named.pub[:8].hex()], {"pub": named.pub[:8].hex(), "partial": True, "type": "chat", "name": "Eve",
                                                   "lat": None, "lon": None, "last_heard": now - 400, "rf": None, "obs": None})
        self.assertEqual(sum(1 for x in rows if x["pub"].startswith(a.pub[:8].hex())), 1)
        self.assertIsNone(r.heard_on_rf(member.pub))                         # (listed, but not "heard" for logins)
        c.close()


class NodeDirectoryTests(unittest.TestCase):
    def test_heard_nodes_are_kept_with_full_keys(self):
        h = Harness()
        try:
            a = kc.Identity.generate()
            h.events.put(("rxraw", advert(a, "Alice", ts=1000, lat=36.5, lon=-121.9)))
            h.pump(lambda: a.pub in h.room.nodes, 5)
            n = h.room.nodes[a.pub]
            self.assertEqual((n["type"], n["name"], n["lat"], n["lon"], n["adv_ts"]), (mr.ADV_TYPE_CHAT, "Alice", 36.5, -121.9, 1000))
            self.assertIsNotNone(n["rf"])
            h.events.put(("rxraw", advert(a, "Old name", ts=999)))         # an older advert: heard, but no rename
            h.pump(lambda: False, 0.3)
            self.assertEqual(h.room.nodes[a.pub]["name"], "Alice")
            h.room.flush_topology()
            h.room.store.close()
            st = mr.Store(os.path.join(h.cfg.data_dir, "room.db"))
            rows = st.read("SELECT pubkey, type, name, lat, lon, adv_ts FROM nodes")
            self.assertEqual([(bytes(r[0]), r[1], r[2], r[3], r[4], r[5]) for r in rows],
                             [(a.pub, mr.ADV_TYPE_CHAT, "Alice", 36.5, -121.9, 1000)])
            st.close()
        finally:
            h.tmp.cleanup()

    def test_an_observer_report_doesnt_let_a_web_key_send(self):
        """Only this radio hearing the key counts (the old "trust observers" setting is gone, and ignored quietly)."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "meshroom.json")
            with open(path, "w") as f:
                json.dump({"web_trust_observers": True}, f)
            with self.assertNoLogs("meshroom", "WARNING"):
                self.assertNotIn("web_trust_observers", mr.Config(path).data)
        h = Harness(mqtt_advert_ingest=True)
        try:
            a = kc.Identity.generate()
            h.room.observer_advert(advert(a, "Far away"), b"")
            self.assertIsNone(h.room.heard_on_rf(a.pub))
            self.assertIsNotNone(h.room.heard_on_rf(a.pub, trust_observers=True))       # (known: in the directory)
            self.assertFalse(h.room.kaas.web_can_send(a.pub.hex()))
        finally:
            h.close()


if __name__ == "__main__":
    unittest.main()
