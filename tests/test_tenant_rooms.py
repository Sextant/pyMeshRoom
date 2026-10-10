import http.cookiejar
import json
import os
import pathlib
import socket
import stat
import struct
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "meshroom"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import meshroom as mr
from meshroom import (DEFAULT_CONFIG, Packet, RepeaterIdentity, check_web_password, encrypt_then_mac,
                      tenant_spec)
from test_virtual_companion import Harness, RawClient


def spec(name="Hiking", path="hiking", **kw):
    body = dict(name=name, path=path, room_password="join", admin_password="boss", web_password="tenantpw")
    body.update(kw)
    return tenant_spec(body)


def anon_login(node, room_pub, password, ts=None):
    """A MeshCore app's room login (ANON_REQ), flooded, as raw bytes."""
    data = struct.pack("<II", ts or int(time.time()), 0) + password.encode()
    pkt = Packet(mr.PT_ANON_REQ, bytes([room_pub[0]]) + node.pub_key + encrypt_then_mac(node.shared_secret(room_pub), data))
    pkt.header |= mr.ROUTE_FLOOD
    return pkt.encode()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class TenantSpecTests(unittest.TestCase):
    def test_off_by_default(self):
        self.assertEqual(DEFAULT_CONFIG["tenant_rooms"], [])

    def test_example_config_loads_tenant_rooms_as_a_list(self):
        import tempfile, shutil
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "meshroom.json")
            shutil.copy(pathlib.Path(__file__).resolve().parents[1] / "meshroom" / "meshroom.json.example", path)
            cfg = mr.Config(path)
            self.assertEqual(cfg.tenant_rooms, [])
            cfg.set("tenant_rooms", [dict(name="A", path="a", public_key="00")])
            self.assertEqual(mr.Config(path).tenant_rooms, [dict(name="A", path="a", public_key="00")])

    def test_form_is_validated(self):
        s = spec()
        self.assertEqual((s["name"], s["path"], s["room_password"], s["admin_password"], s["private_key"]),
                         ("Hiking", "hiking", "join", "boss", ""))
        self.assertTrue(check_web_password("tenantpw", s["web_password_hash"]))
        self.assertFalse(check_web_password("wrong", s["web_password_hash"]))
        self.assertNotIn("tenantpw", json.dumps(s))                 # only the hash travels on
        for bad in (dict(path="api"), dict(path="static"), dict(path="Has Space"), dict(path=""), dict(name=""),
                    dict(web_password="short"), dict(admin_password="join"), dict(room_password="x" * 16),
                    dict(private_key="abc")):
            with self.assertRaises(ValueError, msg=bad):
                spec(**bad)
        with self.assertRaises(ValueError):
            tenant_spec(dict(name="X", path="hiking", web_password="tenantpw"), taken_paths={"hiking"})
        self.assertEqual(spec(path="/Hiking-2/")["path"], "hiking-2")


class TenantRoomTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness(companion_enabled=True, room_password="")
        self.room = self.h.room
        self.room.tenant_create(spec())
        self.t = next(iter(self.room.tenants.values()))

    def tearDown(self):
        self.h.close()

    def test_tenant_is_stored_apart_and_config_holds_only_name_path_key(self):
        [entry] = self.h.cfg.tenant_rooms
        self.assertEqual(set(entry), {"name", "path", "public_key"})
        self.assertEqual(entry["public_key"], self.t.key)
        db = os.path.join(self.h.tmp.name, "tenants", self.t.key + ".db")
        self.assertTrue(os.path.exists(db))
        self.assertEqual(stat.S_IMODE(os.stat(db).st_mode), 0o600)
        self.h.pump(lambda: False, timeout=0.3)                    # (settings reach the database on its writer thread)
        with open(os.path.join(self.h.tmp.name, "meshroom.json")) as f:
            cfg_text = f.read()
        self.assertNotIn(self.t.cfg.private_key, cfg_text)
        self.assertNotIn("boss", cfg_text)

    def test_tenant_cannot_change_anything_outside_its_room(self):
        t, host = self.t, self.room
        for cmd in ("reboot", "restart", "discover", "set path.hash.mode 2", "set push.pace.min 900", "set push.gap.flood 0"):
            self.assertTrue(t.handle_cli(cmd).startswith("Err"), cmd)
        self.assertEqual(host.cfg.path_hash_mode, 0)
        self.assertEqual(t.handle_cli("set name Trail Crew"), "OK")
        self.assertEqual(t.cfg.name, "Trail Crew")
        self.assertEqual(host.cfg.name, DEFAULT_CONFIG["name"])     # the main room keeps its name
        with self.assertRaises(ValueError):
            t.cfg.set("radio_freq_mhz", 433.0)
        with self.assertRaises(ValueError):
            t.cfg.web_port = 80
        self.assertEqual(t.cfg.radio_freq_mhz, host.cfg.radio_freq_mhz)   # (server settings read through)

    def test_rf_login_joins_only_the_tenant_and_is_answered_on_air(self):
        node = RepeaterIdentity(os.urandom(32))
        self.room.on_rx(anon_login(node, self.t.id.pub_key, "nope"), 6.0, -90)
        self.assertNotIn(node.pub_key, self.t.members)              # wrong password: ignored
        self.room.on_rx(anon_login(node, self.t.id.pub_key, "join", int(time.time()) + 1), 6.0, -90)
        self.assertIn(node.pub_key, self.t.members)
        self.assertNotIn(node.pub_key, self.room.members)
        self.assertFalse(self.t.members[node.pub_key].is_admin)
        sent = lambda: [p for p in self.h.modem.on_air() if p and p.ptype == mr.PT_PATH and p.payload[1] == self.t.self_hash]
        self.assertTrue(self.h.pump(lambda: sent(), timeout=5), "the tenant's login reply didn't go on the air")
        boss = RepeaterIdentity(os.urandom(32))
        self.room.on_rx(anon_login(boss, self.t.id.pub_key, "boss"), 6.0, -90)
        self.assertTrue(self.t.members[boss.pub_key].is_admin)

    def test_companion_session_with_a_tenant_stays_off_the_air(self):
        t = self.t
        self.h.pump(lambda: t.id.pub_key in self.room.vc.contacts, timeout=20)   # its advert introduced it
        tpub = t.id.pub_key

        def client():
            c = RawClient(self.h.port)
            c.call(bytes([1]) + bytes(7) + b"test", 5)
            self.assertEqual(c.call(bytes([26]) + tpub + b"join", 6, 1)[0], 6)
            self.assertEqual(c.wait(0x85, 0x86)[0], 0x85)
            time.sleep(1.1)
            ts = struct.pack("<I", int(time.time()))
            ack = c.call(bytes([2, 0, 0]) + ts + tpub[:6] + b"hello tenant", 6)[2:6]
            self.assertEqual(c.wait(0x82)[1:5], ack)
            c.close()
        self.h.run_client(client, timeout=60)
        self.assertIn(self.room.vc.pub, t.members)
        self.assertTrue(any(x == "hello tenant" for _, _, x, _ in t.posts))
        self.assertFalse(any(x == "hello tenant" for _, _, x, _ in self.room.posts))
        on_air = [p for p in self.h.modem.on_air() if p is not None]
        self.assertFalse([p for p in on_air if p.ptype in (mr.PT_ANON_REQ, mr.PT_ACK, mr.PT_TXT_MSG, mr.PT_PATH, mr.PT_RESPONSE)],
                         "companion <-> tenant traffic went on the air")
        self.assertTrue([p for p in on_air if p.ptype == mr.PT_ADVERT and p.payload[:32] == tpub], "the tenant never adverted")

    def test_one_push_at_a_time_across_rooms(self):
        t, host = self.t, self.room
        for r in (host, t):                                         # a member and a post waiting in each room
            m = r.put_member(os.urandom(32))
            m.perms, m.out_path_len, m.out_path, m.last_activity = mr.PERM_READ_WRITE, 0, b"", int(time.time())
            r.posts.append((int(time.time()) - 60, os.urandom(32), "news", None))
            r.next_push = 0.0
        host.push_rooms()
        pushing = [r for r in (host, t) if any(m.pending_ack for m in r.members.values())]
        self.assertEqual(len(pushing), 1)                           # one room pushed...
        host.push_rooms()
        self.assertEqual(len([r for r in (host, t) if any(m.pending_ack for m in r.members.values())]), 1)   # ...the other waits

    def test_survives_a_restart_and_delete_erases_it(self):
        node = RepeaterIdentity(os.urandom(32))
        self.room.on_rx(anon_login(node, self.t.id.pub_key, "join"), 6.0, -90)
        key, tmp = self.t.id.pub_key, self.h.tmp
        d = tmp.name
        self.h.close(keep=True)
        self.h = h2 = Harness(data_dir=d, companion_enabled=True)
        h2.tmp = tmp                                                # (cleaned up by tearDown)
        t2 = h2.room.tenants[key]
        self.assertEqual((t2.cfg.name, t2.cfg.path, t2.cfg.room_password), ("Hiking", "hiking", "join"))
        self.assertIn(node.pub_key, t2.members)
        h2.room.tenant_delete(key)
        self.assertFalse(h2.room.tenants)
        self.assertEqual(h2.cfg.tenant_rooms, [])
        self.assertFalse(os.path.exists(os.path.join(d, "tenants", mr.hexs(key) + ".db")))


class TenantWebTests(unittest.TestCase):
    def setUp(self):
        self.wport = free_port()
        self.h = Harness(web_port=self.wport, web_bind="127.0.0.1", web_password="adminpw")
        self.h.room.publish_web_state()
        mr.WebUI(self.h.room, self.h.events)
        self.stop = False
        self.pumper = threading.Thread(target=lambda: self.h.pump(lambda: self.stop, timeout=300), daemon=True)
        self.pumper.start()

    def tearDown(self):
        self.stop = True
        self.pumper.join()
        self.h.close()

    def client(self):
        jar = http.cookiejar.CookieJar()
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def req(self, op, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        r = urllib.request.Request("http://127.0.0.1:%d%s" % (self.wport, path), data=data,
                                   headers={"Content-Type": "application/json"} if data else {})
        try:
            with op.open(r, timeout=10) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def wait(self, cond, timeout=10):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if cond():
                return True
            time.sleep(0.05)
        return cond()

    def test_admin_creates_tenant_and_tenant_page_is_scoped(self):
        room = self.h.room
        admin, tenant, other_tenant = self.client(), self.client(), self.client()
        form = dict(name="Hiking", path="hiking", room_password="join", admin_password="boss", web_password="tenantpw")
        self.assertEqual(self.req(tenant, "/api/tenants", form)[0], 401)
        self.assertEqual(self.req(admin, "/api/login", dict(password="adminpw"))[0], 200)
        self.assertEqual(self.req(admin, "/api/tenants", dict(form, path="api"))[0], 400)
        self.assertEqual(self.req(admin, "/api/tenants", form)[0], 200)
        self.assertEqual(self.req(admin, "/api/tenants", dict(form, name="Other", path="other"))[0], 200)
        self.assertTrue(self.wait(lambda: len(room.tenants) == 2))
        t = room.web_tenants["hiking"]
        rows = json.loads(self.req(admin, "/api/tenants")[1])["rooms"]
        self.assertEqual({r["path"] for r in rows}, {"hiking", "other"})

        status, page = self.req(tenant, "/hiking")                   # redirected to /hiking/
        self.assertEqual(status, 200)
        self.assertIn(b"window.TENANT=true", page)
        self.assertFalse(json.loads(self.req(tenant, "/hiking/api/session")[1])["admin"])
        self.assertEqual(self.req(tenant, "/hiking/api/chat", dict(text="hi"))[0], 401)
        self.assertEqual(self.req(tenant, "/hiking/api/login", dict(password="adminpw"))[0], 401)
        self.assertEqual(self.req(tenant, "/hiking/api/login", dict(password="tenantpw"))[0], 200)
        self.assertTrue(json.loads(self.req(tenant, "/hiking/api/session")[1])["admin"])
        self.assertEqual(self.req(tenant, "/hiking/api/chat", dict(text="hello hikers"))[0], 200)
        self.assertTrue(self.wait(lambda: any(x == "hello hikers" for _, _, x, _ in t.posts)))
        self.assertFalse(any(x == "hello hikers" for _, _, x, _ in room.posts))
        st = json.loads(self.req(tenant, "/hiking/api/state")[1])
        self.assertEqual((st["room"]["name"], st["room"]["tenant"]), ("Hiking", True))
        self.assertEqual(st["room"]["key"], t.key)
        self.assertEqual(self.req(tenant, "/hiking/api/map")[0], 200)
        # a tenant login is good for its own room only
        self.assertEqual(self.req(tenant, "/api/tenants")[0], 401)
        self.assertEqual(self.req(tenant, "/api/chat", dict(text="x"))[0], 401)
        self.assertEqual(self.req(tenant, "/other/api/chat", dict(text="x"))[0], 401)
        self.assertEqual(self.req(other_tenant, "/hiking/api/chat", dict(text="x"))[0], 401)
        # the main admin may act on a tenant's page
        self.assertEqual(self.req(admin, "/hiking/api/advert", dict(flood=False))[0], 200)
        # reset the tenant's web password: its sessions end
        self.assertEqual(self.req(admin, "/api/tenants/%s/password" % t.key, dict(web_password="newpass1"))[0], 200)
        self.assertFalse(json.loads(self.req(tenant, "/hiking/api/session")[1])["admin"])
        self.assertTrue(self.wait(lambda: check_web_password("newpass1", t.cfg.web_password_hash)))
        # deleting needs the admin password
        self.assertEqual(self.req(admin, "/api/tenants/%s/delete" % t.key, dict(password="wrong"))[0], 403)
        self.assertIn("hiking", room.web_tenants)
        self.assertEqual(self.req(admin, "/api/tenants/%s/delete" % t.key, dict(password="adminpw"))[0], 200)
        self.assertTrue(self.wait(lambda: "hiking" not in room.web_tenants))
        self.assertEqual(self.req(tenant, "/hiking/")[0], 404)


if __name__ == "__main__":
    unittest.main()
