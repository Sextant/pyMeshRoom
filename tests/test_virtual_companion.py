import asyncio
import os
import pathlib
import queue
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "meshroom"))
import meshroom as mr
from meshroom import (Config, CompanionStore, DEFAULT_CONFIG, LocalIdentity, Packet, RepeaterIdentity, RoomServer, Store,
                      companion_changes, encrypt_then_mac, make_advert)

try:
    from meshcore import MeshCore, EventType
except ImportError:                                         # optional: the reference client library
    MeshCore = None


class FakeModem:
    """Records what would go on the air; reports every transmission done at once."""

    def __init__(self, events):
        self.events, self.sent = events, []

    def send_packet(self, raw):
        self.sent.append(raw)
        self.events.put(("txdone", True))

    def command(self, *a, **k):
        return None

    def request(self, *a, **k):
        pass

    def set_param(self, *a, **k):
        pass

    def on_air(self):
        return [Packet.parse(r) for r in self.sent]


class Harness:
    """A real RoomServer on a fake modem, with the companion listening on a free local port."""

    def __init__(self, **cfg):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.events = queue.Queue()
        self.cfg = Config(os.path.join(d, "meshroom.json"))
        settings = dict(data_dir=d, companion_bind="127.0.0.1", companion_port=0, web_port=0, advert_interval_min=0,
                        flood_advert_interval_h=0, discovery_interval_min=0, trace_neighbours=False)
        settings.update(cfg)
        for k, v in settings.items():
            self.cfg.set(k, v)
        self.modem = FakeModem(self.events)
        self.store = Store(os.path.join(d, "room.db"))
        self.room = RoomServer(self.cfg, self.modem, LocalIdentity(os.path.join(d, "room.key")), self.store)
        self.room.events_put = self.events.put
        self.room.events_q = self.events
        self.room.companion_apply()

    @property
    def port(self):
        return self.room.vc.link.port

    def pump(self, until, timeout=30.0):
        """Run the main loop's job (events, then run_once) until until() is true."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if until():
                return True
            try:
                ev = self.events.get(timeout=0.01)
            except queue.Empty:
                ev = None
            while ev is not None:
                kind = ev[0]
                if kind.startswith("vc_"):
                    self.room.companion_event(ev)
                elif kind == "txdone":
                    self.room.on_txdone(ev[1])
                elif kind == "say":
                    self.room.room_say(ev[1])
                try:
                    ev = self.events.get_nowait()
                except queue.Empty:
                    ev = None
            self.room.run_once()
        return until()

    def run_client(self, fn, timeout=60.0):
        """fn runs on its own thread (it talks TCP) while this thread is the room's main loop."""
        box = {}

        def target():
            try:
                box["result"] = fn()
            except BaseException as e:                       # re-raised on the test thread
                box["error"] = e
        t = threading.Thread(target=target, daemon=True)
        t.start()
        self.pump(lambda: not t.is_alive(), timeout)
        if "error" in box:
            raise box["error"]
        if t.is_alive():
            raise AssertionError("client did not finish")
        return box.get("result")

    def close(self):
        if self.room.vc is not None:
            self.room.vc.close()
        self.store.close()
        self.tmp.cleanup()


class RawClient:
    """The companion protocol over TCP, by hand (as tcp_cx.py)."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=20)
        self.buf = b""

    def send(self, frame):
        self.sock.sendall(b"<" + struct.pack("<H", len(frame)) + frame)

    def recv(self):
        while True:
            i = self.buf.find(b">")
            if i >= 0 and len(self.buf) >= i + 3:
                n = struct.unpack_from("<H", self.buf, i + 1)[0]
                if len(self.buf) >= i + 3 + n:
                    f = self.buf[i + 3:i + 3 + n]
                    self.buf = self.buf[i + 3 + n:]
                    return f
            d = self.sock.recv(4096)
            if not d:
                raise ConnectionError("closed")
            self.buf += d

    def wait(self, *codes):
        """Next frame with one of these codes (pushes and other frames in between are skipped)."""
        while True:
            f = self.recv()
            if f[0] in codes:
                return f

    def call(self, frame, *codes):
        self.send(frame)
        return self.wait(*codes)

    def close(self):
        self.sock.close()


class CompanionUnitTests(unittest.TestCase):
    def test_companion_is_off_by_default(self):
        self.assertFalse(DEFAULT_CONFIG["companion_enabled"])
        self.assertEqual(DEFAULT_CONFIG["companion_key"], "")
        self.assertEqual(DEFAULT_CONFIG["companion_port"], 5000)

    def test_imported_key_agrees_with_the_room_on_shared_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            room = LocalIdentity(os.path.join(d, "k"))
            h = bytearray(mr.hashlib.sha512(b"companion").digest())    # a MeshCore private key: clamped scalar || prefix
            h[0] &= 248
            h[31] &= 127
            h[31] |= 64
            comp = RepeaterIdentity(bytes(h))
            self.assertEqual(comp.shared_secret(room.pub_key), room.shared_secret(comp.pub_key))
            seeded = RepeaterIdentity(bytes(range(32)))
            self.assertEqual(seeded.shared_secret(comp.pub_key), comp.shared_secret(seeded.pub_key))

    def test_dashboard_changes_are_validated(self):
        ch = companion_changes({"enabled": True, "name": "Phone", "port": "5001", "allow": "192.168.1.0/24, 10.0.0.5",
                                "auto_advert": True, "advert_min": 30, "advert_flood": False})
        self.assertEqual(ch["companion_port"], 5001)
        self.assertEqual(ch["companion_allow"], ["192.168.1.0/24", "10.0.0.5"])
        self.assertEqual(ch["companion_advert_interval_min"], 30)
        for bad in ({"port": 0}, {"port": 70000}, {"allow": "not-an-ip"}, {"name": ""}, {"name": "x" * 32},
                    {"advert_min": 0}, {"private_key": "abc"}):
            with self.assertRaises(ValueError):
                companion_changes(bad)
        key = bytes(range(32)).hex()
        self.assertEqual(companion_changes({"private_key": key}), {"companion_key": key})

    def test_companion_db_is_private_and_persistent(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "companion.db")
            st = CompanionStore(path)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            c = mr.VCContact(b"\x11" * 32)
            c.name, c.type, c.out_len, c.out_path = "Bob", 1, 1, b"\xAB"
            st.save_contacts([c])
            st.save_channel(1, "#test", b"\x22" * 16)
            qid = st.queue_add(b"\x10frame")
            st.close()
            st = CompanionStore(path)
            [c2] = st.contacts()
            self.assertEqual((c2.name, c2.type, c2.out_len, c2.out_path), ("Bob", 1, 1, b"\xAB"))
            self.assertEqual(st.channels()[1], ("#test", b"\x22" * 16))
            self.assertEqual(st.queued(), [(qid, b"\x10frame")])
            st.close()


class CompanionRoomTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness(companion_enabled=True, room_password="")
        self.room, self.vc = self.h.room, self.h.room.vc

    def tearDown(self):
        self.h.close()

    def test_port_is_open_only_while_enabled(self):
        port = self.h.port
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
        self.h.room.companion_event(("vc_cfg", {"companion_enabled": False}))
        self.assertIsNone(self.room.vc)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=2).close()
        self.assertTrue(os.path.exists(os.path.join(self.h.tmp.name, "companion.db")))

    def test_app_session_with_the_room_stays_off_the_air(self):
        room_pub = self.room.id.pub_key
        vc_pub = self.vc.pub
        events = self.h.events

        def client():
            c = RawClient(self.h.port)
            f = c.call(bytes([22, 3]), 13)
            self.assertEqual(f[1], mr.VC_FIRMWARE_VER_CODE)
            f = c.call(bytes([1]) + bytes(7) + b"test", 5)
            self.assertEqual(f[4:36], vc_pub)
            self.assertEqual(f[58:].decode(), DEFAULT_CONFIG["companion_name"])
            c.send(bytes([4]))
            contacts = []
            while True:
                f = c.wait(3, 4)
                if f[0] == 4:
                    break
                contacts.append(f)
            room = [x for x in contacts if x[1:33] == room_pub]
            self.assertEqual(len(room), 1)
            self.assertEqual(room[0][33], mr.ADV_TYPE_ROOM)
            f = c.call(bytes([26]) + room_pub, 6, 1)                 # login (open room)
            self.assertEqual(f[0], 6)
            f = c.wait(0x85, 0x86)
            self.assertEqual(f[0], 0x85, "login failed")
            time.sleep(1.1)                                         # (same second as the login = a retry to the room)
            ts = struct.pack("<I", int(time.time()))
            f = c.call(bytes([2, 0, 0]) + ts + room_pub[:6] + b"hello room", 6)
            ack = f[2:6]
            f = c.wait(0x82)
            self.assertEqual(f[1:5], ack)                           # the room's ACK came back
            events.put(("say", "hi from the room"))
            texts = []
            deadline = time.monotonic() + 40
            while "hi from the room" not in texts and time.monotonic() < deadline:
                c.wait(0x83)                                        # messages waiting
                while True:
                    f = c.call(bytes([10]), 16, 10)
                    if f[0] == 10:
                        break
                    self.assertEqual(f[4:10], room_pub[:6])
                    self.assertEqual(f[11], mr.TXT_TYPE_SIGNED_PLAIN)
                    texts.append(f[20:].decode())
            self.assertIn("hi from the room", texts)
            f = c.call(bytes([11]) + struct.pack("<IIBB", 869525, 250000, 11, 5), 0, 1)
            self.assertEqual(f[0], 0)                               # radio change: acknowledged...
            self.assertEqual(c.call(bytes([23]), 15, 14)[0], 15)    # private key export: disabled
            c.close()
        self.h.run_client(client, timeout=90)
        self.assertEqual(self.room.cfg.radio_freq_mhz, DEFAULT_CONFIG["radio_freq_mhz"])   # ...and ignored
        self.assertIn(vc_pub, self.room.members)
        self.assertTrue(any(a == vc_pub and t == "hello room" for _, a, t, _ in self.room.posts))
        on_air = [p for p in self.h.modem.on_air() if p is not None]
        self.assertFalse([p for p in on_air if p.ptype in (mr.PT_ANON_REQ, mr.PT_ACK, mr.PT_TXT_MSG, mr.PT_PATH,
                                                           mr.PT_RESPONSE, mr.PT_MULTIPART)],
                         "companion <-> room traffic went on the air")

    def test_messages_from_the_mesh_are_queued_and_acked_on_air(self):
        other = RepeaterIdentity(os.urandom(32))
        adv = make_advert(other, mr.ADV_TYPE_CHAT, "Alice", 0, 0)
        adv.header |= mr.ROUTE_FLOOD
        self.room.on_rx(adv.encode(), 8.0, -90)                     # heard on the air: auto-added
        self.assertIn(other.pub_key, self.vc.contacts)
        data = struct.pack("<I", int(time.time())) + b"\0" + b"hi companion"
        dm = Packet(mr.PT_TXT_MSG, bytes([self.vc.pub[0], other.pub_key[0]])
                    + encrypt_then_mac(other.shared_secret(self.vc.pub), data))
        dm.header |= mr.ROUTE_FLOOD
        self.room.on_rx(dm.encode(), 6.0, -95)
        self.assertEqual(len(self.vc.queue), 1)
        self.assertTrue(self.vc.queue[0][1].endswith(b"hi companion"))
        self.h.pump(lambda: any(p and p.ptype == mr.PT_PATH for p in self.h.modem.on_air()), timeout=5)
        self.assertTrue(any(p and p.ptype == mr.PT_PATH for p in self.h.modem.on_air()), "no path return / ACK sent")

    def test_channel_messages_reach_the_app_queue(self):
        key = mr.hashlib.sha256(b"#test").digest()[:16]
        self.vc.channels[3] = ("#test", key)
        data = struct.pack("<I", int(time.time())) + b"\0" + b"Bob: hello channel"
        pkt = Packet(mr.PT_GRP_TXT, bytes([mr.channel_hash(key)]) + encrypt_then_mac(key + bytes(16), data))
        pkt.header |= mr.ROUTE_FLOOD
        self.room.on_rx(pkt.encode(), 5.0, -100)
        frame = self.vc.queue[-1][1]
        self.assertEqual(frame[0], mr.RESP_CHANNEL_MSG_RECV_V3)
        self.assertEqual(frame[4], 3)
        self.assertTrue(frame.endswith(b"Bob: hello channel"))

    def test_a_new_connection_replaces_the_old_one(self):
        def client():
            first = RawClient(self.h.port)
            self.assertEqual(first.call(bytes([5]), 9)[0], 9)
            second = RawClient(self.h.port)
            self.assertEqual(second.call(bytes([5]), 9)[0], 9)        # the new app is answered...
            first.sock.settimeout(3)
            with self.assertRaises((ConnectionError, OSError)):
                first.recv()                                        # ...and the old connection was closed
            for _ in range(100):                                    # a burst of commands is all answered
                second.send(bytes([5]))
            for _ in range(100):
                self.assertEqual(second.wait(9)[0], 9)
            second.close()
        self.h.run_client(client)

    def test_refuses_addresses_outside_the_allow_list(self):
        self.room.companion_event(("vc_cfg", {"companion_allow": ["10.99.0.0/16"]}))
        s = socket.create_connection(("127.0.0.1", self.h.port), timeout=2)
        s.settimeout(2)
        self.assertEqual(s.recv(10), b"")                           # closed straight away
        s.close()
        self.assertTrue(self.room.vc.allowed("10.99.3.4"))
        self.assertFalse(self.room.vc.allowed("127.0.0.1"))


@unittest.skipIf(MeshCore is None, "meshcore_py (the reference client library) is not installed")
class MeshcorePyClientTests(unittest.TestCase):
    """The same protocol as apps use, through the meshcore_py library over TCP."""

    def setUp(self):
        self.h = Harness(companion_enabled=True, room_password="")

    def tearDown(self):
        self.h.close()

    def test_meshcore_py_session(self):
        room_pub = self.h.room.id.pub_key.hex()
        port = self.h.port
        out = {}

        async def session():
            mc = await MeshCore.create_tcp("127.0.0.1", port, default_timeout=10)
            assert mc is not None, "appstart failed"
            out["self"] = mc.self_info
            out["device"] = (await mc.commands.send_device_query()).payload
            await mc.ensure_contacts()
            out["contacts"] = dict(mc.contacts)
            room = mc.get_contact_by_key_prefix(room_pub[:12])
            out["login"] = await mc.commands.send_login_sync(room, "", timeout=10)
            await asyncio.sleep(1.1)
            r = await mc.commands.send_msg(room, "hello from meshcore_py")
            ack = r.payload["expected_ack"].hex()
            out["ack"] = await mc.dispatcher.wait_for_event(EventType.ACK, attribute_filters={"code": ack}, timeout=10)
            out["radio"] = await mc.commands.set_radio(869.525, 250, 11, 5)
            out["chan_set"] = await mc.commands.set_channel(2, "#pymeshroom")
            out["chan"] = (await mc.commands.get_channel(2)).payload
            out["stats"] = (await mc.commands.get_stats_core()).payload
            out["bat"] = (await mc.commands.get_bat()).payload
            out["key"] = await mc.commands.export_private_key()
            await mc.disconnect()

        self.h.run_client(lambda: asyncio.run(session()), timeout=90)
        self.assertEqual(out["self"]["name"], DEFAULT_CONFIG["companion_name"])
        self.assertEqual(out["device"]["fw ver"], mr.VC_FIRMWARE_VER_CODE)
        self.assertIn(room_pub, out["contacts"])
        self.assertEqual(out["login"].type, EventType.LOGIN_SUCCESS)
        self.assertIsNotNone(out["ack"])
        self.assertEqual(out["radio"].type, EventType.OK)
        self.assertEqual(out["chan_set"].type, EventType.OK)
        self.assertEqual(out["chan"]["channel_name"], "#pymeshroom")
        self.assertIn("uptime_secs", out["stats"])
        self.assertEqual(out["key"].type, EventType.DISABLED)
        self.assertTrue(any(t == "hello from meshcore_py" for _, _, t, _ in self.h.room.posts))


if __name__ == "__main__":
    unittest.main()
