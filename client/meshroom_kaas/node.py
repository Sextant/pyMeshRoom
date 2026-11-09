"""Helpers that make a KaaS connection act like a MeshCore chat node: adverts, contacts, DMs, channels and rooms.

All the crypto happens here, in the client: the server only ever sees encrypted packets."""
import collections
import logging
import math
import os
import queue
import struct
import threading
import time

from .crypto import (PUBLIC_CHANNEL_KEY, Identity, channel_hash, ed25519_verify, encrypt_then_mac, hashtag_channel_key,
                     mac_then_decrypt, sha256)
from .packet import (ADV_TYPE_CHAT, ADV_TYPE_ROOM, PT_ACK, PT_ADVERT, PT_ANON_REQ, PT_GRP_TXT, PT_MULTIPART, PT_PATH,
                     PT_RESPONSE, PT_TXT_MSG, TXT_TYPE_PLAIN, TXT_TYPE_SIGNED_PLAIN, Packet, path_bytes, path_valid)

log = logging.getLogger("meshroom_kaas")

ADV_LATLON_MASK, ADV_FEAT1_MASK, ADV_FEAT2_MASK, ADV_NAME_MASK = 0x10, 0x20, 0x40, 0x80
MAX_ADVERT_DATA_SIZE = 32
MAX_TEXT_LEN = 160
UNLIMITED = (PT_ACK, PT_PATH)           # the server's per-key rate limit doesn't apply to these


class LoginFailed(Exception):
    pass


def _cut(b, n):
    """At most n bytes of UTF-8, never ending mid-character."""
    b = b[:n]
    while b:
        try:
            b.decode()
            return b
        except UnicodeDecodeError:
            b = b[:-1]
    return b


def _pub(x):
    if isinstance(x, Contact):
        return x.pub
    b = bytes.fromhex(x) if isinstance(x, str) else bytes(x)
    if len(b) != 32:
        raise ValueError("a public key is 32 bytes")
    return b


class Contact:
    """Another node. out_path/out_len: the route to it, learned when it sends us a path (None: flood)."""

    def __init__(self, pub, name="", type=ADV_TYPE_CHAT):
        self.pub, self.name, self.type = pub, name, type
        self.lat = self.lon = None
        self.out_path, self.out_len = b"", None
        self.last_advert = None

    hash = property(lambda s: s.pub[0])

    def __repr__(self):
        return "<Contact %s %s>" % (self.pub[:6].hex().upper(), self.name)


class Channel:
    def __init__(self, name, key16):
        self.name, self.key = name, bytes(key16)
        self.hash = channel_hash(self.key)

    def __repr__(self):
        return "<Channel %s>" % self.name


class Room(Contact):
    """A room server joined with Node.join_room. Its posts arrive at on_post callbacks; post() sends one."""

    def __init__(self, node, pub, name=""):
        super().__init__(pub, name, ADV_TYPE_ROOM)
        self.node = node
        self.sync_since = 0             # newest post received: the room resumes after it on the next login
        self.logged_in, self.is_admin, self.perms = False, False, 0
        self.handlers = []
        self.recent = collections.OrderedDict()

    def on_post(self, fn):
        """fn(room, author_prefix (4 bytes of the author's key), text, ts). Usable as a decorator."""
        self.handlers.append(fn)
        return fn

    def post(self, text, attempts=3):
        """Post to the room. True once the room ACKs it."""
        return self.node.send_dm(self, text, attempts)


class Node:
    """A chat node on the mesh, through a KaasClient.

        node = Node(client, Identity.load_or_create("bot.key"), "WeatherBot")
        node.advert()
        @node.on_dm
        def hello(contact, text, ts): node.send_dm(contact, "you said " + text)

    Callbacks run one at a time on the node's own thread, so they may block (send_dm waits for the ACK)."""

    def __init__(self, client, identity, name, lat=0.0, lon=0.0, node_type=ADV_TYPE_CHAT):
        self.client, self.id, self.name = client, identity, name
        self.lat, self.lon, self.node_type = lat, lon, node_type
        self.contacts = {}                  # pub -> Contact (or Room)
        self.channels = []
        self.expected = {}                  # ACK -> Event
        self.logins = {}                    # room pub -> (Event, result box)
        self.seen = collections.OrderedDict()
        self.dm_handlers, self.channel_handlers, self.advert_handlers = [], [], []
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.limited = collections.deque()   # when our rate-limited sends went (the server's rolling window)
        self.last_ts = 0
        self.jobs = queue.Queue()
        self.recent_dms = collections.OrderedDict()
        threading.Thread(target=self._run_callbacks, name="kaas-node", daemon=True).start()
        client.on_packet(self._on_packet)

    # ---------------------------------------------------------------- callbacks

    def on_dm(self, fn):
        """fn(contact, text, ts) for each direct message to this node. Usable as a decorator."""
        self.dm_handlers.append(fn)
        return fn

    def on_channel(self, fn):
        """fn(channel, sender_name, text, ts) for each message on a channel added with add_channel."""
        self.channel_handlers.append(fn)
        return fn

    def on_advert(self, fn):
        """fn(contact) for each advert heard (the contact is updated first)."""
        self.advert_handlers.append(fn)
        return fn

    def _run_callbacks(self):
        while True:
            fn, args = self.jobs.get()
            try:
                fn(*args)
            except Exception:
                log.exception("callback")

    def _call(self, handlers, *args):
        for fn in list(handlers):
            self.jobs.put((fn, args))

    # ---------------------------------------------------------------- sending

    def unique_time(self):
        with self.lock:
            self.last_ts = max(int(time.time()), self.last_ts + 1)
            return self.last_ts

    def send(self, pkt, wait=True):
        """Send a packet, keeping to the server's per-key rate limit (ACKs and path returns go at once)."""
        self._seen(pkt.packet_hash())
        if pkt.ptype in UNLIMITED:
            return self.client.send(pkt, wait=wait)
        hello = self.client.hello or {}
        burst, window = int(hello.get("send_burst", 3)), float(hello.get("send_window_s", 20))
        with self.send_lock:
            for _ in range(3):
                while len(self.limited) >= burst:
                    gap = self.limited[0] + window - time.monotonic()
                    if gap > 0:
                        time.sleep(gap)
                    self.limited.popleft()
                self.limited.append(time.monotonic())
                res = self.client.send(pkt, wait=True)
                if res.status == "dropped" and "rate limit" in (res.get("reason") or ""):
                    time.sleep(float(res.get("retry_after") or 0.1))   # (another client on the same key, or network jitter)
                    continue
                return res
            return res

    def airtime_ms(self, length):
        r = (self.client.hello or {}).get("radio")
        if not r:
            return 400
        ts = (1 << r["sf"]) / r["bw_hz"]
        de = 1 if ts > 0.016 else 0
        n = 8 + max(math.ceil((8 * length - 4 * r["sf"] + 28 + 16) / (4 * (r["sf"] - 2 * de))) * r["cr"], 0)
        return int((16 + 4.25 + n) * ts * 1000)

    def ack_timeout(self, pkt):
        """Seconds to wait for an ACK, as the firmware reckons it."""
        t = self.airtime_ms(len(pkt.encode()))
        if pkt.is_flood:
            return (500 + 16 * t) / 1000.0
        return (500 + (t * 6 + 250) * (pkt.hop_count + 1)) / 1000.0

    def _route(self, c, ptype, payload, flood=False):
        if c.out_len is None or flood:
            return Packet.flood(ptype, payload)
        return Packet.direct(ptype, payload, c.out_path, c.out_len)

    def _datagram(self, ptype, c, data):
        return bytes([c.pub[0], self.id.hash]) + encrypt_then_mac(self.id.shared_secret(c.pub), data)

    def _path_return(self, c, path, plen, extra_type=None, extra=b""):
        data = bytes([plen]) + bytes(path[:path_bytes(plen)])
        data += bytes([extra_type]) + extra if extra else b"\xFF" + os.urandom(4)
        return bytes([c.pub[0], self.id.hash]) + encrypt_then_mac(self.id.shared_secret(c.pub), data)

    # ---------------------------------------------------------------- what you can do

    def advert(self, flood=False):
        """Announce this node: zero-hop (nodes that hear the radio directly) or flood (the whole mesh)."""
        flags, body = self.node_type, b""
        if self.lat or self.lon:
            flags |= ADV_LATLON_MASK
            body += struct.pack("<ii", int(self.lat * 1e6), int(self.lon * 1e6))
        name = _cut(str(self.name).encode(), MAX_ADVERT_DATA_SIZE - 1 - len(body))
        if name:
            flags |= ADV_NAME_MASK
        app = bytes([flags]) + body + name
        ts = struct.pack("<I", self.unique_time())
        payload = self.id.pub + ts + self.id.sign(self.id.pub + ts + app) + app
        return self.send(Packet.flood(PT_ADVERT, payload) if flood else Packet.direct(PT_ADVERT, payload))

    def contact(self, pub, name=""):
        """The contact for a public key (32 bytes or hex), added if new."""
        pub = _pub(pub)
        with self.lock:
            c = self.contacts.get(pub)
            if c is None:
                c = self.contacts[pub] = Contact(pub, name)
        return c

    def find(self, name_or_prefix):
        """A contact by name (exact, case-insensitive) or by the start of its public key in hex."""
        s = name_or_prefix.lower()
        for c in list(self.contacts.values()):
            if c.name.lower() == s or c.pub.hex().startswith(s):
                return c
        return None

    def send_dm(self, to, text, attempts=3):
        """A direct message (to a Contact, or a public key). Retries until ACKed, the last try by flood.
        True once ACKed."""
        c = to if isinstance(to, Contact) else self.contact(to)
        body = _cut(text.encode(), MAX_TEXT_LEN)
        ts = self.unique_time()
        for attempt in range(attempts):
            data = struct.pack("<I", ts) + bytes([(TXT_TYPE_PLAIN << 2) | (attempt & 3)]) + body
            ack = sha256(data, self.id.pub)[:4]
            ev = self.expected[ack] = threading.Event()
            flood = attempt > 0 and attempt == attempts - 1
            pkt = self._route(c, PT_TXT_MSG, self._datagram(PT_TXT_MSG, c, data), flood)
            res = self.send(pkt)
            if res.ok and ev.wait(self.ack_timeout(pkt) + 2.0):
                return True
            if not res.ok:
                log.info("DM to %s: %s (%s)", c, res.status, res.get("reason"))
            self.expected.pop(ack, None)
        return False

    def add_channel(self, name, secret=None):
        """A channel to read and send on: "Public", "#hashtag" (key from its name), or a private channel's name with
        its 16-byte secret (bytes, or hex)."""
        if secret is not None:
            key = bytes.fromhex(secret) if isinstance(secret, str) else bytes(secret)
            if len(key) != 16:
                raise ValueError("a channel secret is 16 bytes")
        elif name.lower() == "public":
            key = PUBLIC_CHANNEL_KEY
        elif name.startswith("#"):
            key = hashtag_channel_key(name)
        else:
            raise ValueError('use "Public", a "#hashtag", or give the private channel\'s secret')
        ch = Channel(name, key)
        self.channels.append(ch)
        return ch

    def send_channel(self, channel, text):
        """A message on a channel ("Name: text", as the apps send it). Channel messages have no ACK."""
        prefix = (self.name + ": ").encode()
        data = struct.pack("<I", self.unique_time()) + b"\0" + prefix + _cut(text.encode(), max(0, MAX_TEXT_LEN - len(prefix)))
        payload = bytes([channel.hash]) + encrypt_then_mac(channel.key + bytes(16), data)
        return self.send(Packet.flood(PT_GRP_TXT, payload))

    def join_room(self, pub, password="", timeout=30.0):
        """Log in to a room server. Its posts then come to the Room's on_post callbacks. Raises LoginFailed."""
        pub = _pub(pub)
        with self.lock:
            room = self.contacts.get(pub)
            if not isinstance(room, Room):
                old = room
                room = Room(self, pub, old.name if old else "")
                if old is not None:
                    room.out_path, room.out_len, room.lat, room.lon = old.out_path, old.out_len, old.lat, old.lon
                self.contacts[pub] = room
        data = struct.pack("<II", self.unique_time(), room.sync_since) + password.encode()[:15]
        payload = bytes([pub[0]]) + self.id.pub + encrypt_then_mac(self.id.shared_secret(pub), data)
        ev, box = threading.Event(), {}
        self.logins[pub] = (ev, box)
        res = self.send(self._route(room, PT_ANON_REQ, payload))
        if not res.ok:
            raise LoginFailed("the login wasn't sent: %s" % (res.get("reason") or res.status))
        if not ev.wait(timeout):
            self.logins.pop(pub, None)
            raise LoginFailed("no answer from the room (wrong password, or it didn't hear the login)")
        if not box.get("ok"):
            raise LoginFailed("the room refused the login")
        room.logged_in = True
        return room

    # ---------------------------------------------------------------- receiving (the client's reader thread)

    def _seen(self, h):
        with self.lock:
            if h in self.seen:
                return True
            self.seen[h] = None
            while len(self.seen) > 2048:
                self.seen.popitem(last=False)
            return False

    def _on_packet(self, pkt):
        if self._seen(pkt.packet_hash()):
            return                                          # a copy heard again, or our own packet going out
        if pkt.is_direct and pkt.hop_count > 0:
            return                                          # still on its way through repeaters: not for us yet
        t, p = pkt.ptype, pkt.payload
        if t == PT_ADVERT:
            self._rx_advert(pkt)
        elif t in (PT_TXT_MSG, PT_RESPONSE, PT_PATH):
            self._rx_peer(pkt)
        elif t == PT_ACK and len(p) >= 4:
            self._rx_ack(p[:4])
        elif t == PT_MULTIPART and len(p) >= 5 and (p[0] & 0x0F) == PT_ACK:
            self._rx_ack(p[1:5])
        elif t == PT_GRP_TXT:
            self._rx_group(pkt)

    def _rx_ack(self, ack):
        ev = self.expected.pop(bytes(ack), None)
        if ev is not None:
            ev.set()

    def _rx_advert(self, pkt):
        p = pkt.payload
        if len(p) < 101:
            return
        pub, ts, sig, app = p[:32], struct.unpack_from("<I", p, 32)[0], p[36:100], p[100:100 + MAX_ADVERT_DATA_SIZE]
        if pub == self.id.pub or not ed25519_verify(pub, sig, pub + p[32:36] + app):
            return
        flags, i = app[0], 1
        lat = lon = None
        if flags & ADV_LATLON_MASK:
            if len(app) < 9:
                return
            la, lo = struct.unpack_from("<ii", app, 1)
            lat, lon = (la / 1e6, lo / 1e6) if la or lo else (None, None)
            i += 8
        i += 2 * bool(flags & ADV_FEAT1_MASK) + 2 * bool(flags & ADV_FEAT2_MASK)
        name = app[i:].split(b"\0", 1)[0].decode(errors="replace") if flags & ADV_NAME_MASK else ""
        c = self.contact(pub)
        if c.last_advert is not None and ts <= c.last_advert:
            return                                          # an older advert (or a replay)
        c.name, c.type, c.lat, c.lon, c.last_advert = name, flags & 0x0F, lat, lon, ts
        self._call(self.advert_handlers, c)

    def _rx_peer(self, pkt):
        p = pkt.payload
        if len(p) <= 4 or p[0] != self.id.hash:
            return
        for c in [c for c in list(self.contacts.values()) if c.pub[0] == p[1]]:
            data = mac_then_decrypt(self.id.shared_secret(c.pub), p[2:])
            if data is None:
                continue
            if pkt.ptype == PT_PATH:
                self._rx_path(pkt, c, data)
            elif pkt.ptype == PT_TXT_MSG:
                self._rx_txt(pkt, c, data)
            elif pkt.ptype == PT_RESPONSE:
                self._rx_response(c, data)
            return

    def _rx_path(self, pkt, c, data):
        plen = data[0]
        if not path_valid(plen):
            return
        k = 1 + path_bytes(plen)
        path = bytes(data[1:k])
        extra_type = data[k] & 0x0F if k < len(data) else 0xFF
        extra = data[k + 1:]
        c.out_path, c.out_len = path, plen                  # how to reach them directly from now on
        if extra_type == PT_ACK and len(extra) >= 4:
            self._rx_ack(extra[:4])
        elif extra_type == PT_RESPONSE and extra:
            self._rx_response(c, extra)
        if pkt.is_flood:                                    # tell them the way back to us, sent direct on that path
            self.send(Packet.direct(PT_PATH, self._path_return(c, pkt.path, pkt.path_len), path, plen), wait=False)

    def _reply_ack(self, pkt, c, ack):
        if pkt.is_flood:                                    # the path to us, carrying the ACK
            out = Packet.flood(PT_PATH, self._path_return(c, pkt.path, pkt.path_len, PT_ACK, ack), pkt.hash_size)
        elif c.out_len is None:
            out = Packet.flood(PT_ACK, ack)
        else:
            out = Packet.direct(PT_ACK, ack, c.out_path, c.out_len)
        self.send(out, wait=False)

    def _rx_txt(self, pkt, c, data):
        if len(data) <= 5:
            return
        ts, flags = struct.unpack_from("<I", data, 0)[0], data[4] >> 2
        if flags == TXT_TYPE_PLAIN:
            text = data[5:].split(b"\0", 1)[0]
            self._reply_ack(pkt, c, sha256(data[:5 + len(text)], c.pub)[:4])
            if self._fresh(self.recent_dms, (c.pub, ts, text)):
                self._call(self.dm_handlers, c, text.decode(errors="replace"), ts)
        elif flags == TXT_TYPE_SIGNED_PLAIN and len(data) > 9 and isinstance(c, Room):
            text = data[9:].split(b"\0", 1)[0]
            self._reply_ack(pkt, c, sha256(data[:9 + len(text)], self.id.pub)[:4])
            c.sync_since = max(c.sync_since, ts)
            if self._fresh(c.recent, (ts, data[5:9], text)):  # (a push retried after a lost ACK: once only)
                self._call(c.handlers, c, bytes(data[5:9]), text.decode(errors="replace"), ts)

    @staticmethod
    def _fresh(recent, k):
        if k in recent:
            return False
        recent[k] = None
        while len(recent) > 256:
            recent.popitem(last=False)
        return True

    def _rx_response(self, c, data):
        w = self.logins.pop(c.pub, None)
        if w is None or len(data) < 5:
            return
        ok = data[4] == 0                                   # RESP_SERVER_LOGIN_OK
        if ok and isinstance(c, Room) and len(data) >= 8:
            c.is_admin, c.perms = data[6] == 1, data[7]
        w[1]["ok"] = ok
        w[0].set()

    def _rx_group(self, pkt):
        p = pkt.payload
        if len(p) <= 3:
            return
        for ch in self.channels:
            if ch.hash != p[0]:
                continue
            data = mac_then_decrypt(ch.key + bytes(16), p[1:])
            if data is None:
                continue
            if len(data) < 5 or data[4] >> 2:
                return
            text = data[5:].split(b"\0", 1)[0].decode(errors="replace")
            sender, sep, msg = text.partition(": ")
            if not sep:
                sender, msg = "", text
            self._call(self.channel_handlers, ch, sender, msg, struct.unpack_from("<I", data, 0)[0])
            return
