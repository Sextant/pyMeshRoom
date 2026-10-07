#!/usr/bin/env python3
"""
meshroom.py - a MeshCore room server for Linux (e.g. Raspberry Pi Zero 2 W),
using a MeshCore KISS modem (examples/kiss_modem firmware) as the radio.

Ported from the C++ simple_room_server firmware (branch room-server-improvements),
including: persistent members/posts/routes (SQLite), multi-route table with scoring,
adaptive push gaps, hop-sorted push rounds, late-ACK handling, backoff + give-up for
stuck members, catch-up cap for new members, companion name cache, repeater
neighbours (app neighbours screen), and a built-in web dashboard.

The room's identity is the modem's: its private key never leaves the radio. Signing
and key exchange are done by the modem (SetHardware SignData / KeyExchange); AES and
HMAC are done locally with the per-member shared secrets.

Requirements:  python3 >= 3.9, pyserial, cryptography
    sudo apt install python3-serial python3-cryptography

Usage:
    python3 meshroom.py --config meshroom.json          # creates a default config if missing
"""

import argparse
import hashlib
import heapq
import hmac
import collections
import json
import logging
import math
import os
import queue
import random
import signal
import sqlite3
import struct
import sys
import threading
import time

try:
    import serial
except ImportError:
    sys.exit("pyserial missing:  sudo apt install python3-serial")
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("cryptography missing:  sudo apt install python3-cryptography")

log = logging.getLogger("meshroom")
FIRMWARE_VERSION = "meshroom-py 3.9"
FIRMWARE_VER_LEVEL = 1

# ============================================================================
# Configuration
# ============================================================================

DEFAULT_CONFIG = {
    "serial": "/dev/ttyACM0",
    "baud": 115200,
    "name": "Pi Room",
    "lat": 0.0,
    "lon": 0.0,
    "admin_password": "password",
    "room_password": "hello",
    "allow_read_only": False,
    "data_dir": "./meshroom_data",
    "max_posts": 100,               # posts kept (history depth)
    "catchup_max": 10,              # brand-new members get only the newest N
    "path_hash_mode": 0,            # 0/1/2 = 1/2/3-byte path hashes for floods we originate
    "advert_interval_min": 60,      # zero-hop advert (0 = off)
    "flood_advert_interval_h": 12,  # flood advert (0 = off)
    "push_gap_base_ms": 1000,       # quiet window after a push: base
    "push_gap_hop_ms": 2000,        # ... plus per hop
    "push_gap_flood_ms": 10000,     # ... or after a flood push
    "radio_freq_mhz": 910.525,      # radio settings pushed to the modem at startup (it doesn't save them):
    "radio_bw_khz": 62.5,           #   US/Canada preset 910.525 MHz / BW 62.5 / SF7 / CR4:5
    "radio_sf": 7,
    "radio_cr": 5,
    "radio_tx_power_dbm": None,     # None = leave the modem's default
    "route_halflife_h": 6,          # how fast route/member-location evidence fades (nodes move)
    "topology_halflife_h": 24,      # how fast the repeater map fades (repeaters rarely move)
    "routes_per_member": 6,         # proven routes kept per member
    "push_quiet_ms": 1500,          # pushes wait for this much quiet after the last packet heard
    "welcome_new_members": True,    # private "logged in" message for first-time members
    "welcome_message": "Logged in to {room}.",
    "welcome_advert_hint": "The room doesn't know your name yet: please send an advert.",   # added if their name is unknown ("" = never)
    "discovery_interval_min": 15,   # zero-hop repeater discovery (0 = off): finds every repeater that hears the room directly
    "trace_neighbours": True,       # trace one neighbour at a time, at the end of a member round, when the room is idle
    "trace_min_interval_s": 120,    # ... but never more often than this
    "extra_acks": 1,                # ACKs for posts: 1 = send a second ACK (on a 2nd confident route if there is one), 0 = single
    "dedupe_window_s": 300,         # identical text re-sent by the same member within this window = a retry (0 = off)
    "kick_message": "You have been removed from {room}.",    # sent once when kicked ("" = no message)
    "ban_message": "You have been banned from {room}.",      # sent once when banned ("" = no message)
    "web_port": 8081,               # dashboard (0 = off)
    "web_bind": "0.0.0.0",
    "web_password": "",             # dashboard admin password (resync/kick/ban/unban/dismiss); viewing is public. "" = admin off
    "kiss_txdelay": 1,              # KISS TXDELAY (x10 ms)
    "kiss_persistence": 128,        # KISS CSMA persistence 0-255
    "kiss_slottime": 5,             # KISS slot time (x10 ms)
    "identity": "modem",            # "modem", or a key file path (testing without modem crypto)
    "log_level": "INFO",
}


class Config:
    """Settings file. Settings may sit at the top level or inside named sections ("radio": {...}); keys starting
    with "_" are notes and ignored. CLI changes are written back in place, keeping the file's layout."""

    def __init__(self, path):
        self.path = path
        self.data = dict(DEFAULT_CONFIG)
        self.layout = {}                                    # the file as written (sections preserved)
        self.where = {}                                     # setting -> section name (None = top level)
        if os.path.exists(path):
            with open(path) as f:
                self.layout = json.load(f)
            for k, v in self.layout.items():
                if k.startswith("_"):
                    continue
                if isinstance(v, dict) and k not in DEFAULT_CONFIG:   # a section
                    for k2, v2 in v.items():
                        if not k2.startswith("_"):
                            self._take(k2, v2, k)
                else:
                    self._take(k, v, None)
        else:
            self.layout = dict(DEFAULT_CONFIG)
            self.save()
            log.warning("created default config %s - edit passwords and serial port", path)

    def _take(self, k, v, section):
        if k not in DEFAULT_CONFIG:
            log.warning("config: '%s'%s is not a setting this version uses (ignored)", k, " in section '%s'" % section if section else "")
        self.data[k] = v
        self.where[k] = section

    def __getattr__(self, k):
        try:
            return self.__dict__["data"][k]
        except KeyError:
            raise AttributeError(k)

    def set(self, k, v):
        self.data[k] = v
        sec = self.where.get(k)
        if sec is not None and isinstance(self.layout.get(sec), dict):
            self.layout[sec][k] = v                         # update it where it lives
        else:
            self.layout[k] = v
            self.where[k] = None
        self.save()

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.layout, f, indent=2)
        try:
            os.chmod(tmp, 0o600)                            # holds passwords
        except OSError:
            pass
        os.replace(tmp, self.path)


# ============================================================================
# Protocol constants
# ============================================================================

PUB_KEY_SIZE = 32
SIGNATURE_SIZE = 64
CIPHER_MAC_SIZE = 2
CIPHER_BLOCK_SIZE = 16
MAX_PACKET_PAYLOAD = 184
MAX_PATH_SIZE = 64
MAX_ADVERT_DATA_SIZE = 32
OUT_PATH_UNKNOWN = None

ROUTE_TRANSPORT_FLOOD, ROUTE_FLOOD, ROUTE_DIRECT, ROUTE_TRANSPORT_DIRECT = 0, 1, 2, 3

PT_REQ, PT_RESPONSE, PT_TXT_MSG, PT_ACK, PT_ADVERT, PT_GRP_TXT, PT_GRP_DATA, PT_ANON_REQ, \
    PT_PATH, PT_TRACE, PT_MULTIPART, PT_CONTROL = range(12)
PT_NAMES = ["req", "resp", "txt", "ack", "advert", "grp_txt", "grp_data", "anon_req",
            "path", "trace", "multipart", "control"]

ADV_TYPE_CHAT, ADV_TYPE_REPEATER, ADV_TYPE_ROOM, ADV_TYPE_SENSOR = 1, 2, 3, 4
ADV_LATLON_MASK, ADV_FEAT1_MASK, ADV_FEAT2_MASK, ADV_NAME_MASK = 0x10, 0x20, 0x40, 0x80

TXT_TYPE_PLAIN, TXT_TYPE_CLI_DATA, TXT_TYPE_SIGNED_PLAIN, TXT_TYPE_CLI_COMMAND = 0, 1, 2, 3

PERM_GUEST, PERM_READ_ONLY, PERM_READ_WRITE, PERM_ADMIN = 0, 1, 2, 3

REQ_GET_STATUS, REQ_KEEP_ALIVE, REQ_GET_TELEMETRY, REQ_GET_ACCESS_LIST, REQ_GET_NEIGHBOURS = 1, 2, 3, 5, 6
RESP_SERVER_LOGIN_OK = 0

SERVER_RESPONSE_DELAY = 0.3
TXT_ACK_DELAY = 0.2
PUSH_NOTIFY_DELAY = 2.0
POST_SYNC_DELAY_SECS = 6
MAX_POST_TEXT_LEN = 160 - 9
SYNC_SKIP_INTERVAL = 0.15

PUSH_ATTEMPTS = 4                 # current route x2, best other route, flood
ROUTES_PER_MEMBER = 3
ROUTE_DROP_FAILS = 2
ROUTE_HALFLIFE_H = 24
ROUTE_MAX_AGE_D = 7
FLOOD_ACK_MIN = 25.0
STUCK_RETRY_H = 6
STUCK_GIVEUP_H = 72
BACKOFF_SECS = [60, 300, 900, 1800, STUCK_RETRY_H * 3600]
MAX_NEIGHBOURS = 50
NAME_CACHE_MAX = 1000

SLOT_FLOOD = "flood"


def path_bytes(path_len):
    return (path_len & 63) * ((path_len >> 6) + 1)


def path_valid(path_len):
    return ((path_len >> 6) + 1) != 4 and path_bytes(path_len) <= MAX_PATH_SIZE


def path_hops(path_len):
    return 0xFF if path_len is None else (path_len & 63)


def hexs(b):
    return b.hex().upper()


def now_s():
    return int(time.time())


# ============================================================================
# Crypto (AES-128-ECB + truncated HMAC-SHA256, exactly as MeshCore Utils.cpp)
# ============================================================================

def sha256(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def aes_encrypt(secret, data):
    if len(data) % 16:
        data = data + bytes(16 - len(data) % 16)          # zero padding
    enc = Cipher(algorithms.AES(secret[:16]), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


def aes_decrypt(secret, data):
    dec = Cipher(algorithms.AES(secret[:16]), modes.ECB()).decryptor()
    return dec.update(data) + dec.finalize()


def encrypt_then_mac(secret, plaintext):
    ct = aes_encrypt(secret, plaintext)
    mac = hmac.new(secret[:PUB_KEY_SIZE], ct, hashlib.sha256).digest()[:CIPHER_MAC_SIZE]
    return mac + ct


def mac_then_decrypt(secret, data):
    if len(data) <= CIPHER_MAC_SIZE:
        return None
    ct = data[CIPHER_MAC_SIZE:]
    if len(ct) % CIPHER_BLOCK_SIZE:
        return None
    mac = hmac.new(secret[:PUB_KEY_SIZE], ct, hashlib.sha256).digest()[:CIPHER_MAC_SIZE]
    if not hmac.compare_digest(mac, data[:CIPHER_MAC_SIZE]):
        return None
    return aes_decrypt(secret, ct)


def ed25519_verify(pub, sig, msg):
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


_P = 2 ** 255 - 19


def ed25519_pub_to_x25519(pub):
    y = int.from_bytes(pub, "little") & ((1 << 255) - 1)
    u = (1 + y) * pow((1 - y) % _P, _P - 2, _P) % _P
    return u.to_bytes(32, "little")


class LocalIdentity:
    """Software identity (key file), for testing without the modem's crypto commands."""

    def __init__(self, path):
        if os.path.exists(path):
            with open(path, "rb") as f:
                seed = f.read(32)
        else:
            seed = os.urandom(32)
            with open(path, "wb") as f:
                f.write(seed)
            os.chmod(path, 0o600)
        self._sk = Ed25519PrivateKey.from_private_bytes(seed)
        from cryptography.hazmat.primitives import serialization
        self.pub_key = self._sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        h = bytearray(hashlib.sha512(seed).digest()[:32])
        h[0] &= 248; h[31] &= 127; h[31] |= 64
        self._x = X25519PrivateKey.from_private_bytes(bytes(h))

    def sign(self, msg):
        return self._sk.sign(msg)

    def shared_secret(self, other_pub):
        return self._x.exchange(X25519PublicKey.from_public_bytes(ed25519_pub_to_x25519(other_pub)))


class ModemIdentity:
    """The modem's identity: signing and key exchange happen on the radio."""

    def __init__(self, modem):
        self.modem = modem
        r = modem.command(0x01)
        if r is None or len(r) < 32:
            raise RuntimeError("modem did not return its identity")
        self.pub_key = bytes(r[:32])

    def sign(self, msg):
        r = self.modem.command(0x04, msg, timeout=5)
        if r is None or len(r) < 64:
            raise RuntimeError("modem SignData failed")
        return bytes(r[:64])

    def shared_secret(self, other_pub):
        r = self.modem.command(0x07, other_pub, timeout=5)
        if r is None or len(r) < 32:
            raise RuntimeError("modem KeyExchange failed")
        return bytes(r[:32])


# ============================================================================
# Packet
# ============================================================================

class Packet:
    __slots__ = ("header", "transport_codes", "path_len", "path", "payload", "snr", "rssi", "raw_len")

    def __init__(self, ptype=0, payload=b""):
        self.header = (ptype & 0x0F) << 2
        self.transport_codes = (0, 0)
        self.path_len = 0
        self.path = b""
        self.payload = payload
        self.snr = 0.0
        self.rssi = 0
        self.raw_len = 0

    route_type = property(lambda s: s.header & 0x03)
    ptype = property(lambda s: (s.header >> 2) & 0x0F)
    is_flood = property(lambda s: s.route_type in (ROUTE_FLOOD, ROUTE_TRANSPORT_FLOOD))
    is_direct = property(lambda s: s.route_type in (ROUTE_DIRECT, ROUTE_TRANSPORT_DIRECT))
    has_transport = property(lambda s: s.route_type in (ROUTE_TRANSPORT_FLOOD, ROUTE_TRANSPORT_DIRECT))
    hash_size = property(lambda s: (s.path_len >> 6) + 1)
    hop_count = property(lambda s: s.path_len & 63)

    @classmethod
    def parse(cls, raw):
        p = cls()
        i = 0
        p.header = raw[i]; i += 1
        if p.has_transport:
            if len(raw) < i + 4:
                return None
            p.transport_codes = struct.unpack_from("<HH", raw, i); i += 4
        if len(raw) <= i:
            return None
        p.path_len = raw[i]; i += 1
        if not path_valid(p.path_len):
            return None
        bl = path_bytes(p.path_len)
        p.path = bytes(raw[i:i + bl]); i += bl
        if i >= len(raw):
            return None
        p.payload = bytes(raw[i:])
        if len(p.payload) > MAX_PACKET_PAYLOAD:
            return None
        p.raw_len = len(raw)
        return p

    def encode(self):
        out = bytearray([self.header])
        if self.has_transport:
            out += struct.pack("<HH", *self.transport_codes)
        out.append(self.path_len)
        out += self.path[:path_bytes(self.path_len)]
        out += self.payload
        return bytes(out)

    def packet_hash(self):
        h = hashlib.sha256()
        h.update(bytes([self.ptype]))
        if self.ptype == PT_TRACE:
            h.update(struct.pack("<H", self.path_len))
        h.update(self.payload)
        return h.digest()[:8]

    def raw_length(self):
        return 2 + path_bytes(self.path_len) + len(self.payload) + (4 if self.has_transport else 0)


# ============================================================================
# KISS modem driver
# ============================================================================

FEND, FESC, TFEND, TFESC = 0xC0, 0xDB, 0xDC, 0xDD
HW_TXDONE, HW_RXMETA, HW_OK, HW_ERROR = 0xF8, 0xF9, 0xF0, 0xF1


class KissModem:
    """Serial KISS link. A reader thread decodes frames: received packets (with their
    RxMeta SNR/RSSI) and TxDone events go to the main event queue; command responses
    wake the caller of command()."""

    def __init__(self, port, baud, events):
        # Standard open (DTR raised): nRF52 boards like the RAK4631 only send over USB once DTR is up.
        # An ESP32 board that resets on open is covered by the startup ping retries in main().
        self.ser = serial.Serial(port, baud, timeout=0.2)
        self.events = events
        self._wlock = threading.Lock()
        self._cmd_lock = threading.Lock()
        self._resp_evt = threading.Event()
        self._resp_sub = None
        self._resp_data = None
        self._pending_rx = None
        self._async_pending = set()
        self._running = True
        threading.Thread(target=self._reader, name="kiss-rx", daemon=True).start()

    def close(self):
        self._running = False
        try:
            self.ser.close()
        except Exception:
            pass

    @staticmethod
    def _escape(data):
        out = bytearray()
        for b in data:
            if b == FEND:
                out += bytes([FESC, TFEND])
            elif b == FESC:
                out += bytes([FESC, TFESC])
            else:
                out.append(b)
        return bytes(out)

    def _write_frame(self, type_byte, data=b""):
        frame = bytes([FEND, type_byte]) + self._escape(data) + bytes([FEND])
        with self._wlock:
            self.ser.write(frame)

    def send_packet(self, raw):
        self._write_frame(0x00, raw)

    def set_param(self, cmd, value):
        self._write_frame(cmd, bytes([value & 0xFF]))

    def request(self, sub, data=b""):
        """Fire-and-forget SetHardware request: the reply arrives as an ("hw", sub, body) event."""
        with self._wlock:
            self._async_pending.add(sub | 0x80)
        self._write_frame(0x06, bytes([sub]) + data)

    def command(self, sub, data=b"", timeout=2.0):
        """SetHardware request/response. Returns the response data, or None on error/timeout."""
        with self._cmd_lock:
            self._resp_evt.clear()
            self._resp_sub = sub
            self._resp_data = None
            self._write_frame(0x06, bytes([sub]) + data)
            if not self._resp_evt.wait(timeout):
                self._resp_sub = None
                return None
            self._resp_sub = None
            return self._resp_data

    def _flush_rx(self, snr=0.0, rssi=0):
        if self._pending_rx is not None:
            self.events.put(("rx", self._pending_rx, snr, rssi))
            self._pending_rx = None

    def _on_frame(self, frame):
        if not frame:
            return
        t = frame[0] & 0x0F
        data = frame[1:]
        if t == 0x00:
            self._flush_rx()                      # previous packet had no RxMeta
            self._pending_rx = bytes(data)
            return
        if t != 0x06 or not data:
            return
        sub, body = data[0], data[1:]
        if sub == HW_RXMETA:
            snr = struct.unpack("b", body[0:1])[0] / 4.0 if len(body) >= 1 else 0.0
            rssi = struct.unpack("b", body[1:2])[0] if len(body) >= 2 else 0
            self._flush_rx(snr, rssi)
            return
        self._flush_rx()
        if sub == HW_TXDONE:
            self.events.put(("txdone", bool(body and body[0])))
            return
        if sub in self._async_pending and (self._resp_sub is None or sub != (self._resp_sub | 0x80)):
            self._async_pending.discard(sub)                # reply to a fire-and-forget request
            self.events.put(("hw", sub, bytes(body)))
            return
        want = self._resp_sub
        if want is None and sub == HW_ERROR and self._async_pending:
            self._async_pending.clear()
            self.events.put(("hw", sub, bytes(body)))
            return
        if want is not None:
            if sub == (want | 0x80) or sub == HW_OK:
                self._resp_data = bytes(body)
                self._resp_evt.set()
            elif sub == HW_ERROR:
                if body and body[0] == 0x07:      # TxBusy can also answer a data frame
                    self.events.put(("txbusy",))
                self._resp_data = None
                self._resp_evt.set()
        elif sub == HW_ERROR and body and body[0] == 0x07:
            self.events.put(("txbusy",))

    def _reader(self):
        buf = bytearray()
        in_frame = esc = False
        while self._running:
            try:
                # wait for the first byte (up to the 0.2 s timeout), then take whatever else has arrived:
                # read(256) would sit on a short frame until 256 bytes or the timeout (up to 200 ms late)
                chunk = self.ser.read(1)
                if chunk:
                    waiting = self.ser.in_waiting
                    if waiting:
                        chunk += self.ser.read(waiting)
            except Exception as e:
                log.error("serial read failed: %s", e)
                self.events.put(("serial_error",))
                return
            if not chunk:
                if self._pending_rx is not None:  # no RxMeta coming
                    self._flush_rx()
                continue
            for b in chunk:
                if b == FEND:
                    if in_frame and buf:
                        self._on_frame(bytes(buf))
                    buf.clear()
                    in_frame = True
                    esc = False
                elif not in_frame:
                    continue
                elif esc:
                    buf.append(FEND if b == TFEND else FESC if b == TFESC else b)
                    esc = False
                elif b == FESC:
                    esc = True
                else:
                    buf.append(b)
                    if len(buf) > 600:
                        buf.clear()
                        in_frame = False


# ============================================================================
# Persistent state (SQLite)
# ============================================================================

class Store:
    """SQLite persistence. Reads happen once at startup; every write after that goes through a
    writer thread, so the room's main loop never waits on the SD card."""

    # every table with its full column list. Existing databases get any missing column added automatically,
    # so a new setting or field never needs a hand-written migration.
    TABLES = {
        "members": ("pubkey BLOB PRIMARY KEY", "perms INT", "last_timestamp INT", "last_activity INT", "sync_since INT",
                    "out_path BLOB", "out_path_len INT", "given_up INT DEFAULT 0", "secret BLOB", "attempts_avg REAL",
                    "deliveries INT", "in_path BLOB", "in_path_len INT", "in_ts INT"),
        "posts": ("ts INT PRIMARY KEY", "author BLOB", "text TEXT", "to_key BLOB"),
        "routes": ("pubkey BLOB", "slot INT", "len INT", "path BLOB", "last_ok INT", "added_at INT", "s REAL", "n REAL",
                   "t INT", "lat REAL", "lat_n INT", "PRIMARY KEY (pubkey, slot)"),
        "names": ("key8 BLOB PRIMARY KEY", "ts INT", "name TEXT"),
        "rpt_routes": ("target BLOB", "plen INT", "path BLOB", "w REAL", "ok REAL", "fail REAL", "t INT",
                       "PRIMARY KEY (target, plen, path)"),
        "member_rpts": ("pubkey BLOB", "rpt BLOB", "w REAL", "t INT", "PRIMARY KEY (pubkey, rpt)"),
        "member_inroutes": ("key8 BLOB", "plen INT", "path BLOB", "w REAL", "t INT", "PRIMARY KEY (key8, plen, path)"),
        "edges": ("a BLOB", "b BLOB", "w REAL", "t INT", "snr REAL", "PRIMARY KEY (a, b)"),
        "repeaters": ("pubkey BLOB PRIMARY KEY", "name TEXT", "lat REAL", "lon REAL", "adv_ts INT", "last_advert INT"),
        "heard": ("hash BLOB PRIMARY KEY", "last INT", "w REAL", "t INT", "last_direct INT", "snr REAL", "disc INT", "out_snr REAL"),
        "bans": ("pubkey BLOB PRIMARY KEY", "name TEXT", "ts INT"),
        "probes": ("hash BLOB PRIMARY KEY", "data TEXT"),
    }

    def __init__(self, path):
        self.path = path
        db = self.connect()
        for table, cols in self.TABLES.items():
            db.execute("CREATE TABLE IF NOT EXISTS %s (%s)" % (table, ", ".join(cols)))
            have = {r[1] for r in db.execute("PRAGMA table_info(%s)" % table)}
            for c in cols:
                name = c.split()[0]
                if name != "PRIMARY" and name not in have:
                    db.execute("ALTER TABLE %s ADD COLUMN %s" % (table, c.replace(" PRIMARY KEY", "")))
        db.commit()
        db.close()
        try:
            os.chmod(path, 0o600)                           # holds shared secrets
        except OSError:
            pass
        self.events = None
        self.q = queue.Queue()
        self.thread = threading.Thread(target=self._writer, name="db-writer", daemon=True)
        self.thread.start()

    def connect(self):
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        return db

    def read(self, sql, args=()):
        db = self.connect()
        try:
            return db.execute(sql, args).fetchall()
        finally:
            db.close()

    # --- called from the main loop: just queue the work ---
    def add_post(self, ts, author, text, to, prune_before):
        self.q.put(("post", (ts, author, text, to, prune_before)))

    def apply(self, changes):
        self.q.put(("changes", changes))

    def execmany(self, ops):
        """ops: list of (sql, rows). Runs in one transaction on the writer thread."""
        self.q.put(("exec", ops))

    def close(self):
        self.q.put(("stop", None))
        self.thread.join(timeout=15)

    # --- writer thread ---
    def _writer(self):
        db = self.connect()
        while True:
            kind, arg = self.q.get()
            if kind == "stop":
                break
            try:
                with db:
                    if kind == "exec":
                        for sql, rows in arg:
                            if rows is None:
                                db.execute(sql)
                            else:
                                db.executemany(sql, rows)
                    elif kind == "post":
                        ts, author, text, to, prune_before = arg
                        db.execute("INSERT OR REPLACE INTO posts (ts, author, text, to_key) VALUES (?,?,?,?)",
                                   (ts, author, text, to))
                        if prune_before:
                            db.execute("DELETE FROM posts WHERE ts < ? AND to_key IS NULL", (prune_before,))
                    elif kind == "changes":
                        c = arg
                        db.executemany("INSERT OR REPLACE INTO members (pubkey, perms, last_timestamp, last_activity, sync_since, "
                                       "out_path, out_path_len, given_up, secret, attempts_avg, deliveries, in_path, in_path_len, in_ts) "
                                       "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", c["members"])
                        db.executemany("DELETE FROM routes WHERE pubkey=?", [(k,) for k in c["members_gone"]])
                        db.executemany("DELETE FROM members WHERE pubkey=?", [(k,) for k in c["members_gone"]])
                        for pub, rows in c["routes"].items():
                            db.execute("DELETE FROM routes WHERE pubkey=?", (pub,))
                            db.executemany("INSERT INTO routes (pubkey, slot, len, path, last_ok, added_at, s, n, t, lat, lat_n) "
                                           "VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
                        db.executemany("INSERT OR REPLACE INTO names VALUES (?,?,?)", c["names"])
                        db.executemany("DELETE FROM names WHERE key8=?", [(k,) for k in c["names_gone"]])
            except Exception as e:
                log.exception("database write failed")
                if self.events:
                    self.events.put(("dberror", str(e)))
        db.close()


def resolve_route(text, repeaters):
    """'Seaside (E3C5), 4322, Williams Hill' -> [bytes, ...] (room side first) or raises ValueError.
    repeaters: iterable of (name, id_hex). Tokens: a hex id (1-3 bytes), 'Name (HEX)', or an exact name."""
    import re
    reps = list(repeaters)
    hops = []
    for raw in [t.strip() for t in text.split(",")]:
        if not raw:
            continue
        mt = re.search(r"\(([0-9A-Fa-f]{2,6})\)\s*$", raw)
        if mt:
            hx = mt.group(1)
        elif re.fullmatch(r"[0-9A-Fa-f]{2}|[0-9A-Fa-f]{4}|[0-9A-Fa-f]{6}", raw):
            hx = raw
        else:
            hits = {h for n, h in reps if n and n.casefold() == raw.casefold()}
            if not hits:
                raise ValueError("unknown repeater: %s" % raw)
            if len(hits) > 1:
                raise ValueError("more than one repeater is called %s: use its id" % raw)
            hx = hits.pop()
        if len(hx) % 2:
            raise ValueError("bad id: %s" % raw)
        hops.append(bytes.fromhex(hx))
    if not hops:
        raise ValueError("enter at least one repeater")
    size = len(hops[0])
    if any(len(h) != size for h in hops):
        raise ValueError("all ids in a route must be the same size (1, 2 or 3 bytes)")
    if size * len(hops) > MAX_PATH_SIZE:
        raise ValueError("route too long")
    return hops


def fade(v, t_from, t_to, half_s):
    """Exponential fade: value halves every half_s seconds."""
    if t_to <= t_from or half_s <= 0:
        return v
    return v * 0.5 ** ((t_to - t_from) / half_s)


class ProvenRoute:
    """A route that has delivered to this member, with a recency-weighted success rate:
    s / n are faded success / attempt counts; rate() = (s + 1) / (n + 2) pulls thin evidence toward 50%."""
    __slots__ = ("len", "path", "s", "n", "t", "lat", "lat_n", "last_ok", "added_at")

    def __init__(self, plen, path, t):
        self.len, self.path = plen, bytes(path[:path_bytes(plen)])
        self.s = self.n = 0.0
        self.t = t
        self.lat, self.lat_n = 0.0, 0
        self.last_ok = 0
        self.added_at = t

    def same(self, plen, path):
        return plen == self.len and bytes(path[:path_bytes(plen)]) == self.path

    def evidence(self, now, half):
        f = 0.5 ** (max(0, now - self.t) / half) if half > 0 else 1.0
        return self.s * f, self.n * f

    def rate(self, now, half):
        s, n = self.evidence(now, half)
        return (s + 1.0) / (n + 2.0)

    def record(self, ok, now, half):
        s, n = self.evidence(now, half)
        self.s, self.n, self.t = s + (1.0 if ok else 0.0), n + 1.0, now
        if ok:
            self.last_ok = now

    def add_latency(self, ms):
        self.lat = ms if self.lat_n == 0 else self.lat * 0.7 + ms * 0.3
        self.lat_n = min(self.lat_n + 1, 1000)


class RptRoute:
    """A route from the room to a repeater, seen in flood paths (reversed): w = faded observation
    count, ok / fail = faded delivery outcomes when the room used it."""
    __slots__ = ("plen", "path", "w", "ok", "fail", "t")

    def __init__(self, plen, path, t):
        self.plen, self.path = plen, path
        self.w = self.ok = self.fail = 0.0
        self.t = t

    def faded(self, now, half):
        if now > self.t:
            f = 0.5 ** ((now - self.t) / half)
            self.w *= f; self.ok *= f; self.fail *= f
            self.t = now

    def confidence(self, now, half):
        self.faded(now, half)
        seen = self.w / (self.w + 2.0)                       # seen often = likely good
        delivered = (self.ok + 1.0) / (self.ok + self.fail + 2.0)
        return seen * delivered * 2.0 if self.ok + self.fail < 0.5 else delivered * (0.5 + seen / 2.0)


class Member:
    def __init__(self, pub):
        self.pub = pub
        self.perms = PERM_GUEST
        self.last_timestamp = 0
        self.last_activity = 0
        self.sync_since = 0
        self.out_path = b""
        self.out_path_len = OUT_PATH_UNKNOWN
        self.secret = None
        # push state (runtime)
        self.pending_ack = None
        self.ack_timeout = 0.0
        self.push_failures = 0
        self.push_post_ts = 0
        self.push_sent = 0.0
        self.push_hops = 0xFF
        self.prev_acks = [None, None]
        self.routes = []                  # ProvenRoute list
        self.plan = None                  # attempt plan for the post being delivered
        self.plan_retry = False           # plan is a backoff retry (best route, then flood)
        self.inflight = None              # plan entry of the attempt in flight
        self.prev_entries = [None, None]  # plan entries of earlier attempts, parallel to prev_acks
        self.backoff = 0
        self.retry_at = 0.0
        self.stuck_since = 0.0
        self.given_up = False
        self.new_member = False
        self.attempts_avg = None          # recency-weighted attempts per delivered post (1.0 = always first try)
        self.deliveries = 0
        self.attempts_cur = 0             # attempts on the post being delivered
        self.in_path, self.in_path_len, self.in_ts = b"", None, 0   # route their app uses to reach the room (last path return)

    role = property(lambda s: s.perms & 3)
    is_admin = property(lambda s: (s.perms & 3) == PERM_ADMIN)
    key6 = property(lambda s: hexs(s.pub[:6]))


# ============================================================================
# Room server
# ============================================================================

class RoomServer:
    def __init__(self, cfg, modem, identity, store):
        self.cfg, self.modem, self.id, self.store = cfg, modem, identity, store
        self.self_hash = identity.pub_key[0]
        self.members = {}                 # pubkey -> Member
        self.bans = {}                    # pubkey -> dict(name, ts): the room ignores them completely
        self.notices = []                 # kick/ban messages being retried until ACKed
        self.last_pushed = None           # member of the most recent push (its ACK ends the gap early)
        self.last_push_at, self.last_push_flood = 0.0, False
        self.inpaths = {}                 # member key8 -> {(plen, path): [w, t]}  paths their floods took to reach us
        self.flood_owner = {}             # flood packet hash -> (member pubkey, expiry): attribute duplicate copies
        self.disc_tag, self.disc_until, self.disc_replies = None, 0.0, 0
        self.disc_responders = set()
        self.probes = {}                  # neighbour hash -> discovery stats (link score)
        self.disc_close_at = 0.0          # when the current discovery round's reply window closes
        self.trace_pending = None         # (tag, hash, sent) of the one neighbour trace in flight
        self.last_trace = float("-inf")   # never traced (the monotonic clock can be small right after boot)
        self.next_discovery = time.monotonic() + 60        # first one a minute after start
        self.disc_due_since = 0.0
        self.posts = []                   # [(ts, author32, text)], oldest first
        self.max_issued = 0
        self.names = {}                   # key8 -> (ts, name)
        self.neighbours = {}              # pubkey -> dict(advert_ts, heard, snr4, name)
        self.seen = {}                    # packet hash -> None (insertion ordered)
        self.txq = []                     # heap (due, prio, seq, raw, ptype, is_flood)
        self.txseq = 0
        self.tx_busy_until = 0.0
        self.next_push = 0.0
        self.round = []
        self.dirty = False
        self.next_flush = 0.0
        self.boot = time.monotonic()
        self.radio = None                 # (freq, bw, sf, cr)
        self.noise_floor = 0
        self.nf_min = self.nf_max = 0
        self.last_rssi = 0
        self.last_snr = 0.0
        self.stats = dict(recv=0, sent=0, recv_flood=0, recv_direct=0, sent_flood=0, sent_direct=0,
                          flood_dups=0, direct_dups=0, errors=0, airtime_ms=0, posted=0, pushes=0,
                          acks=0, late_acks=0, timeouts=0, flood_fallbacks=0, deduped=0, traces=0)
        self.lat_sum = [0] * 6
        self.lat_cnt = [0] * 6
        self.next_zero_advert = time.monotonic() + 5
        self.next_flood_advert = time.monotonic() + 15
        self.next_aging = 0.0
        self.next_nf = 0.0
        self.next_batt = 0.0
        self.next_radio_check = time.monotonic() + 300
        self.batt_mv = 0
        self.mcu_temp_c = None
        self.temp_supported = True
        # repeater map (database 1), member locations (database 2), links, repeater registry
        self.rroutes = {}                 # target hash -> {(plen, path): RptRoute}
        self.mrpts = {}                   # companion directory, locations: key8 -> {repeater hash (b"" = direct): [w, t]}
        self.edges = {}                   # (a_hash, b_hash) -> [w, t, snr]   b"" = the room
        self.repeaters = {}               # repeater pubkey -> dict(name, lat, lon, adv_ts, last_advert)
        self.heard = {}                   # repeater hash -> dict(last, w, t, last_direct, snr)
        self.next_topo_flush = time.monotonic() + 300
        self.last_rx_mono = 0.0
        self.rx_airtime_ms = 0
        # per-minute stats, dashboard
        self.next_metric = time.monotonic() + 60
        self.metric_prev = None
        self.m_nf_min = self.m_nf_max = 0
        self.minutes = collections.deque(maxlen=60)   # last hour of per-minute samples, for the header (memory only)
        self.sys_samples = collections.deque(maxlen=120)   # (cpu %, mem %) every 5 s = last 10 minutes
        self.cpu_prev = None
        self.mem_total_mb = None
        self.next_sys = 0.0
        self.last_hw_reply = time.monotonic()
        self.push_fail_since = 0.0
        self.web_state = {}
        self.web_port_active = bool(cfg.web_port)
        self.web_last_request = 0.0
        self.web_dirty = False
        self.events_q = None              # main event queue (set by main): housekeeping yields to waiting packets
        self.next_web = 0.0
        self.load()

    # ------------------------------------------------------------------ persistence

    def load(self):
        st = self.store
        for row in st.read("SELECT pubkey, perms, last_timestamp, last_activity, sync_since, out_path, out_path_len, given_up, secret, "
                           "attempts_avg, deliveries, in_path, in_path_len, in_ts FROM members"):
            m = Member(bytes(row[0]))
            m.perms, m.last_timestamp, m.last_activity, m.sync_since = row[1], row[2], row[3], row[4]
            m.out_path = bytes(row[5] or b"")
            m.out_path_len = row[6]
            m.given_up = bool(row[7])
            m.secret = bytes(row[8]) if row[8] else None   # saved: no modem key exchange needed after restart
            m.attempts_avg = row[9]
            m.deliveries = row[10] or 0
            m.in_path, m.in_path_len, m.in_ts = bytes(row[11] or b""), row[12], row[13] or 0
            self.members[m.pub] = m
        self.bans = {bytes(pub): dict(name=name, ts=ts) for pub, name, ts in st.read("SELECT pubkey, name, ts FROM bans")}
        for h, data in st.read("SELECT hash, data FROM probes"):
            try:
                self.probes[bytes(h)] = json.loads(data)
                self.probe_stats(bytes(h))
            except ValueError:
                pass
        for row in st.read("SELECT pubkey, slot, len, path, last_ok, added_at, s, n, t, lat, lat_n FROM routes ORDER BY pubkey, slot"):
            m = self.members.get(bytes(row[0]))
            if m and len(m.routes) < self.cfg.routes_per_member:
                r = ProvenRoute(row[2], bytes(row[3]), row[5] or now_s())
                r.last_ok = row[4] or 0
                r.s, r.n, r.t = float(row[6] or 0), float(row[7] or 0), row[8] or row[4] or now_s()
                r.lat, r.lat_n = float(row[9] or 0), int(row[10] or 0)
                m.routes.append(r)
        rows = st.read("SELECT ts, author, text, to_key FROM posts WHERE to_key IS NULL ORDER BY ts DESC LIMIT ?", (self.cfg.max_posts,))
        rows += st.read("SELECT ts, author, text, to_key FROM posts WHERE to_key IS NOT NULL")
        for ts, author, text, to in sorted(rows, key=lambda r: r[0]):
            self.posts.append((ts, bytes(author), text, bytes(to) if to else None))
        for target, plen, path, w, ok, fail, t in st.read("SELECT target, plen, path, w, ok, fail, t FROM rpt_routes"):
            rr = RptRoute(plen, bytes(path), t)
            rr.w, rr.ok, rr.fail = w, ok, fail
            self.rroutes.setdefault(bytes(target), {})[(plen, bytes(path))] = rr
        for k8, rpt, w, t in st.read("SELECT pubkey, rpt, w, t FROM member_rpts"):
            self.mrpts.setdefault(bytes(k8), {})[bytes(rpt)] = [w, t]
        for k8, plen, path, w, t in st.read("SELECT key8, plen, path, w, t FROM member_inroutes"):
            self.inpaths.setdefault(bytes(k8), {})[(plen, bytes(path))] = [w, t]
        for a, b, w, t, snr in st.read("SELECT a, b, w, t, snr FROM edges"):
            self.edges[(bytes(a), bytes(b))] = [w, t, snr]
        for pub, name, lat, lon, adv_ts, last in st.read("SELECT pubkey, name, lat, lon, adv_ts, last_advert FROM repeaters"):
            self.repeaters[bytes(pub)] = dict(name=name, lat=lat, lon=lon, adv_ts=adv_ts, last_advert=last)
        for h, last, w, t, last_direct, snr, disc, out_snr in st.read("SELECT hash, last, w, t, last_direct, snr, disc, out_snr FROM heard"):
            self.heard[bytes(h)] = dict(last=last, w=w, t=t, last_direct=last_direct, snr=snr, disc=disc or 0, out_snr=out_snr)
        for m in self.members.values():
            self.update_current(m, mark=False)
        self.max_issued = max((p[0] for p in self.posts), default=0)
        for key8, ts, name in st.read("SELECT key8, ts, name FROM names"):
            self.names[bytes(key8)] = (ts, name)
        # what's on disk now, so flushes only write rows that changed
        self.disk_members = {m.pub: self.member_row(m) for m in self.members.values()}
        self.disk_routes = {m.pub: self.route_rows(m) for m in self.members.values()}
        self.disk_names = dict(self.names)
        # every saved member is active after a restart (pushes resume without waiting for contact)
        t = now_s()
        for m in self.members.values():
            if m.last_activity == 0 and not m.given_up:
                m.last_activity = t
        log.info("loaded %d members, %d posts, %d names, %d repeaters mapped", len(self.members), len(self.posts),
                 len(self.names), len(self.rroutes))

    @staticmethod
    def member_row(m):
        return (m.pub, m.perms, m.last_timestamp, m.last_activity, m.sync_since, m.out_path, m.out_path_len,
                int(m.given_up), m.secret, m.attempts_avg, m.deliveries, m.in_path, m.in_path_len, m.in_ts)

    @staticmethod
    def route_rows(m):
        return [(m.pub, k, r.len, r.path, r.last_ok, r.added_at, r.s, r.n, r.t, r.lat, r.lat_n)
                for k, r in enumerate(m.routes)]

    def flush(self):
        """Queue only what changed since the last flush for the writer thread (guests aren't saved)."""
        keep = {m.pub: m for m in self.members.values() if m.perms != PERM_GUEST}
        mrows, routes = [], {}
        for pub, m in keep.items():
            row = self.member_row(m)
            if self.disk_members.get(pub) != row:
                mrows.append(row)
                self.disk_members[pub] = row
            rrows = self.route_rows(m)
            if self.disk_routes.get(pub) != rrows:
                routes[pub] = rrows
                self.disk_routes[pub] = rrows
        gone = [pub for pub in self.disk_members if pub not in keep]
        for pub in gone:
            del self.disk_members[pub]
            if self.disk_routes.pop(pub, None):
                routes[pub] = []
        nrows = [(k, v[0], v[1]) for k, v in self.names.items() if self.disk_names.get(k) != v]
        ngone = [k for k in self.disk_names if k not in self.names]
        self.disk_names = dict(self.names)
        if mrows or gone or routes or nrows or ngone:
            self.store.apply(dict(members=mrows, members_gone=gone, routes=routes, names=nrows, names_gone=ngone))
        self.dirty = False

    def mark_dirty(self):
        self.dirty = True

    # ------------------------------------------------------------------ clock / ids

    def unique_time(self):
        t = now_s()
        if t <= self.max_issued:
            t = self.max_issued + 1
        return t

    def secret_for(self, m):
        if m.secret is None:
            m.secret = self.id.shared_secret(m.pub)
        return m.secret

    # ------------------------------------------------------------------ airtime

    def airtime_ms(self, length):
        if not self.radio:
            return 400
        _, bw, sf, cr = self.radio
        ts = (1 << sf) / bw
        de = 1 if ts > 0.016 else 0
        n = 8 + max(math.ceil((8 * length - 4 * sf + 28 + 16) / (4 * (sf - 2 * de))) * cr, 0)
        return int((16 + 4.25 + n) * ts * 1000)

    # ------------------------------------------------------------------ TX queue

    def queue_tx(self, pkt, prio, delay=0.0, deferrable=False):
        raw = pkt.encode()
        self.seen_mark(pkt)
        self.txseq += 1
        heapq.heappush(self.txq, (time.monotonic() + delay, prio, self.txseq, raw, pkt.ptype, pkt.is_flood, deferrable))

    def service_tx(self):
        now = time.monotonic()
        if now < self.tx_busy_until or not self.txq:
            return
        quiet = now - self.last_rx_mono >= self.cfg.push_quiet_ms / 1000.0
        # pushes aren't urgent: they wait for a quiet gap (floods arrive as bursts of rebroadcasts);
        # ACKs and replies go straight out. The modem's own CSMA still guards the instant of transmit.
        due = [e for e in self.txq if e[0] <= now and (quiet or not e[6])]
        if not due:
            return
        best = min(due, key=lambda e: (e[1], e[2]))       # highest priority, then FIFO
        self.txq.remove(best)
        heapq.heapify(self.txq)
        _, _, _, raw, ptype, is_flood, _ = best
        self.modem.send_packet(raw)
        at = self.airtime_ms(len(raw))
        self.tx_busy_until = now + at / 1000.0 + 3.0       # cleared early by TxDone
        self.stats["sent"] += 1
        self.stats["sent_flood" if is_flood else "sent_direct"] += 1
        self.stats["airtime_ms"] += at

    def wanted_radio(self):
        c = self.cfg
        return (int(round(c.radio_freq_mhz * 1e6)), int(round(c.radio_bw_khz * 1e3)), int(c.radio_sf), int(c.radio_cr))

    def apply_radio(self):
        """Push the configured radio settings to the modem (it reverts to compiled defaults on every reboot)."""
        f, bw, sf, cr = self.wanted_radio()
        ok = self.modem.command(0x09, struct.pack("<IIBB", f, bw, sf, cr), timeout=3) is not None
        if self.cfg.radio_tx_power_dbm is not None:
            self.modem.command(0x0A, bytes([int(self.cfg.radio_tx_power_dbm) & 0xFF]), timeout=3)
        r = self.modem.command(0x0B)
        if r and len(r) >= 10:
            self.radio = struct.unpack("<IIBB", r[:10])
        if not ok or self.radio != (f, bw, sf, cr):
            log.error("modem did not accept radio settings %s (reports %s)", (f, bw, sf, cr), self.radio)
        return ok

    def on_hw(self, sub, body):
        """Replies to fire-and-forget modem requests."""
        self.last_hw_reply = time.monotonic()
        if sub == 0x90 and len(body) >= 2:
            nf = struct.unpack("<h", body[:2])[0]
            self.noise_floor = nf
            self.nf_min = nf if not self.nf_min else min(self.nf_min, nf)
            self.nf_max = nf if not self.nf_max else max(self.nf_max, nf)
            self.m_nf_min = nf if not self.m_nf_min else min(self.m_nf_min, nf)
            self.m_nf_max = nf if not self.m_nf_max else max(self.m_nf_max, nf)
        elif sub == 0x93 and len(body) >= 2:
            self.batt_mv = struct.unpack("<H", body[:2])[0]
        elif sub == 0x94 and len(body) >= 2:
            self.mcu_temp_c = struct.unpack("<h", body[:2])[0] / 10.0
        elif sub == 0x8B and len(body) >= 10:
            if struct.unpack("<IIBB", body[:10]) != self.wanted_radio():
                log.warning("modem radio settings reverted (modem rebooted?) - re-applying")
                self.raise_alert("radio", "reverted", "Modem radio settings had reverted (modem reboot?) and were re-applied")
                self.apply_radio()
                self.send_advert(False)
        elif sub == HW_ERROR and body and body[0] == 0x03:  # NoCallback: board has no temperature sensor
            self.temp_supported = False

    def on_txdone(self, ok):
        self.tx_busy_until = time.monotonic() + 0.05
        if not ok:
            self.stats["errors"] += 1

    def send_flood(self, pkt, delay=0.0, hash_size=None, deferrable=False):
        if hash_size is None:
            hash_size = self.cfg.path_hash_mode + 1
        pkt.header = (pkt.header & ~0x03) | ROUTE_FLOOD
        pkt.path_len = ((hash_size - 1) << 6)
        pkt.path = b""
        prio = 2 if pkt.ptype == PT_PATH else 3 if pkt.ptype == PT_ADVERT else 1
        self.queue_tx(pkt, prio, delay, deferrable)

    def send_direct(self, pkt, path, path_len, delay=0.0, deferrable=False):
        pkt.header = (pkt.header & ~0x03) | ROUTE_DIRECT
        pkt.path_len = path_len
        pkt.path = path[:path_bytes(path_len)]
        self.queue_tx(pkt, 1 if pkt.ptype == PT_PATH else 0, delay, deferrable)

    def send_zero_hop(self, pkt, delay=0.0):
        pkt.header = (pkt.header & ~0x03) | ROUTE_DIRECT
        pkt.path_len, pkt.path = 0, b""
        self.queue_tx(pkt, 0, delay)

    def send_to(self, m, pkt, delay, req_pkt=None):
        """Direct if we have a route, else flood (using the request's hash size when replying)."""
        if m.out_path_len is not None:
            self.send_direct(pkt, m.out_path, m.out_path_len, delay)
        else:
            self.send_flood(pkt, delay, req_pkt.hash_size if req_pkt else None)

    # ------------------------------------------------------------------ packet builders

    def make_datagram(self, ptype, dest_pub, secret, data):
        return Packet(ptype, bytes([dest_pub[0], self.self_hash]) + encrypt_then_mac(secret, data))

    def make_path_return(self, dest_hash, secret, path, path_len, extra_type, extra):
        data = bytes([path_len]) + path[:path_bytes(path_len)]
        if extra:
            data += bytes([extra_type]) + extra
        else:
            data += b"\xFF" + os.urandom(4)
        return Packet(PT_PATH, bytes([dest_hash, self.self_hash]) + encrypt_then_mac(secret, data))

    def make_ack(self, ack, extra=b""):
        return Packet(PT_ACK, ack + extra)

    def make_advert(self):
        flags = ADV_TYPE_ROOM
        body = b""
        lat, lon = float(self.cfg.lat), float(self.cfg.lon)
        if lat or lon:
            flags |= ADV_LATLON_MASK
            body += struct.pack("<ii", int(lat * 1e6), int(lon * 1e6))
        name = self.cfg.name.encode()[:MAX_ADVERT_DATA_SIZE - 1 - len(body)]
        while name:
            try:
                name.decode()
                break
            except UnicodeDecodeError:
                name = name[:-1]
        if name:
            flags |= ADV_NAME_MASK
        app_data = bytes([flags]) + body + name
        ts = struct.pack("<I", now_s())
        sig = self.id.sign(self.id.pub_key + ts + app_data)
        return Packet(PT_ADVERT, self.id.pub_key + ts + sig + app_data)

    # ------------------------------------------------------------------ dedupe

    def was_seen(self, pkt):
        return pkt.packet_hash() in self.seen

    def seen_mark(self, pkt):
        self.seen[pkt.packet_hash()] = None
        while len(self.seen) > 512:
            self.seen.pop(next(iter(self.seen)))

    def check_dup(self, pkt):
        if self.was_seen(pkt):
            self.stats["direct_dups" if pkt.is_direct else "flood_dups"] += 1
            return True
        self.seen_mark(pkt)
        return False

    # ------------------------------------------------------------------ receive

    def on_rx(self, raw, snr, rssi):
        pkt = Packet.parse(raw)
        self.stats["recv"] += 1
        if pkt is None:
            self.stats["errors"] += 1
            return
        pkt.snr, pkt.rssi = snr, rssi
        self.last_snr, self.last_rssi = snr, rssi
        self.last_rx_mono = time.monotonic()
        self.rx_airtime_ms += self.airtime_ms(len(raw))
        self.stats["recv_flood" if pkt.is_flood else "recv_direct"] += 1
        if pkt.is_flood or (pkt.ptype == PT_ADVERT and pkt.hop_count == 0):
            try:
                self.observe_flood_path(pkt)                 # repeater map: every flood, duplicates included
            except Exception:
                log.exception("topology")
        if pkt.is_flood and self.flood_owner and pkt.ptype in (PT_PATH, PT_REQ, PT_TXT_MSG, PT_ANON_REQ, PT_ADVERT):
            own = self.flood_owner.get(pkt.packet_hash())
            if own and own[1] > time.monotonic() and self.was_seen(pkt):
                self.observe_inpath(own[0], pkt)            # another copy of a member's flood: another inbound path
        if pkt.ptype == PT_TRACE and pkt.is_direct:
            try:
                self.observe_trace(pkt)                      # free per-hop SNR from other people's traces
                if not self.trace_reply(pkt):                # our own neighbour trace coming back?
                    self.relay_trace(pkt)                    # else take part when a trace names the room as next hop
            except Exception:
                log.exception("trace")
            return
        if pkt.is_direct and pkt.hop_count > 0:
            return                                         # being routed via others: not for us (no forwarding)
        t = pkt.ptype
        if t == PT_ACK:
            if len(pkt.payload) >= 4 and not self.check_dup(pkt):
                self.process_ack(pkt.payload[:4])
        elif t == PT_MULTIPART:
            if len(pkt.payload) >= 5 and (pkt.payload[0] & 0x0F) == PT_ACK:
                tmp = Packet(PT_ACK, pkt.payload[1:])
                tmp.header = pkt.header
                if not self.check_dup(tmp):
                    self.process_ack(tmp.payload[:4])
        elif t in (PT_PATH, PT_REQ, PT_RESPONSE, PT_TXT_MSG):
            self.on_peer_packet(pkt)
        elif t == PT_ANON_REQ:
            self.on_anon_req(pkt)
        elif t == PT_ADVERT:
            self.on_advert(pkt)
        elif t == PT_CONTROL and pkt.is_direct and pkt.hop_count == 0:
            self.on_control(pkt)

    def on_peer_packet(self, pkt):
        p = pkt.payload
        if len(p) <= 2 + CIPHER_MAC_SIZE or self.check_dup(pkt):
            return
        if p[0] != self.self_hash:
            return
        if pkt.ptype == PT_PATH:                            # a kicked/banned person's flooded ACK for their notice
            for n in [n for n in self.notices if n["pub"][0] == p[1]]:
                data = mac_then_decrypt(n["secret"], p[2:])
                if data is not None and path_valid(data[0]):
                    k = 1 + path_bytes(data[0])
                    if k < len(data) and (data[k] & 0x0F) == PT_ACK and len(data) >= k + 5:
                        self.process_ack(data[k + 1:k + 5])
                        return
        for m in [m for m in self.members.values() if m.pub[0] == p[1]]:
            data = mac_then_decrypt(self.secret_for(m), p[2:])
            if data is None:
                continue
            if pkt.is_flood:
                self.observe_member_at(m, pkt.path[:pkt.hash_size] if pkt.hop_count else b"")
                self.member_flood(m, pkt)
            if pkt.ptype == PT_PATH:
                plen = data[0]
                if not path_valid(plen):
                    return
                k = 1 + path_bytes(plen)
                path = data[1:k]
                extra_type = data[k] & 0x0F if k < len(data) else 0xFF
                extra = data[k + 1:]
                self.on_path_return(m, plen, path, extra_type, extra)
            elif pkt.ptype == PT_TXT_MSG:
                self.on_txt(pkt, m, data)
            elif pkt.ptype == PT_REQ:
                self.on_req(pkt, m, data)
            return

    # ------------------------------------------------------------------ login (ANON_REQ)

    def on_anon_req(self, pkt):
        p = pkt.payload
        if len(p) <= 1 + PUB_KEY_SIZE + 2 or self.check_dup(pkt) or p[0] != self.self_hash:
            return
        sender = p[1:1 + PUB_KEY_SIZE]
        if sender in self.bans:
            return                                          # banned: the room never answers them
        known = self.members.get(sender)
        secret = known.secret if known and known.secret else self.id.shared_secret(sender)
        data = mac_then_decrypt(secret, p[1 + PUB_KEY_SIZE:])
        if data is None or len(data) < 9:
            return
        sender_ts, sync_since = struct.unpack_from("<II", data, 0)
        password = data[8:].split(b"\0", 1)[0].decode(errors="replace")
        m = None
        was_member = sender in self.members
        if password == "":                                  # blank: existing member reconnecting
            m = self.members.get(sender)
            if m and sender_ts > m.last_timestamp:
                m.last_timestamp = sender_ts
                m.last_activity = now_s()
                self.reset_push_state(m)
                self.mark_dirty()
        if m is None:
            if password == self.cfg.admin_password:
                perm = PERM_ADMIN
            elif password == self.cfg.room_password:
                perm = PERM_READ_WRITE
            elif self.cfg.allow_read_only:
                perm = PERM_GUEST
            else:
                return                                      # no response: client times out
            m = self.members.get(sender) or self.put_member(sender)
            if sender_ts <= m.last_timestamp:
                return                                      # replay
            m.last_timestamp = sender_ts
            m.sync_since = sync_since
            m.pending_ack = None
            self.reset_push_state(m)
            # brand-new member (has never received a post): only the newest catchup_max posts
            public = [p for p in self.posts if p[3] is None]
            if sync_since == 0 and 0 < self.cfg.catchup_max < len(public):
                m.sync_since = public[-self.cfg.catchup_max - 1][0]
            m.last_activity = now_s()
            m.perms = (m.perms & ~3) | perm
            m.secret = secret
            self.mark_dirty()
        if pkt.is_flood:
            self.observe_member_at(m, pkt.path[:pkt.hash_size] if pkt.hop_count else b"")
            self.member_flood(m, pkt)
        if not was_member and m.perms != PERM_GUEST and self.cfg.welcome_new_members and self.cfg.welcome_message:
            msg = str(self.cfg.welcome_message).replace("{room}", self.cfg.name)
            if m.pub[:8] not in self.names and self.cfg.welcome_advert_hint:
                msg += " " + str(self.cfg.welcome_advert_hint).replace("{room}", self.cfg.name)
            self.store_post(self.id.pub_key, msg.strip(), to=m.pub)   # private message, only pushed to them
        reply = struct.pack("<I", self.unique_time()) + bytes([
            RESP_SERVER_LOGIN_OK, 0, 1 if m.is_admin else (2 if m.perms == 0 else 0), m.perms]) \
            + os.urandom(4) + bytes([FIRMWARE_VER_LEVEL])
        self.next_push = time.monotonic() + PUSH_NOTIFY_DELAY
        if pkt.is_flood:
            # tell them the path TO us, carrying the response
            m.in_path, m.in_path_len, m.in_ts = bytes(pkt.path[:path_bytes(pkt.path_len)]), pkt.path_len, now_s()
            pr = self.make_path_return(sender[0], secret, pkt.path, pkt.path_len, PT_RESPONSE, reply)
            self.send_flood(pr, SERVER_RESPONSE_DELAY, pkt.hash_size)
        else:
            self.send_to(m, self.make_datagram(PT_RESPONSE, sender, secret, reply), SERVER_RESPONSE_DELAY, pkt)

    def suggest_route(self, pub, hops):
        """Admin-suggested route (list of repeater id bytes, room side first): stored as a proven-route
        candidate at medium confidence (~60%), then it earns or loses rank on real deliveries like any other."""
        m = self.members.get(pub)
        if m is None or not hops:
            return False
        size = len(hops[0])
        plen = ((size - 1) << 6) | len(hops)
        path = b"".join(hops)
        r = self.find_route(m, plen, path) or self.learn_route(m, plen, path, proven=False)
        if r is None:
            return False
        now = now_s()
        s_, n_ = r.evidence(now, self.rhalf())
        if (s_ + 1) / (n_ + 2) < 0.6:                       # never lowers a route that's already doing better
            r.s, r.n, r.t = 2.0, 3.0, now                   # (2 + 1) / (3 + 2) = 60%
        self.update_current(m)
        log.info("suggested route for %s: %s", self.member_label(m), " > ".join(self.rpt_label(h) for h in hops))
        return True

    def force_resync(self, pub):
        """Pry a member loose: clear backoff / give-up, fresh full attempt plan, first in the push queue."""
        m = self.members.get(pub)
        if m is None:
            return None
        self.reset_push_state(m)                            # backoff, give-up, old plan
        m.attempts_cur = 0
        if m.last_activity == 0:
            m.last_activity = now_s()
        pending = self.unsynced_count(m)
        if pending:
            self.round = [pub] + [k for k in self.round if k != pub]
            self.next_push = min(self.next_push, time.monotonic() + 0.1)
        log.info("force resync %s: %d post(s) outstanding%s", self.member_label(m), pending,
                 ", push already in flight" if m.pending_ack else "")
        self.mark_dirty()
        return pending

    def find_member(self, prefix):
        hits = [m for m in self.members.values() if m.pub.startswith(prefix)]
        return hits[0] if len(hits) == 1 else None

    def notify_once(self, m, text):
        """Message from the room to one member that doesn't hold anything up: queued and retried in the
        background (best route, best route, flood) until their node ACKs it, even if they're kicked/banned."""
        if not text:
            return
        text = text.replace("{room}", self.cfg.name).encode()[:MAX_POST_TEXT_LEN].decode(errors="ignore")
        data = struct.pack("<I", self.unique_time()) + bytes([TXT_TYPE_SIGNED_PLAIN << 2]) + self.id.pub_key[:4] + text.encode()
        notice = dict(pub=m.pub, secret=self.secret_for(m), data=data, ack=sha256(data, m.pub)[:4], tries=0, next_at=0.0,
                      path=m.out_path, plen=m.out_path_len, label=self.member_label(m), text=text)
        self.notices.append(notice)
        self.send_notice(notice)

    def send_notice(self, n):
        pkt = self.make_datagram(PT_TXT_MSG, n["pub"], n["secret"], n["data"])
        airtime = self.airtime_ms(pkt.raw_length() + (path_bytes(n["plen"]) if n["plen"] is not None else 0))
        if n["plen"] is not None and n["tries"] < 2:
            self.send_direct(pkt, n["path"], n["plen"])
            hops = n["plen"] & 63
            wait = max(4.0 + 2.0 * (hops + 1), (500 + (airtime * 6 + 250) * (hops + 1)) / 1000.0)
        else:
            self.send_flood(pkt)
            wait = max(FLOOD_ACK_MIN, (500 + 32 * airtime) / 1000.0)
        n["tries"] += 1
        n["next_at"] = time.monotonic() + wait
        log.info("sent to %s (attempt %d of 3): %s", n["label"], n["tries"], n["text"])

    def service_notices(self):
        now = time.monotonic()
        for n in list(self.notices):
            if now >= n["next_at"]:
                if n["tries"] >= 3:
                    self.notices.remove(n)
                    log.info("no ACK from %s for: %s", n["label"], n["text"])
                else:
                    self.send_notice(n)

    def kick(self, pub, message=None):
        """Remove a member completely, as if they never joined (they can log in again)."""
        m = self.members.get(pub)
        if m is None:
            return False
        self.notify_once(m, self.cfg.kick_message if message is None else message)   # queued before they're removed
        self.members.pop(pub, None)
        private = [p for p in self.posts if p[3] == pub]
        if private:
            self.posts = [p for p in self.posts if p[3] != pub]
            self.store.execmany([("DELETE FROM posts WHERE to_key = ?", [(pub,)])])
        self.round = [k for k in self.round if k != pub]
        self.flush()                                        # writes the removal right away
        log.info("kicked %s", self.member_label(m))
        return True

    def ban(self, pub):
        nm = self.names.get(pub[:8])
        name = nm[1] if nm else ""
        self.kick(pub, message=self.cfg.ban_message)
        self.bans[pub] = dict(name=name, ts=now_s())
        self.store.execmany([("INSERT OR REPLACE INTO bans VALUES (?,?,?)", [(pub, name, now_s())])])
        log.info("banned %s %s", hexs(pub[:6]), name)
        self.mark_dirty()

    def unban(self, pub):
        if self.bans.pop(pub, None) is not None:
            self.store.execmany([("DELETE FROM bans WHERE pubkey = ?", [(pub,)])])
            log.info("unbanned %s", hexs(pub[:6]))
            self.mark_dirty()
            return True
        return False

    def put_member(self, pub):
        if len(self.members) >= 256:                        # evict least recently active non-admin
            victims = [m for m in self.members.values() if not m.is_admin]
            if victims:
                del self.members[min(victims, key=lambda m: m.last_activity).pub]
        m = Member(pub)
        self.members[pub] = m
        return m

    # ------------------------------------------------------------------ posts / CLI

    def on_txt(self, pkt, m, data):
        if len(data) <= 5:
            return
        sender_ts = struct.unpack_from("<I", data, 0)[0]
        flags = data[4] >> 2
        if flags not in (TXT_TYPE_PLAIN, TXT_TYPE_CLI_DATA, TXT_TYPE_CLI_COMMAND):
            return
        if sender_ts < m.last_timestamp:
            return                                          # replay
        is_retry = sender_ts == m.last_timestamp
        m.last_timestamp = sender_ts
        m.last_activity = now_s()
        self.reset_push_state(m)
        self.mark_dirty()
        text_b = data[5:].split(b"\0", 1)[0]
        ack = sha256(data[:5 + len(text_b)], m.pub)[:4]
        text = text_b.decode(errors="replace")
        reply_text = None
        send_ack = False
        if flags in (TXT_TYPE_CLI_DATA, TXT_TYPE_CLI_COMMAND):
            if m.is_admin and not is_retry:
                reply_text = self.handle_cli(text)
        elif m.role != PERM_GUEST:
            if not is_retry and self.is_manual_resend(m, text):
                is_retry = True                             # same text again: they never saw our ACK
                self.stats["deduped"] += 1
                log.info("dropped duplicate from %s (re-sent identical text): %s", self.member_label(m), text)
            if not is_retry:
                self.store_post(m.pub, text)
            send_ack = True                                 # ACK either way, so their app shows it delivered
        delay = 0.0
        if send_ack:
            delay = self.send_post_ack(m, ack, pkt) + 0.25
        if reply_text:
            t = self.unique_time()
            if t == sender_ts:
                t += 1
            body = struct.pack("<I", t) + bytes([TXT_TYPE_CLI_DATA << 2]) + reply_text.encode()[:150]
            self.send_to(m, self.make_datagram(PT_TXT_MSG, m.pub, self.secret_for(m), body),
                         delay + SERVER_RESPONSE_DELAY, pkt)

    def is_manual_resend(self, m, text):
        """True if this text is identical to the member's own previous post, sent within dedupe_window_s."""
        window = int(self.cfg.dedupe_window_s or 0)
        if window <= 0:
            return False
        for ts, author, prev, to in reversed(self.posts):
            if author == m.pub and to is None:
                return prev == text[:MAX_POST_TEXT_LEN] and now_s() - ts <= window
        return False

    def send_post_ack(self, m, ack, req_pkt):
        """ACK a member's post. No route: one flood ACK. With extra_acks: a multipart ACK first (firmware format),
        on a second confident route when there is one (independent failure), else on the same route; then the
        normal ACK on the best route 300 ms later. Returns the delay of the last ACK."""
        if m.out_path_len is None:
            self.send_flood(self.make_ack(ack), TXT_ACK_DELAY, req_pkt.hash_size)
            return TXT_ACK_DELAY
        d = TXT_ACK_DELAY
        if self.cfg.extra_acks:
            alt = self.second_route(m)
            path, plen = (alt.path, alt.len) if alt else (m.out_path, m.out_path_len)
            self.send_direct(Packet(PT_MULTIPART, bytes([(1 << 4) | PT_ACK]) + ack), path, plen, d)
            d += 0.3
        self.send_direct(self.make_ack(ack), m.out_path, m.out_path_len, d)
        return d

    def second_route(self, m):
        """A confident (>= 60%) route other than the current one, preferring a different first repeater."""
        now = now_s()
        others = [r for r in m.routes if not self.is_current(m, r) and r.rate(now, self.rhalf()) >= 0.6]
        if not others:
            return None
        sz = (m.out_path_len >> 6) + 1 if m.out_path_len else 0
        first = m.out_path[:sz] if sz and (m.out_path_len & 63) else b""

        def key(r):
            rsz = (r.len >> 6) + 1
            different_first = (r.path[:rsz] if r.len & 63 else b"") != first
            return (different_first, r.rate(now, self.rhalf()))
        return max(others, key=key)

    def store_post(self, author, text, to=None):
        ts = self.unique_time()
        self.max_issued = ts
        text = text[:MAX_POST_TEXT_LEN]
        self.posts.append((ts, author, text, to))
        prune = 0
        public = [p for p in self.posts if p[3] is None]
        if len(public) > self.cfg.max_posts:                # only room posts count toward max_posts;
            prune = public[-self.cfg.max_posts][0]          # private messages are kept until delivered
            self.posts = [p for p in self.posts if p[3] is not None or p[0] >= prune]
        self.store.add_post(ts, author, text, to, prune)    # written by the db thread
        if to is None:
            self.stats["posted"] += 1
        self.next_push = time.monotonic() + PUSH_NOTIFY_DELAY
        self.mark_dirty()
        log.info("%s %s from %s: %s", "post" if to is None else "private post to " + hexs(to[:4]), ts, hexs(author[:4]), text)

    def room_say(self, text):
        """A post from the room itself (admin chat box): stored and pushed to every member."""
        b = text.strip().encode()[:MAX_POST_TEXT_LEN]
        text = b.decode(errors="ignore")                    # never cut a UTF-8 character in half
        if text:
            self.store_post(self.id.pub_key, text)

    def chat_label(self, author):
        if author == self.id.pub_key:
            return self.cfg.name + " (room)"
        nm = self.names.get(author[:8])
        return nm[1] if nm else hexs(author[:4])

    def drop_private(self, pub, ts=None, older_than=None):
        """Remove delivered (ts) or expired (older_than) private messages for pub (any member if pub is None)."""
        gone = [p for p in self.posts if p[3] is not None and (pub is None or p[3] == pub)
                and (ts is None or p[0] == ts) and (older_than is None or p[0] < older_than)]
        if not gone:
            return
        self.posts = [p for p in self.posts if p not in gone]
        self.store.execmany([("DELETE FROM posts WHERE ts = ? AND to_key IS NOT NULL", [(p[0],) for p in gone])])

    def unsynced_count(self, m):
        n = sum(1 for ts, a, _, to in self.posts if ts > m.sync_since and (to is None or to == m.pub) and a[:4] != m.pub[:4])
        return min(n, 255)

    # ------------------------------------------------------------------ requests

    def on_req(self, pkt, m, data):
        if len(data) < 5:
            return
        sender_ts = struct.unpack_from("<I", data, 0)[0]
        if sender_ts < m.last_timestamp:
            return
        m.last_timestamp = sender_ts
        m.last_activity = now_s()
        self.reset_push_state(m)
        self.mark_dirty()
        if data[4] == REQ_KEEP_ALIVE and pkt.is_direct:
            force_since = struct.unpack_from("<I", data, 5)[0] if len(data) >= 9 else 0
            if force_since:
                m.sync_since = force_since
            if m.pending_ack:                               # keep the abandoned attempt's ACK
                m.prev_acks = [m.pending_ack, m.prev_acks[0]]
                m.prev_entries = [m.inflight, m.prev_entries[0]]
            m.pending_ack = None
            m.inflight = None
            if m.out_path_len is not None:
                body = data[:9] if len(data) >= 9 else data[:5] + bytes(4)
                ack = sha256(body, m.pub)[:4]
                self.send_direct(self.make_ack(ack, bytes([self.unsynced_count(m)])),
                                 m.out_path, m.out_path_len, SERVER_RESPONSE_DELAY)
            return
        reply = self.handle_request(m, sender_ts, data[4:])
        if not reply:
            return
        if pkt.is_flood:
            m.in_path, m.in_path_len, m.in_ts = bytes(pkt.path[:path_bytes(pkt.path_len)]), pkt.path_len, now_s()
            self.mark_dirty()
            pr = self.make_path_return(m.pub[0], self.secret_for(m), pkt.path, pkt.path_len, PT_RESPONSE, reply)
            self.send_flood(pr, SERVER_RESPONSE_DELAY, pkt.hash_size)
        else:
            self.send_to(m, self.make_datagram(PT_RESPONSE, m.pub, self.secret_for(m), reply), SERVER_RESPONSE_DELAY, pkt)

    def handle_request(self, m, sender_ts, p):
        head = struct.pack("<I", sender_ts)
        if p[0] == REQ_GET_STATUS:
            s = self.stats
            up = int(time.monotonic() - self.boot)
            stats = struct.pack("<HHhhIIIIIIIIHhHHHH",
                                self.batt_mv, min(len(self.txq), 0xFFFF), int(self.noise_floor), int(self.last_rssi),
                                s["recv"], s["sent"], s["airtime_ms"] // 1000, up,
                                s["sent_flood"], s["sent_direct"], s["recv_flood"], s["recv_direct"],
                                s["errors"] & 0xFFFF, int(self.last_snr * 4),
                                s["direct_dups"] & 0xFFFF, s["flood_dups"] & 0xFFFF,
                                s["posted"] & 0xFFFF, s["pushes"] & 0xFFFF)
            return head + stats
        if p[0] == REQ_GET_TELEMETRY:
            lpp = struct.pack(">BBH", 1, 116, int(self.batt_mv / 10))           # channel 1, voltage, 0.01 V
            temp = self.mcu_temp_c
            if temp is not None:
                lpp += struct.pack(">BBh", 1, 103, int(temp * 10))             # temperature, 0.1 C
            return head + lpp
        if p[0] == REQ_GET_ACCESS_LIST and m.is_admin and len(p) >= 3 and p[1] == 0 and p[2] == 0:
            out = head
            for a in self.members.values():
                if a.is_admin and len(out) + 7 <= 170:
                    out += a.pub[:6] + bytes([a.perms])
            return out
        if p[0] == REQ_GET_NEIGHBOURS and len(p) >= 7 and p[1] == 0:
            count, offset, order_by, prefix_len = p[2], struct.unpack_from("<H", p, 3)[0], p[5], min(p[6], 32)
            nb = list(self.neighbours.items())
            keyf = {1: lambda x: x[1]["heard"], 2: lambda x: -x[1]["snr4"], 3: lambda x: x[1]["snr4"]}.get(order_by, lambda x: -x[1]["heard"])
            nb.sort(key=keyf)
            res, n, t = b"", 0, now_s()
            for pub, info in nb[offset:offset + count]:
                entry = pub[:prefix_len] + struct.pack("<Ib", t - info["heard"], info["snr4"])
                if len(res) + len(entry) > 130:
                    break
                res += entry
                n += 1
            return head + struct.pack("<hh", len(nb), n) + res
        return None

    # ------------------------------------------------------------------ path returns / ACKs

    def on_path_return(self, m, plen, path, extra_type, extra):
        m.last_activity = now_s()
        r = self.learn_route(m, plen, path, proven=True)    # a flood of ours reached them this way
        if r is not None:
            m.out_path, m.out_path_len = r.path, r.len      # freshest evidence: use it now
        sz = (plen >> 6) + 1
        self.observe_member_at(m, path[path_bytes(plen) - sz:path_bytes(plen)] if plen & 63 else b"")
        self.mark_dirty()
        if extra_type == PT_ACK and len(extra) >= 4:
            self.process_ack(extra[:4])
        # (rooms don't send a reciprocal path return, same as the firmware)

    def process_ack(self, ack):
        for n in self.notices:                              # a kick/ban message got through: stop retrying
            if ack == n["ack"]:
                self.notices.remove(n)
                log.info("%s received: %s", n["label"], n["text"])
                return True
        for m in self.members.values():
            late = None
            match = m.pending_ack is not None and ack == m.pending_ack
            if not match:
                for j in (0, 1):
                    if m.prev_acks[j] is not None and ack == m.prev_acks[j]:
                        match, late = True, j
                        break
            if not match:
                continue
            lat_ms = None
            if late is None and m.push_sent:
                lat_ms = int((time.monotonic() - m.push_sent) * 1000)
                b = 5 if m.push_hops == 0xFF else min(m.push_hops, 4)
                self.lat_sum[b] += lat_ms
                self.lat_cnt[b] += 1
            self.stats["late_acks" if late is not None else "acks"] += 1
            entry = m.prev_entries[late] if late is not None else m.inflight
            self.attempt_result(m, entry, True, lat_ms)
            if late is None and m.pub == self.last_pushed:
                self.next_push = min(self.next_push, time.monotonic() + 0.5)   # ACK back: no need to keep waiting
            if m.attempts_cur:
                self.delivery_sample(m, m.attempts_cur)
                m.deliveries += 1
                m.attempts_cur = 0
            m.pending_ack = None
            m.inflight = None
            m.prev_acks = [None, None]
            m.prev_entries = [None, None]
            m.sync_since = m.push_post_ts
            self.drop_private(m.pub, m.push_post_ts)            # private message delivered: no longer needed
            m.push_failures = 0
            m.plan, m.plan_retry = None, False
            m.backoff, m.retry_at, m.stuck_since = 0, 0.0, 0.0
            if m.given_up:
                m.given_up = False
            self.mark_dirty()
            return True
        return False

    # ------------------------------------------------------------------ routes: proven (per member)

    def rhalf(self):
        return max(0.1, float(self.cfg.route_halflife_h)) * 3600.0

    def thalf(self):
        return max(0.1, float(self.cfg.topology_halflife_h)) * 3600.0

    def find_route(self, m, plen, path):
        for r in m.routes:
            if r.same(plen, path):
                return r
        return None

    def is_current(self, m, r):
        return m.out_path_len is not None and r.same(m.out_path_len, m.out_path)

    def learn_route(self, m, plen, path, proven):
        """Add (or refresh) a proven-route candidate; proven=True counts one delivery."""
        if plen is None:
            return None
        now = now_s()
        r = self.find_route(m, plen, path)
        if r is None:
            if len(m.routes) >= self.cfg.routes_per_member:
                worst = min(m.routes, key=lambda x: x.rate(now, self.rhalf()))
                m.routes.remove(worst)
            r = ProvenRoute(plen, path, now)
            m.routes.append(r)
        if proven:
            r.record(True, now, self.rhalf())
        self.update_current(m)
        return r

    def update_current(self, m, mark=True):
        """The member's current route = best-rated proven route (used for replies, ACKs, sorting)."""
        now = now_s()
        best = max(m.routes, key=lambda r: (round(r.rate(now, self.rhalf()), 2), -(r.len & 63), r.last_ok), default=None)
        if best is None:
            if m.out_path_len is not None and not m.routes:
                m.out_path, m.out_path_len = b"", None
        else:
            m.out_path, m.out_path_len = best.path, best.len
        if mark:
            self.mark_dirty()

    def prune_routes(self, m):
        now = now_s()
        for r in list(m.routes):
            s_, n_ = r.evidence(now, self.rhalf())
            dead = n_ >= 2 and r.rate(now, self.rhalf()) < 0.2
            stale = now - max(r.last_ok, r.added_at) > ROUTE_MAX_AGE_D * 86400
            if dead or stale:
                m.routes.remove(r)
        self.update_current(m)

    # ------------------------------------------------------------------ repeater map (database 1)

    def observe_flood_path(self, pkt):
        """Every flood packet's path, read backwards, is a route to each repeater on it.
        A path lists only the relays; for a repeater's own advert the sender is known (its public key),
        so it's added as the first hop: a zero-hop repeater advert means "heard this repeater directly"."""
        k, sz = pkt.hop_count, pkt.hash_size
        if sz > 3:
            return
        path = pkt.path[:k * sz]
        p = pkt.payload
        hdr = PUB_KEY_SIZE + 4 + SIGNATURE_SIZE
        origin = None
        if pkt.ptype == PT_ADVERT and len(p) > hdr and (p[hdr] & 0x0F) == ADV_TYPE_REPEATER and p[:32] != self.id.pub_key:
            origin = p[:32]                                 # the sending repeater: known exactly
        if sz == 1:
            # 1-byte path entries are ambiguous (a 2-byte repeater relaying a 1-byte packet adds only its
            # first byte; 256 values collide constantly): learn only what a repeater's own advert proves
            if origin is not None:
                if k == 0:
                    self._observe_hashes([origin[:2]], 2, pkt.snr)       # heard directly: its 2-byte id
                else:
                    self._touch_heard(origin[:2], direct=False)          # alive, route unknown
            return
        if origin is not None:
            path = origin[:sz] + path
            k += 1
        if k == 0:
            return
        self._observe_hashes([path[i * sz:(i + 1) * sz] for i in range(k)], sz, pkt.snr)

    # ------------------------------------------------------------------ repeater discovery (zero-hop)

    def send_discovery(self):
        """MeshCore node discovery (as repeaters send it): every repeater that hears this directly answers with its
        key and the SNR it heard us at (outbound), and we measure its reply (inbound)."""
        self.disc_tag = os.urandom(4)
        self.disc_until = time.monotonic() + 60
        data = bytes([0x80, 1 << ADV_TYPE_REPEATER]) + self.disc_tag + struct.pack("<I", 0)   # REQ, repeaters only, tag, since=0
        self.send_zero_hop(Packet(PT_CONTROL, data))
        self.disc_replies = 0
        self.disc_responders = set()
        self.disc_close_at = time.monotonic() + 20          # then neighbours that didn't answer count as a miss
        log.info("sent repeater discovery")

    def on_control(self, pkt):
        p = pkt.payload
        if len(p) < 6 + PUB_KEY_SIZE or (p[0] & 0xF0) != 0x90 or (p[0] & 0x0F) != ADV_TYPE_REPEATER:
            return
        if not self.disc_tag or time.monotonic() > self.disc_until or p[2:6] != self.disc_tag:
            return                                          # not an answer to our current discovery
        pub = p[6:6 + PUB_KEY_SIZE]
        if pub == self.id.pub_key:
            return
        out_snr = struct.unpack("b", p[1:2])[0] / 4.0       # how well it heard the room
        now = now_s()
        h = pub[:2]
        self._observe_hashes([h], 2, pkt.snr)               # heard directly + link it -> room (our SNR) + direct route
        hd = self.heard[h]
        hd["disc"], hd["out_snr"] = now, (out_snr if hd.get("out_snr") is None else hd["out_snr"] * 0.6 + out_snr * 0.4)
        self._link(b"", h, out_snr, now, self.thalf())       # room -> it: the SNR it reported
        if h not in self.disc_responders:
            self.disc_responders.add(h)
            self.probe_snr(h, pkt.snr, out_snr, discovery=True)   # SNR both ways; marks it as a neighbour to trace
        old_n = self.neighbours.get(pub, {})
        if pub not in self.neighbours and len(self.neighbours) >= MAX_NEIGHBOURS:
            del self.neighbours[min(self.neighbours, key=lambda k: self.neighbours[k]["heard"])]
        self.neighbours[pub] = dict(advert_ts=old_n.get("advert_ts", 0), heard=now, snr4=int(pkt.snr * 4), name=old_n.get("name", ""))
        if pub not in self.repeaters:
            self.repeaters[pub] = dict(name="", lat=None, lon=None, adv_ts=0, last_advert=0)
            self._rpt_idx = None
        self.disc_replies += 1
        log.info("discovery reply from %s: it hears us at %.1f dB, we hear it at %.1f dB", self.rpt_label(h), out_snr, pkt.snr)

    # ------------------------------------------------------------------ neighbour link probes (trace through each)

    def probe_stats(self, h):
        st = self.probes.setdefault(h, {})
        for k, v in (("last_ok", 0), ("in_last", None), ("in_avg", None), ("out_last", None), ("out_avg", None),
                     ("rtt", None), ("tr_s", 0.0), ("tr_n", 0.0), ("tr_t", now_s()), ("last_disc", 0)):
            st.setdefault(k, v)
        return st

    def probe_snr(self, h, in_snr, out_snr, rtt_ms=None, discovery=False):
        """A reply from neighbour h (discovery reply or returned trace): update SNR averages and last reply."""
        st = self.probe_stats(h)
        now = now_s()
        st["last_ok"] = now
        if discovery:
            st["last_disc"] = now
        st["in_last"], st["out_last"] = round(in_snr, 2), round(out_snr, 2)
        st["in_avg"] = in_snr if st["in_avg"] is None else st["in_avg"] * 0.7 + in_snr * 0.3
        st["out_avg"] = out_snr if st["out_avg"] is None else st["out_avg"] * 0.7 + out_snr * 0.3
        if rtt_ms is not None:
            st["rtt"] = rtt_ms if st["rtt"] is None else st["rtt"] * 0.7 + rtt_ms * 0.3
        self.save_probe(h)

    def trace_result(self, h, ok):
        st = self.probe_stats(h)
        now = now_s()
        f = 0.5 ** (max(0, now - st["tr_t"]) / (24 * 3600.0))
        st["tr_s"], st["tr_n"], st["tr_t"] = st["tr_s"] * f + (1.0 if ok else 0.0), st["tr_n"] * f + 1.0, now
        self.save_probe(h)

    def save_probe(self, h):
        self.store.execmany([("INSERT OR REPLACE INTO probes VALUES (?,?)", [(h, json.dumps(self.probes[h]))])])

    def trace_loss(self, st):
        """Recency-weighted share of traces that never came back (None until traced)."""
        f = 0.5 ** (max(0, now_s() - st["tr_t"]) / (24 * 3600.0))
        n = st["tr_n"] * f
        return None if n < 0.3 else 1.0 - (st["tr_s"] * f) / n

    def close_discovery_round(self):
        self.disc_close_at = 0.0
        log.info("discovery round: %d repeater(s) answered", len(self.disc_responders))

    # ------------------------------------------------------------------ neighbour traces (one at a time, when idle)

    def maybe_trace(self):
        """Called at the end of each round through the members: trace the next neighbour in rotation, but only
        when the room is idle (no push awaiting an ACK, nothing queued, channel quiet) and not too often."""
        if not self.cfg.trace_neighbours or self.trace_pending:
            return
        now = time.monotonic()
        if now - self.last_trace < float(self.cfg.trace_min_interval_s) or now - self.last_rx_mono < 2.0:
            return
        if self.txq or now < self.tx_busy_until or any(m.pending_ack for m in self.members.values()):
            return
        t = now_s()
        # neighbours that replied to anything (discovery or a trace) in the last 24 h; the least recently traced goes next
        targets = [h for h, st in self.probes.items() if t - max(st.get("last_disc") or 0, st.get("last_ok") or 0) < 86400]
        if not targets:
            return
        h = min(targets, key=lambda x: (self.probes[x].get("last_trace") or 0, x))
        self.probes[h]["last_trace"] = t
        tag = os.urandom(4)
        pkt = Packet(PT_TRACE, tag + bytes(4) + bytes([1]) + h)   # tag, auth (unused), 2-byte entries, route = just this repeater
        pkt.header = (pkt.header & ~0x03) | ROUTE_DIRECT
        pkt.path_len, pkt.path = 0, b""
        self.queue_tx(pkt, 1)
        self.trace_pending = (tag, h, now)
        self.last_trace = now
        log.debug("trace through %s", self.rpt_label(h))

    def check_trace_timeout(self):
        if self.trace_pending and time.monotonic() - self.trace_pending[2] > 15:
            _, h, _ = self.trace_pending
            self.trace_pending = None
            self.trace_result(h, False)
            log.info("trace through %s: lost", self.rpt_label(h))

    def trace_reply(self, pkt):
        """Our trace came back: the repeater appended the SNR it heard us at; we measured its retransmission."""
        p = pkt.payload
        if not self.trace_pending or len(p) < 9 or p[:4] != self.trace_pending[0]:
            return False
        es = 1 << (p[8] & 0x03)
        if pkt.hop_count < 1 or pkt.hop_count * es < len(p) - 9:
            return False
        _, h, sent = self.trace_pending
        self.trace_pending = None
        out_snr = struct.unpack("b", pkt.path[:1])[0] / 4.0
        rtt = int((time.monotonic() - sent) * 1000)
        self.trace_result(h, True)
        self.probe_snr(h, pkt.snr, out_snr, rtt)
        log.info("trace through %s: out %.1f dB, in %.1f dB, %d ms", self.rpt_label(h), out_snr, pkt.snr, rtt)
        return True

    def relay_trace(self, pkt):
        """MeshCore trace forwarding (Mesh.cpp): if the next entry in the trace's route is us, append the SNR we
        received it at and send it on. The room forwards nothing else."""
        p = pkt.payload
        if len(p) < 9:
            return
        es = 1 << (p[8] & 0x03)
        route = p[9:]
        offset = pkt.hop_count * es                         # entries already visited = SNRs collected so far
        if offset >= len(route) or route[offset:offset + es] != self.id.pub_key[:es]:
            return                                          # not our turn (or the trace is complete)
        if self.was_seen(pkt) or pkt.hop_count >= 63:
            return                                          # already relayed this one
        self.seen_mark(pkt)
        fwd = Packet(PT_TRACE, p)
        fwd.header = pkt.header
        fwd.path = pkt.path[:pkt.hop_count] + struct.pack("b", max(-128, min(127, int(round(pkt.snr * 4)))))
        fwd.path_len = pkt.hop_count + 1
        self.stats["traces_relayed"] = self.stats.get("traces_relayed", 0) + 1
        log.info("relaying trace (hop %d of %d, SNR %.1f)", fwd.path_len, len(route) // es, pkt.snr)
        self.queue_tx(fwd, 5, random.uniform(0.05, 0.4))    # small random delay, like repeaters

    def observe_trace(self, pkt):
        """A trace lists the repeaters it visits (payload) and collects, in its path field, the SNR each one
        measured when it received the trace. Overheard traces = measured link quality, both directions."""
        p = pkt.payload
        if len(p) < 9:
            return
        es = 1 << (p[8] & 0x03)                             # route entry size: 1, 2, 4 or 8 bytes
        if es == 1:
            return                                          # 1-byte ids are ambiguous: ignored
        hops = [p[i:i + es][:2] for i in range(9, len(p) - es + 1, es)]   # keyed by 2-byte id like the rest of the map
        snrs = [struct.unpack("b", bytes([b]))[0] / 4.0 for b in pkt.path[:pkt.hop_count]]
        now = now_s()
        th = self.thalf()
        done = min(len(snrs), len(hops))                    # hops completed so far
        for i in range(1, done):                            # hops[i] received it from hops[i-1] at snrs[i]
            self._link(hops[i - 1], hops[i], snrs[i], now, th)
        for h in hops[:done]:
            self._touch_heard(h, direct=False)
        if done:                                            # we heard the repeater that forwarded it last
            self._link(hops[done - 1], b"", pkt.snr, now, th)
            self._touch_heard(hops[done - 1], direct=True, snr=pkt.snr)
            self.stats["traces"] += 1

    def _link(self, a, b, snr, now, th):
        """Link a -> b seen (b received from a); snr = what b measured, averaged."""
        e = self.edges.get((a, b))
        if e is None:
            e = self.edges[(a, b)] = [0.0, now, None]
        e[0] = fade(e[0], e[1], now, th) + 1.0
        e[1] = now
        if snr is not None:
            e[2] = snr if e[2] is None else e[2] * 0.8 + snr * 0.2

    def _touch_heard(self, h, direct, snr=None):
        now = now_s()
        hd = self.heard.get(h)
        if hd is None:
            hd = self.heard[h] = dict(last=now, w=0.0, t=now, last_direct=0, snr=None, disc=0, out_snr=None)
        hd["w"] = fade(hd["w"], hd["t"], now, 6 * 3600.0) + 1.0
        hd["t"] = hd["last"] = now
        if direct:
            hd["last_direct"] = now
            hd["snr"] = snr if hd["snr"] is None else hd["snr"] * 0.8 + snr * 0.2

    def _observe_hashes(self, hashes, sz, snr):
        """hashes = repeaters in travel order (first = farthest from the room, last = heard by the room)."""
        k = len(hashes)
        now = now_s()
        th = self.thalf()
        for j in range(k):
            target = hashes[j][:2]                          # one entry per repeater, whatever id size the packet used
            route = b"".join(reversed(hashes[j:]))          # (the route itself keeps its real id size)
            plen = ((sz - 1) << 6) | (k - j)
            tab = self.rroutes.setdefault(target, {})
            rr = tab.get((plen, route))
            if rr is None:
                if len(tab) >= 6:
                    for x in tab.values():
                        x.faded(now, th)
                    del tab[min(tab, key=lambda key: tab[key].w)]
                rr = tab[(plen, route)] = RptRoute(plen, route, now)
            rr.faded(now, th)
            rr.w += 1.0
        # links between repeaters, and the last hop into the room (with our SNR for it)
        for i in range(k):
            a = hashes[i][:2]
            b = hashes[i + 1][:2] if i + 1 < k else b""
            self._link(a, b, snr if b == b"" else None, now, th)     # only the last hop's SNR is known (ours)
        for i, h in enumerate(hashes):
            self._touch_heard(h[:2], direct=(i == k - 1), snr=snr)
        if len(self.edges) > 4000 or len(self.rroutes) > 1500:
            self.trim_topology()

    def trim_topology(self):
        now = now_s()
        th = self.thalf()
        for key in [k for k, e in self.edges.items() if fade(e[0], e[1], now, th) < 0.05]:
            del self.edges[key]
        for target in list(self.rroutes):
            tab = self.rroutes[target]
            for key in list(tab):
                tab[key].faded(now, th)
                if tab[key].w < 0.05 and tab[key].ok < 0.05:
                    del tab[key]
            if not tab:
                del self.rroutes[target]

    def top_rpt_routes(self, target, n=3):
        tab = self.rroutes.get(target)
        if not tab:
            return []
        now = now_s()
        scored = sorted(((rr, rr.confidence(now, self.thalf())) for rr in tab.values()), key=lambda x: -x[1])
        return scored[:n]

    def best_rpt_route(self, target):
        tab = self.rroutes.get(target)
        if not tab:
            return None, 0.0
        now = now_s()
        best = max(tab.values(), key=lambda rr: rr.confidence(now, self.thalf()))
        return best, best.confidence(now, self.thalf())

    def rpt_feedback(self, plen, path, ok):
        """A push on this route delivered (credit every repeater along it) or failed (debit the end)."""
        if plen is None or (plen & 63) == 0:
            return
        sz, k = (plen >> 6) + 1, plen & 63
        now = now_s()
        hashes = [path[i * sz:(i + 1) * sz] for i in range(k)]
        for i in range(k):
            if not ok and i != k - 1:
                continue
            sub = b"".join(hashes[:i + 1])
            rr = self.rroutes.get(hashes[i][:2], {}).get((((sz - 1) << 6) | (i + 1), sub))
            if rr:
                rr.faded(now, self.thalf())
                if ok:
                    rr.ok += 1.0
                else:
                    rr.fail += 1.0

    # ------------------------------------------------------------------ member locations (database 2)

    def observe_member_at(self, m, rpt, weight=1.0):
        self.observe_near(m.pub, rpt, weight)

    def observe_inpath(self, pub, pkt):
        """A copy of a member's flood reached the room via pkt.path (member side first)."""
        if pub not in self.members:
            return
        now = now_s()
        key = (pkt.path_len, bytes(pkt.path[:path_bytes(pkt.path_len)])) if pkt.hop_count else (0, b"")   # one "direct" entry
        tab = self.inpaths.setdefault(pub[:8], {})
        e = tab.get(key)
        if e is None:
            if len(tab) >= 12:
                del tab[min(tab, key=lambda k: fade(tab[k][0], tab[k][1], now, self.rhalf()))]
            e = tab[key] = [0.0, now]
        e[0] = fade(e[0], e[1], now, self.rhalf()) + 1.0
        e[1] = now

    def member_flood(self, m, pkt):
        """First copy of a member's flood: remember it so later copies (other paths) are attributed too."""
        self.observe_inpath(m.pub, pkt)
        now = time.monotonic()
        if len(self.flood_owner) > 500:
            self.flood_owner = {k: v for k, v in self.flood_owner.items() if v[1] > now}
        self.flood_owner[pkt.packet_hash()] = (m.pub, now + 120)

    def observe_near(self, pub, rpt, weight=1.0):
        """Companion pub was heard via repeater rpt first (b"" = heard directly), time-weighted. Kept for every
        companion (members and not), so a newcomer already has a location. 1-byte ids are ignored."""
        if len(rpt) == 1:
            return
        rpt = rpt[:2]                                       # 2-byte id, like the rest of the map
        now = now_s()
        k8 = pub[:8]
        tab = self.mrpts.get(k8)
        if tab is None:
            if len(self.mrpts) >= NAME_CACHE_MAX:           # full: drop the companion heard from least recently (never a member)
                members8 = {mm.pub[:8] for mm in self.members.values()}
                cands = [k for k in self.mrpts if k not in members8]
                if not cands:
                    return
                del self.mrpts[min(cands, key=lambda k: max(e[1] for e in self.mrpts[k].values()) if self.mrpts[k] else 0)]
            tab = self.mrpts[k8] = {}
        e = tab.get(rpt)
        if e is None:
            if len(tab) >= 4:
                del tab[min(tab, key=lambda k: fade(tab[k][0], tab[k][1], now, self.rhalf()))]
            e = tab[rpt] = [0.0, now]
        e[0] = fade(e[0], e[1], now, self.rhalf()) + weight
        e[1] = now

    def member_locations(self, m):
        """[(repeater hash or b"", share 0..1)] most likely first."""
        tab = self.mrpts.get(m.pub[:8])
        if not tab:
            return []
        now = now_s()
        ws = {k: fade(v[0], v[1], now, self.rhalf()) for k, v in tab.items()}
        tot = sum(ws.values()) or 1.0
        return sorted(((k, w / tot) for k, w in ws.items() if w > 0.01), key=lambda x: -x[1])

    # ------------------------------------------------------------------ attempt plans

    def candidates(self, m):
        """Scored route candidates for m: proven routes, plus routes built from the repeater map."""
        now = now_s()
        out = {}
        for r in m.routes:
            out[(r.len, r.path)] = dict(plen=r.len, path=r.path, score=r.rate(now, self.rhalf()), proven=r, built=None)
        for rpt, share in self.member_locations(m):
            if rpt == b"":
                plen, path, conf = 0, b"", 1.0                       # heard directly: zero-hop direct
            else:
                rr, conf = self.best_rpt_route(rpt)
                if rr is None:
                    continue
                plen, path = rr.plen, rr.path
            score = share * conf
            key = (plen, path)
            if key in out:
                if out[key]["proven"] is not None:
                    continue                                          # proven evidence wins
                out[key]["score"] = max(out[key]["score"], score)
            else:
                out[key] = dict(plen=plen, path=path, score=score, proven=None, built=rpt)
        for r in list(m.routes):                            # shortcuts: skip hops the room doesn't need
            sc = self.shortcut_for(r)
            if sc is None:
                continue
            plen, path = sc
            if (plen, path) in out:
                continue                                    # already known (maybe already proven)
            out[(plen, path)] = dict(plen=plen, path=path, score=r.rate(now, self.rhalf()) * 0.85, proven=None, built="shortcut")
        # best score first; on (nearly) equal scores, fewer hops first
        return sorted(out.values(), key=lambda c: (-round(c["score"], 2), (c["plen"] or 0) & 63))

    def two_way_direct(self, h):
        """The room reaches repeater h directly, confirmed both ways: heard directly in the last 6 h, discovery says
        h hears the room (outbound SNR > 0), and traces (if any) mostly come back."""
        d = self.heard.get(h[:2])
        if not d or now_s() - (d.get("last_direct") or 0) > 6 * 3600:
            return False
        st = self.probes.get(h[:2])
        if not st or st.get("out_avg") is None or st["out_avg"] <= 0:
            return False
        loss = self.trace_loss(self.probe_stats(h[:2]))
        return loss is None or loss < 0.25

    def shortcut_for(self, r):
        """For proven route r, the suffix starting at the farthest repeater the room reaches directly (two-way),
        or None if no hop can be skipped. The suffix keeps the route's id size."""
        sz, k = (r.len >> 6) + 1, r.len & 63
        if k < 2:
            return None
        hops = [r.path[i * sz:(i + 1) * sz] for i in range(k)]
        for i in range(k - 1, 0, -1):                       # from the far end back toward the room (i > 0 = a real shortcut)
            if self.two_way_direct(hops[i]):
                rest = hops[i:]
                return ((sz - 1) << 6) | len(rest), b"".join(rest)
        return None

    def build_plan(self, m, retry=False):
        """Attempts for one post: best route, best built route (if different), best again,
        next distinct route, flood. Straight to flood if nothing scores at least 35%."""
        flood = dict(plen=None, path=None, score=0.0, proven=None, built=None)
        cands = self.candidates(m)
        if not cands or cands[0]["score"] < 0.35:
            return [flood]
        best = cands[0]
        if retry:
            return [best, flood]
        plan = [best]
        second = next((c for c in cands[1:] if c["built"] == "shortcut"), None) \
            or next((c for c in cands[1:] if c["built"] is not None), None) or (cands[1] if len(cands) > 1 else None)
        if second is not None and second["score"] >= 0.2:
            plan.append(second)
        plan.append(best)
        nxt = next((c for c in cands[1:] if c is not second and c["score"] >= 0.2), None)
        if nxt is not None:
            plan.append(nxt)
        plan.append(flood)
        return plan

    def reset_push_state(self, m):
        m.push_failures = 0
        m.plan, m.plan_retry = None, False
        m.backoff, m.retry_at, m.stuck_since = 0, 0.0, 0.0
        if m.given_up:
            m.given_up = False
            self.mark_dirty()

    def push_eligible(self, m):
        if m.pending_ack is not None or m.last_activity == 0 or m.given_up:
            return False
        if m.plan is None or m.push_failures < len(m.plan):
            return True
        return time.monotonic() >= m.retry_at                    # backoff retry due

    def delivery_sample(self, m, attempts):
        m.attempts_avg = float(attempts) if m.attempts_avg is None else m.attempts_avg * 0.75 + attempts * 0.25
        self.mark_dirty()

    @staticmethod
    def delivery_score(m):
        """100 = always delivered on the first try, 50 = usually two tries, ..."""
        return None if m.attempts_avg is None else max(1, min(100, round(100.0 / m.attempts_avg)))

    def est_hops(self, m):
        """Hops to m for ordering: their current route, else their best built route (newcomers the
        directory has located), else unknown (last)."""
        if m.out_path_len is not None:
            return m.out_path_len & 63
        if m.pending_ack is None and self.unsynced_count(m):
            c = self.candidates(m)
            if c and c[0]["score"] >= 0.35:
                return c[0]["plen"] & 63
        return 0xFF

    def flood_gap_done(self, now):
        """After a flooded push, stop waiting once the rebroadcast wave around us has passed: at least 2 s, and the
        channel quiet for push_quiet_ms (rebroadcasts we hear keep resetting that). push_gap_flood_ms stays the cap."""
        q = self.cfg.push_quiet_ms / 1000.0
        return (self.last_push_flood and q > 0 and now - self.last_push_at >= 2.0 and now - self.last_rx_mono >= q
                and now - self.last_push_at >= q)

    def gap_after_push(self, m):
        """Wait before the next push, so we aren't transmitting while this push's ACK comes back. Routes with
        measured ACK times use them (x1.25 + 0.5 s); others use the per-hop formula, which is also the ceiling."""
        formula = self.gap_for(m.push_hops)
        entry = m.inflight
        r = entry.get("proven") if entry else None
        if r is None or entry.get("plen") is None or r.lat_n < 3:
            return formula
        measured = r.lat * 1.25 / 1000.0 + 0.5
        return max(self.cfg.push_gap_base_ms / 1000.0, min(measured, formula))

    def gap_for(self, hops):
        if hops == 0xFF:
            return self.cfg.push_gap_flood_ms / 1000.0
        return (self.cfg.push_gap_base_ms + self.cfg.push_gap_hop_ms * hops) / 1000.0

    # ------------------------------------------------------------------ outcomes

    def attempt_result(self, m, entry, ok, latency_ms=None):
        if not entry:
            return
        now = now_s()
        plen, path = entry["plen"], entry["path"]
        if plen is None:                                         # flood
            if not ok:
                self.stats["flood_fallbacks"] += 1
            return                                               # success: the path return teaches the route
        r = entry["proven"] if entry["proven"] in m.routes else self.find_route(m, plen, path)
        if r is None and ok:
            r = self.learn_route(m, plen, path, proven=False)    # a built route delivered: now proven
            if entry.get("built") == "shortcut":
                log.info("shortcut proven for %s: %s", self.member_label(m), " > ".join(self.path_names(plen, path) or ["direct"]))
        if r is not None:
            r.record(ok, now, self.rhalf())
            if ok and latency_ms is not None:
                r.add_latency(latency_ms)
        self.rpt_feedback(plen, path, ok)
        if ok and (plen & 63) > 0:
            sz = (plen >> 6) + 1
            self.observe_member_at(m, path[path_bytes(plen) - sz:path_bytes(plen)], 0.5)
        self.prune_routes(m)

    def check_ack_timeouts(self):
        now = time.monotonic()
        for m in self.members.values():
            if m.pending_ack is None or now < m.ack_timeout:
                continue
            entry = m.inflight
            m.push_failures += 1
            m.prev_acks = [m.pending_ack, m.prev_acks[0]]   # late ACKs still count
            m.prev_entries = [entry, m.prev_entries[0]]
            m.pending_ack = None
            m.inflight = None
            self.stats["timeouts"] += 1
            self.attempt_result(m, entry, False)
            if m.plan is not None and m.push_failures >= len(m.plan):
                if m.attempts_cur:                          # undelivered after all of them: a bad sample
                    self.delivery_sample(m, m.attempts_cur + 1)
                    m.attempts_cur = 0
                # every attempt in the plan failed: retries at 1, 5, 15, 30 min, then every 6 h
                # (each retry = best route, then flood); give up after 72 h until they make contact
                if m.stuck_since == 0:
                    m.stuck_since, m.backoff = now, 0
                elif m.backoff < len(BACKOFF_SECS) - 1:
                    m.backoff += 1
                if now - m.stuck_since >= STUCK_GIVEUP_H * 3600 and not m.given_up:
                    m.given_up = True
                    self.raise_alert("member", m.key6, "Gave up on %s after %d h of failed deliveries; waiting for them to make contact"
                                     % (self.member_label(m), STUCK_GIVEUP_H))
                    log.info("giving up on %s until they make contact", m.key6)
                m.retry_at = now + BACKOFF_SECS[m.backoff]
            self.mark_dirty()

    # ------------------------------------------------------------------ push loop

    def push_tick(self):
        now = time.monotonic()
        if not self.members:
            return
        if now < self.next_push and not self.flood_gap_done(now):
            return
        self.check_ack_timeouts()
        if not self.round:
            self.maybe_trace()                              # end of a full round through the members
            # new round: members who take the fewest attempts first (new members neutral at 1.5),
            # then fewest hops; everyone still gets one push per round
            self.round = sorted(self.members.keys(), key=lambda k: (
                self.members[k].attempts_avg if self.members[k].attempts_avg is not None else 1.5,
                self.est_hops(self.members[k])))
        m = self.members.get(self.round.pop(0))
        did_push = False
        if m and self.push_eligible(m):
            t = now_s()
            for ts, author, text, to in self.posts:
                if t >= ts + POST_SYNC_DELAY_SECS and ts > m.sync_since and (to is None or to == m.pub) \
                        and author[:4] != m.pub[:4]:
                    self.push_post(m, ts, author, text)
                    did_push = True
                    break
        self.next_push = now + (self.gap_after_push(m) if did_push else SYNC_SKIP_INTERVAL)
        if did_push:
            self.last_pushed = m.pub
            self.last_push_at = now
            self.last_push_flood = m.push_hops == 0xFF

    def push_post(self, m, ts, author, text):
        if ts != m.push_post_ts:
            m.prev_acks = [None, None]                      # different post: earlier attempts' ACKs no longer apply
            if not m.plan_retry or m.plan is None:
                m.plan, m.push_failures = None, 0
        if m.plan is None:
            m.plan, m.plan_retry, m.push_failures = self.build_plan(m), False, 0
        elif m.push_failures >= len(m.plan):                # backoff retry: best route, then flood
            m.plan, m.plan_retry, m.push_failures = self.build_plan(m, retry=True), True, 0
        entry = m.plan[m.push_failures]
        m.attempts_cur += 1
        data = struct.pack("<I", ts) + bytes([(TXT_TYPE_SIGNED_PLAIN << 2) | random.randrange(4)]) \
            + author[:4] + text.encode()
        m.pending_ack = sha256(data, m.pub)[:4]
        m.push_post_ts = ts
        m.push_sent = time.monotonic()
        m.inflight = entry
        plen, path = entry["plen"], entry["path"]
        m.push_hops = path_hops(plen)
        pkt = self.make_datagram(PT_TXT_MSG, m.pub, self.secret_for(m), data)
        airtime = self.airtime_ms(pkt.raw_length() + (path_bytes(plen) if plen is not None else 0))
        if plen is None:
            self.send_flood(pkt, deferrable=True)
            m.ack_timeout = time.monotonic() + max(12.0, FLOOD_ACK_MIN, (500 + 32 * airtime) / 1000.0)
        else:
            self.send_direct(pkt, path, plen, deferrable=True)
            hops = plen & 63
            formula = max(4.0 + 2.0 * (hops + 1), (500 + (airtime * 6 + 250) * (hops + 1)) / 1000.0)
            r = entry["proven"]
            if r is not None and r.lat_n >= 3:              # learned from this route's own ACK times
                formula = min(max(3.0, r.lat * 2.5 / 1000.0 + 1.5), formula * 1.5)
            m.ack_timeout = time.monotonic() + formula
        self.stats["pushes"] += 1
        log.debug("push %s -> %s attempt %d/%d via %s", ts, m.key6, m.push_failures + 1, len(m.plan),
                  "flood" if plen is None else "%d hops" % (plen & 63))

    # ------------------------------------------------------------------ adverts

    def on_advert(self, pkt):
        p = pkt.payload
        if len(p) < PUB_KEY_SIZE + 4 + SIGNATURE_SIZE:
            return
        pub = p[:32]
        if pub == self.id.pub_key or self.check_dup(pkt):
            return
        ts = struct.unpack_from("<I", p, 32)[0]
        sig = p[36:100]
        app = p[100:100 + MAX_ADVERT_DATA_SIZE]
        if not app or not ed25519_verify(pub, sig, pub + p[32:36] + app):
            return
        flags = app[0]
        i = 1
        if flags & ADV_LATLON_MASK:
            i += 8
        if flags & ADV_FEAT1_MASK:
            i += 2
        if flags & ADV_FEAT2_MASK:
            i += 2
        if len(app) < i:
            return
        name = app[i:].split(b"\0", 1)[0].decode(errors="replace") if flags & ADV_NAME_MASK else ""
        name = "".join(c if ord(c) >= 0x20 else " " for c in name)
        atype = flags & 0x0F
        if flags & ADV_LATLON_MASK:
            la, lo = struct.unpack_from("<ii", app, 1)
            where = "%.4f,%.4f" % (la / 1e6, lo / 1e6) if (la or lo) else "position 0,0 (unset)"
        else:
            where = "no position"
        log.info("advert: %s %r key %s, %s, %s, SNR %.1f, %s", {1: "companion", 2: "repeater", 3: "room", 4: "sensor"}.get(atype, "type%d" % atype),
                 name, hexs(pub[:4]), "zero-hop" if pkt.hop_count == 0 else "%d hops via %s" % (pkt.hop_count, hexs(pkt.path[:pkt.hash_size])),
                 where, pkt.snr, "flood" if pkt.is_flood else "direct")
        if atype == ADV_TYPE_REPEATER:
            lat = lon = None
            if flags & ADV_LATLON_MASK:
                la, lo = struct.unpack_from("<ii", app, 1)
                if la or lo:
                    lat, lon = la / 1e6, lo / 1e6
            old_r = self.repeaters.get(pub, {})
            self.repeaters[pub] = dict(name=name or old_r.get("name", ""), lat=lat if lat is not None else old_r.get("lat"),
                                       lon=lon if lon is not None else old_r.get("lon"), adv_ts=ts, last_advert=now_s())
            self._rpt_idx = None                                # names changed: rebuild the lookup index on next use
        if atype == ADV_TYPE_CHAT and pkt.is_flood:          # every companion: the directory knows where they are
            self.observe_near(pub, pkt.path[:pkt.hash_size] if pkt.hop_count else b"")
            if pub in self.members:
                self.member_flood(self.members[pub], pkt)
        if atype == ADV_TYPE_REPEATER and pkt.hop_count == 0:
            if pub not in self.neighbours and len(self.neighbours) >= MAX_NEIGHBOURS:
                del self.neighbours[min(self.neighbours, key=lambda k: self.neighbours[k]["heard"])]
            self.neighbours[pub] = dict(advert_ts=ts, heard=now_s(), snr4=int(pkt.snr * 4), name=name)
        if atype == ADV_TYPE_CHAT:
            m = self.members.get(pub)
            if m and m.push_failures > 0 and m.pending_ack is None:
                self.reset_push_state(m)                    # signed advert: they're on the air
                if m.last_activity == 0:
                    m.last_activity = now_s()
                self.mark_dirty()
            if name:
                k8 = pub[:8]
                old = self.names.get(k8)
                if old and ts <= old[0]:
                    return                                  # older advert can't overwrite
                if not old and len(self.names) >= NAME_CACHE_MAX:
                    members8 = {mm.pub[:8] for mm in self.members.values()}
                    cands = [k for k in self.names if k not in members8]
                    if not cands:
                        return
                    del self.names[min(cands, key=lambda k: self.names[k][0])]
                self.names[k8] = (ts, name)
                self.mark_dirty()

    def send_advert(self, flood):
        try:
            pkt = self.make_advert()
        except Exception as e:
            log.error("advert: %s", e)
            return
        if flood:
            self.send_flood(pkt)
        else:
            self.send_zero_hop(pkt)
        log.info("sent %s advert", "flood" if flood else "zero-hop")

    # ------------------------------------------------------------------ link events

    # ------------------------------------------------------------------ CLI (admin, from the app)

    def handle_cli(self, cmd):
        cmd = cmd.strip()
        c = self.cfg
        try:
            if cmd == "ver":
                return FIRMWARE_VERSION
            if cmd == "clock":
                return time.strftime("%H:%M - %d/%m/%Y UTC", time.gmtime())
            if cmd == "discover":
                self.send_discovery()
                return "OK - discovery sent: replies appear in the neighbours list within ~30 s"
            if cmd == "advert":
                self.send_advert(True)
                return "OK - Advert sent"
            if cmd.startswith("get "):
                k = cmd[4:].strip()
                vals = {"name": c.name, "lat": c.lat, "lon": c.lon, "allow.read.only": "on" if c.allow_read_only else "off",
                        "path.hash.mode": c.path_hash_mode, "public.key": hexs(self.id.pub_key), "role": "room_server",
                        "push.gap": "base %sms, +%sms/hop, flood %sms" % (c.push_gap_base_ms, c.push_gap_hop_ms, c.push_gap_flood_ms)}
                return "> %s" % vals[k] if k in vals else "??: " + k
            if cmd.startswith("set "):
                k, _, v = cmd[4:].partition(" ")
                v = v.strip()
                if k == "name":
                    c.set("name", v[:31])
                elif k in ("lat", "lon"):
                    c.set(k, float(v))
                elif k == "guest.password":
                    c.set("room_password", v)
                elif k == "allow.read.only":
                    c.set("allow_read_only", v == "on")
                elif k == "path.hash.mode" and v in ("0", "1", "2"):
                    c.set("path_hash_mode", int(v))
                elif k in ("push.gap.base", "push.gap.hop", "push.gap.flood"):
                    c.set("push_gap_%s_ms" % k.split(".")[-1], max(0, min(120000, int(v))))
                else:
                    return "unknown config: " + k
                return "OK"
            if cmd.startswith("password "):
                c.set("admin_password", cmd[9:].strip())
                return "password now: " + c.admin_password
            if cmd.startswith("setperm "):
                hexkey, _, perm = cmd[8:].partition(" ")
                pref = bytes.fromhex(hexkey)
                for m in self.members.values():
                    if m.pub.startswith(pref):
                        m.perms = int(perm)
                        self.mark_dirty()
                        return "OK"
                return "Err - not found"
            if cmd.startswith("route "):
                who, _, rest = cmd[6:].strip().partition(" ")
                m = self.find_member(bytes.fromhex(who))
                if m is None:
                    return "Err - no single member matches"
                self.build_rpt_index()
                reps = [(r["name"], hexs(pub[:2])) for pub, r in self.repeaters.items()] + [("", hexs(h)) for h in self.heard]
                hops = resolve_route(rest, reps)
                return "OK - route suggested" if self.suggest_route(m.pub, hops) else "Err - could not add"
            if cmd.startswith("resync "):
                m = self.find_member(bytes.fromhex(cmd[7:].strip()))
                if m is None:
                    return "Err - no single member matches"
                n = self.force_resync(m.pub)
                return "OK - resyncing %d post(s)" % n if n else "OK - nothing outstanding"
            if cmd.startswith(("kick ", "ban ", "unban ")):
                verb, _, hexkey = cmd.partition(" ")
                pref = bytes.fromhex(hexkey.strip())
                if verb == "unban":
                    hit = [k for k in self.bans if k.startswith(pref)]
                    return "OK - unbanned" if len(hit) == 1 and self.unban(hit[0]) else "Err - no single match"
                m = self.find_member(pref)
                if m is None:
                    return "Err - no single member matches"
                if verb == "kick":
                    self.kick(m.pub)
                    return "OK - kicked"
                self.ban(m.pub)
                return "OK - banned"
            if cmd in ("neighbors", "neighbours"):
                t = now_s()
                return "\n".join("%s:%d:%.1f" % (hexs(k[:4]), t - v["heard"], v["snr4"] / 4)
                                 for k, v in sorted(self.neighbours.items(), key=lambda x: -x[1]["heard"])[:8]) or "-none-"
            if cmd in ("reboot", "restart"):
                self.events_put(("quit",))
                return "OK - restarting (systemd brings the service back)"
        except Exception as e:
            return "Err - %s" % e
        return "Unknown command"

    events_put = None   # set by main

    # ------------------------------------------------------------------ periodic

    def periodic(self):
        now = time.monotonic()
        if self.cfg.advert_interval_min and now >= self.next_zero_advert:
            self.send_advert(False)
            self.next_zero_advert = now + self.cfg.advert_interval_min * 60
        if self.cfg.flood_advert_interval_h and now >= self.next_flood_advert:
            self.send_advert(True)
            self.next_flood_advert = now + self.cfg.flood_advert_interval_h * 3600
        if self.cfg.discovery_interval_min and now >= self.next_discovery:
            if not self.disc_due_since:
                self.disc_due_since = now
            quiet = now - self.last_rx_mono >= 3.0 and not self.txq and now >= self.tx_busy_until
            if quiet or now - self.disc_due_since > 300:
                self.send_discovery()
                self.next_discovery = now + float(self.cfg.discovery_interval_min) * 60
                self.disc_due_since = 0.0
        if now >= self.next_aging:
            for m in self.members.values():
                self.prune_routes(m)
            self.trim_topology()
            self.drop_private(None, older_than=now_s() - 7 * 86400)
            self.next_aging = now + 3600
        if now >= self.next_topo_flush:
            self.flush_topology()
            self.next_topo_flush = now + 300
        if now >= self.next_sys:
            self.sample_system()
            self.next_sys = now + 5
        if now >= self.next_metric:
            self.record_metric()
            self.next_metric = now + 60
        if self.web_port_active and (self.web_dirty or (now >= self.next_web and now - self.web_last_request < 20)) \
                and (self.events_q is None or self.events_q.empty()):
            self.publish_web_state()                         # only while a browser is polling, never while packets wait
            self.web_dirty = False
            self.next_web = now + 3
        if now >= self.next_radio_check:
            self.modem.request(0x0B)                        # verify radio settings survived (async)
            self.next_radio_check = now + 300
        # routine modem polling: fire the request, the reply arrives later as an event (never waits)
        if now >= self.next_batt:
            self.modem.request(0x13)                        # battery
            if self.temp_supported:
                self.modem.request(0x14)                    # MCU temperature
            self.next_batt = now + 60
        if now >= self.next_nf:
            self.modem.request(0x10)                        # noise floor
            self.next_nf = now + 2
        if self.dirty and now >= self.next_flush:
            self.flush()
            self.next_flush = now + 30

    # ------------------------------------------------------------------ persistence of the map

    def flush_topology(self):
        rr_rows = [(t, rr.plen, rr.path, rr.w, rr.ok, rr.fail, rr.t) for t, tab in self.rroutes.items() for rr in tab.values()]
        mr_rows = [(k8, rpt, e[0], e[1]) for k8, tab in self.mrpts.items() for rpt, e in tab.items()]
        ir_rows = [(k8, plen, path, e[0], e[1]) for k8, tab in self.inpaths.items() for (plen, path), e in tab.items()]
        ed_rows = [(a, b, e[0], e[1], e[2]) for (a, b), e in self.edges.items()]
        rp_rows = [(pub, r["name"], r["lat"], r["lon"], r["adv_ts"], r["last_advert"]) for pub, r in self.repeaters.items()]
        hd_rows = [(h, d["last"], d["w"], d["t"], d["last_direct"], d["snr"], d.get("disc", 0), d.get("out_snr")) for h, d in self.heard.items()]
        self.store.execmany([
            ("DELETE FROM rpt_routes", None), ("INSERT INTO rpt_routes VALUES (?,?,?,?,?,?,?)", rr_rows),
            ("DELETE FROM member_rpts", None), ("INSERT INTO member_rpts VALUES (?,?,?,?)", mr_rows),
            ("DELETE FROM member_inroutes", None), ("INSERT INTO member_inroutes VALUES (?,?,?,?,?)", ir_rows),
            ("DELETE FROM edges", None), ("INSERT INTO edges VALUES (?,?,?,?,?)", ed_rows),
            ("DELETE FROM repeaters", None), ("INSERT INTO repeaters VALUES (?,?,?,?,?,?)", rp_rows),
            ("DELETE FROM heard", None), ("INSERT INTO heard (hash, last, w, t, last_direct, snr, disc, out_snr) VALUES (?,?,?,?,?,?,?,?)", hd_rows),
        ])

    # ------------------------------------------------------------------ per-minute stats (dashboard header)

    def record_metric(self):
        """Once a minute: deltas of the counters + noise-floor range, kept in memory for the dashboard header."""
        s = self.stats
        cur = (s["recv"], s["sent"], s["airtime_ms"], self.rx_airtime_ms, s["pushes"], s["acks"] + s["late_acks"])
        prev = self.metric_prev or cur
        self.metric_prev = cur
        rx, tx, tx_ms, rx_ms, pushes, acks = [c - p for c, p in zip(cur, prev)]
        self.minutes.append(dict(nf=self.noise_floor, nf_min=self.m_nf_min or self.noise_floor, nf_max=self.m_nf_max or self.noise_floor,
                                 rx=rx, tx=tx, tx_ms=tx_ms, rx_ms=rx_ms, pushes=pushes, acks=acks))
        self.m_nf_min = self.m_nf_max = 0

    def sample_system(self):
        """Whole-Pi CPU and memory use (Linux /proc). CPU is busy share since the previous sample; memory excludes
        reclaimable cache (MemAvailable), as `free` reports it."""
        try:
            with open("/proc/stat") as f:
                v = [int(x) for x in f.readline().split()[1:9]]
            idle, total = v[3] + v[4], sum(v)
            cpu = None
            if self.cpu_prev and total > self.cpu_prev[1]:
                cpu = 100.0 * (1.0 - (idle - self.cpu_prev[0]) / float(total - self.cpu_prev[1]))
            self.cpu_prev = (idle, total)
            mem = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    k, _, rest = line.partition(":")
                    if k in ("MemTotal", "MemAvailable"):
                        mem[k] = int(rest.split()[0])
            mem_pct = 100.0 * (1.0 - mem["MemAvailable"] / float(mem["MemTotal"]))
            self.mem_total_mb = mem["MemTotal"] // 1024
            if cpu is not None:
                self.sys_samples.append((max(0.0, min(100.0, cpu)), mem_pct))
        except (OSError, ValueError, KeyError, IndexError):
            pass                                            # not Linux: no system stats

    def sys_stats(self):
        if not self.sys_samples:
            return None
        cpu_now, mem_now = self.sys_samples[-1]
        n = len(self.sys_samples)
        return dict(cpu=round(cpu_now), cpu_avg=round(sum(x[0] for x in self.sys_samples) / n),
                    mem=round(mem_now), mem_avg=round(sum(x[1] for x in self.sys_samples) / n),
                    mem_total_mb=self.mem_total_mb, window_min=round(n * 5 / 60.0, 1))

    def hour_stats(self):
        """Averages over the minutes recorded so far (up to the last hour)."""
        ms = list(self.minutes)
        if not ms:
            return None
        n = len(ms)
        nfs = [x["nf"] for x in ms if x["nf"]]
        pushes, acks = sum(x["pushes"] for x in ms), sum(x["acks"] for x in ms)
        return dict(minutes=n,
                    nf_avg=round(sum(nfs) / len(nfs)) if nfs else None,
                    nf_min=min((x["nf_min"] for x in ms if x["nf_min"]), default=None),
                    nf_max=max((x["nf_max"] for x in ms if x["nf_max"]), default=None),
                    tx_pct=round(100.0 * sum(x["tx_ms"] for x in ms) / (n * 60000.0), 1),
                    rx_pct=round(100.0 * sum(x["rx_ms"] for x in ms) / (n * 60000.0), 1),
                    rx_pm=round(sum(x["rx"] for x in ms) / n, 1), tx_pm=round(sum(x["tx"] for x in ms) / n, 1),
                    pushes_pm=round(pushes / n, 1), push_ok=round(100.0 * min(acks, pushes) / pushes) if pushes else None)

    # ------------------------------------------------------------------ labels

    def member_label(self, m):
        nm = self.names.get(m.pub[:8])
        return "%s (%s)" % (nm[1], m.key6) if nm else m.key6

    def build_rpt_index(self):
        """Repeater id prefix (1-3 bytes) -> (pubkey, info) of the most recently adverted match.
        Built once per dashboard refresh so name lookups are instant instead of scanning every repeater."""
        idx = {}
        for pub, r in self.repeaters.items():
            for n in (1, 2, 3):
                cur = idx.get(pub[:n])
                if cur is None or (r["last_advert"] or 0) > (cur[1]["last_advert"] or 0):
                    idx[pub[:n]] = (pub, r)
        self._rpt_idx = idx
        self._label_memo = {}
        return idx

    def rpt_lookup(self, h):
        idx = getattr(self, "_rpt_idx", None)
        if idx is None:
            idx = self.build_rpt_index()
        return idx.get(h[:3]) if h else None

    def rpt_label(self, h):
        if not h:
            return "room"
        memo = getattr(self, "_label_memo", None)
        if memo is not None and h in memo:
            return memo[h]
        hit = self.rpt_lookup(h)
        label = "%s (%s)" % (hit[1]["name"], hexs(h)) if hit and hit[1]["name"] else hexs(h)
        if memo is not None:
            memo[h] = label
        return label

    def raise_alert(self, kind, key, msg):
        log.warning("%s", msg)

    # ------------------------------------------------------------------ dashboard state (read by the web thread)

    def publish_web_state(self):
        """Build a fresh, self-contained dict; the web thread only ever reads the latest one."""
        t = now_s()
        self.build_rpt_index()
        rh = self.rhalf()
        members = []
        for m in self.members.values():
            nm = self.names.get(m.pub[:8])
            in_backoff = m.plan is not None and m.push_failures >= len(m.plan) and time.monotonic() < m.retry_at
            members.append(dict(
                pub=hexs(m.pub), key=m.key6, name=nm[1] if nm else "",
                delivery=self.delivery_score(m), avg_attempts=None if m.attempts_avg is None else round(m.attempts_avg, 2),
                deliveries=m.deliveries, role={PERM_ADMIN: "admin", PERM_GUEST: "guest"}.get(m.role, "member"),
                last_activity=m.last_activity, sync_since=m.sync_since, outstanding=self.unsynced_count(m),
                push="gave_up" if m.given_up else "waiting" if m.pending_ack else "backoff" if in_backoff
                     else "retrying" if m.push_failures else "idle",
                retry_in=int(m.retry_at - time.monotonic()) if in_backoff else 0,
                route=self.path_names(m.out_path_len, m.out_path),
                in_route=self.path_names(m.in_path_len, m.in_path) if m.in_ts else None, in_age=m.in_ts,
                in_routes=self.member_inroutes(m),
                routes=[dict(path=self.path_names(r.len, r.path), rate=round(r.rate(t, rh) * 100),
                             evidence=round(r.evidence(t, rh)[1], 1), lat_ms=int(r.lat), current=self.is_current(m, r))
                        for r in sorted(m.routes, key=lambda r: -r.rate(t, rh))],
                near=[dict(rpt=self.rpt_label(k) if k else "direct", share=round(sh * 100)) for k, sh in self.member_locations(m)]))
        th = self.thalf()
        heard_by_x, x_heard_by = {}, {}                     # index the links once: O(links)
        for (a, b), e in self.edges.items():
            w = fade(e[0], e[1], t, th)
            if w < 0.2:
                continue
            item = (w, e[2])
            heard_by_x.setdefault(b, []).append((a,) + item)
            x_heard_by.setdefault(a, []).append((b,) + item)

        def nlist(items):
            items = sorted(items, key=lambda x: -x[1])[:8]
            return [dict(name=self.rpt_label(n) if n else "room", seen=round(w, 1), snr=None if snr is None else round(snr, 1))
                    for n, w, snr in items]
        rpts = []
        for h, d in self.heard.items():
            best, conf = self.best_rpt_route(h)
            hit = self.rpt_lookup(h)
            info_pub, info = hit if hit else (None, None)
            rpts.append(dict(hash=hexs(h), name=(info or {}).get("name") or "", lat=(info or {}).get("lat"), lon=(info or {}).get("lon"),
                             key=hexs(info_pub) if info_pub else None, last_advert=(info or {}).get("last_advert"),
                             last=d["last"], last_direct=d["last_direct"], activity=round(fade(d["w"], d["t"], t, 6 * 3600.0), 1),
                             disc=d.get("disc") or 0, out_snr=None if d.get("out_snr") is None else round(d["out_snr"], 1),
                             snr=None if d["snr"] is None else round(d["snr"], 1),
                             routes=[dict(path=self.path_names(rr.plen, rr.path), conf=round(c * 100)) for rr, c in self.top_rpt_routes(h)],
                             heard=nlist(heard_by_x.get(h, [])), heard_by=nlist(x_heard_by.get(h, []))))
        rpts.sort(key=lambda r: -r["activity"])
        edges = [dict(a=hexs(a), b=hexs(b) if b else "", w=round(fade(e[0], e[1], t, th), 1),
                      snr=None if e[2] is None else round(e[2], 1)) for (a, b), e in self.edges.items() if fade(e[0], e[1], t, th) >= 0.5]
        s = self.stats
        self.web_state = dict(
            room=dict(name=self.cfg.name, key=hexs(self.id.pub_key), lat=self.cfg.lat, lon=self.cfg.lon, fw=FIRMWARE_VERSION,
                      radio=list(self.radio) if self.radio else None, uptime=int(time.monotonic() - self.boot), time=t,
                      clock_ok=t > 1735689600, noise_floor=self.noise_floor, batt_mv=self.batt_mv),
            stats=dict(s, posts_held=sum(1 for p in self.posts if p[3] is None), names_known=len(self.names),
                       tx_queue=len(self.txq)),
            members=sorted(members, key=lambda x: (x["delivery"] is None, -(x["delivery"] or 0), -x["last_activity"])),
            repeaters=rpts[:200], edges=edges,
            bans=[dict(pub=hexs(k), key=hexs(k[:6]), name=v["name"], ts=v["ts"]) for k, v in sorted(self.bans.items(), key=lambda x: -x[1]["ts"])],
            top_links=self.top_links(), discovery_min=self.cfg.discovery_interval_min, hour=self.hour_stats(),
            sys=self.sys_stats())

    def member_inroutes(self, m, n=5):
        """Other paths the member's floods took to reach us (member side first), most seen first, excluding the current."""
        tab = self.inpaths.get(m.pub[:8]) or {}
        t = now_s()
        cur = (m.in_path_len, m.in_path) if m.in_ts else None
        ws = {k: fade(e[0], e[1], t, self.rhalf()) for k, e in tab.items() if k != cur}
        tot = sum(fade(e[0], e[1], t, self.rhalf()) for e in tab.values()) or 1.0
        top = sorted(ws.items(), key=lambda kv: -kv[1])[:n]
        return [dict(path=self.path_names(plen, path), share=round(100 * w / tot)) for (plen, path), w in top if w > 0.05]

    def top_links(self, n=10):
        """Neighbours ranked by trace packet loss (lowest first, more traces first), untraced ones after."""
        rows = []
        f24 = lambda st: 0.5 ** (max(0, now_s() - st["tr_t"]) / (24 * 3600.0))
        for h, st in self.probes.items():
            if not st.get("last_ok"):
                continue
            loss = self.trace_loss(st)
            avgs = [x for x in (st["in_avg"], st["out_avg"]) if x is not None]
            weakest = min(avgs) if avgs else -99
            traces = st["tr_n"] * f24(st)
            f = f24(st)
            lost = (st["tr_n"] - st["tr_s"]) * f
            est = (lost + 1.0) / (traces + 2.0)                  # thin evidence ranks conservatively: 1 lucky trace ~ 33%
            rows.append(((0, est, -traces, -weakest) if loss is not None else (1, 0, 0, -weakest), dict(
                name=self.rpt_label(h), hash=hexs(h), loss=None if loss is None else round(loss * 100, 1), traces=round(traces, 1),
                few=round(traces, 1) < 5,
                in_last=st["in_last"], in_avg=None if st["in_avg"] is None else round(st["in_avg"], 1),
                out_last=st["out_last"], out_avg=None if st["out_avg"] is None else round(st["out_avg"], 1),
                rtt=None if st["rtt"] is None else int(st["rtt"]), last_ok=st["last_ok"])))
        rows.sort(key=lambda r: r[0])
        return [r[1] for r in rows[:n]]

    def path_names(self, plen, path):
        if plen is None:
            return None
        sz = (plen >> 6) + 1
        return [self.rpt_label(path[i * sz:(i + 1) * sz]) for i in range(plen & 63)]

    def run_once(self):
        if self.notices:
            self.service_notices()
        if self.disc_close_at and time.monotonic() >= self.disc_close_at:
            self.close_discovery_round()
        if self.trace_pending:
            self.check_trace_timeout()
        if not self.members and self.cfg.trace_neighbours:
            self.maybe_trace()                              # (no member rounds to hang it on)
        self.push_tick()
        self.service_tx()
        self.periodic()


# ============================================================================

# ============================================================================
# Dashboard (own thread; reads only the snapshot the main loop publishes)
# ============================================================================

DASHBOARD_HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>meshroom</title>
<meta name="referrer" content="strict-origin-when-cross-origin">
<link rel="stylesheet" href="static/leaflet.css">
<script src="static/leaflet.js"></script>
<style>
:root{--bg:#111418;--card:#1a1f26;--line:#2a313b;--fg:#d8dee6;--dim:#8a94a3;--acc:#5cb3ff;--ok:#4caf7a;--warn:#e0a83e;--bad:#e05a5a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.4 system-ui,sans-serif}
header{padding:12px 18px;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:18px;align-items:baseline}
header h1{font-size:18px;margin:0}.dim{color:var(--dim)}main{padding:14px 18px;display:grid;gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;overflow-x:auto}
.card h2{font-size:14px;margin:0 0 8px;color:var(--acc);text-transform:uppercase;letter-spacing:.04em}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:4px 8px;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:top}
th{color:var(--dim);font-weight:500}.tag{padding:1px 6px;border-radius:4px;font-size:12px}
.idle{background:#24382c;color:var(--ok)}.waiting,.retrying{background:#3a3220;color:var(--warn)}.backoff,.gave_up{background:#3d2424;color:var(--bad)}
button{background:#2a313b;color:var(--fg);border:1px solid var(--line);border-radius:4px;padding:2px 10px;cursor:pointer}
.mapwrap{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px}
@media (max-width:900px){.mapwrap{grid-template-columns:1fr}}
#map{height:520px;border-radius:6px}
.rdetail{background:#151a20;border:1px solid var(--line);border-radius:6px;padding:12px 14px;max-height:540px;overflow:auto}
.rdetail .pick{display:flex;align-items:center;justify-content:center;height:100%;min-height:200px}
.rdetail h3{margin:0 0 2px;font-size:16px}.rdetail .sec{margin:12px 0 4px;color:var(--acc);text-transform:uppercase;font-size:11px;letter-spacing:.05em}
.rdetail table td,.rdetail table th{padding:3px 6px;font-size:12px}.kv td:first-child{color:var(--dim);width:110px}.mono{font-family:ui-monospace,monospace;word-break:break-all;white-space:normal}.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}
.volt{font-weight:600}.volt .dim{font-weight:400}
.hstats{flex-basis:100%;display:flex;flex-wrap:wrap;gap:6px 22px;font-size:13px}.hstats b{font-weight:600}.hstats .dim{margin-right:4px}
.modal{position:fixed;inset:0;background:#000a;display:none;align-items:center;justify-content:center;z-index:3000}
.mbox{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px 18px;width:300px}.mbox h3{margin:0 0 10px;font-size:15px}
.mbox input{width:100%;padding:6px 8px;background:#0d1014;border:1px solid var(--line);border-radius:4px;color:var(--fg)}
.act{background:transparent;border:2px solid var(--acc);border-radius:6px;padding:2px;margin-right:6px;line-height:0;cursor:pointer;
 box-sizing:border-box;width:72px;height:72px;min-width:72px;min-height:72px;flex:none;display:inline-flex;align-items:center;justify-content:center;vertical-align:middle}
.act:hover{border-color:var(--bad)}.act:disabled{opacity:.5}
.act img{width:64px;height:64px;min-width:64px;max-width:64px;min-height:64px;max-height:64px;display:block;object-fit:contain}
td.acts{white-space:nowrap;width:320px;min-width:320px}td.idcell{line-height:1.35}
.dir{display:inline-block;font-size:10px;font-weight:700;padding:0 4px;border-radius:3px;margin-right:5px;vertical-align:1px}
.dir.tx{background:#1f3a52;color:#7cc4ff}.dir.rx{background:#3a2e1a;color:#f0b85a}
td.rcell{white-space:normal;min-width:220px;max-width:380px}td.rcell div{display:flex;gap:2px;align-items:baseline;margin:2px 0}
td.rcell .dir{flex:none}.mono4{font-family:ui-monospace,monospace}
.chatlog{height:320px;overflow-y:auto;background:#151a20;border:1px solid var(--line);border-radius:6px;padding:8px 10px;font-size:13px}
.chatlog .msg{padding:3px 0;border-bottom:1px solid #1f262e}.chatlog .when{color:var(--dim);font-size:11px;margin-right:6px}
.chatlog .who{font-weight:600;margin-right:6px}.chatlog .who.room{color:var(--acc)}
.chatin{display:flex;gap:8px;align-items:center;margin-top:8px}.chatin input{flex:1;padding:7px 9px;background:#0d1014;border:1px solid var(--line);border-radius:4px;color:var(--fg)}
.advrow{display:flex;gap:26px;align-items:center;flex-wrap:wrap}.adv{display:flex;gap:10px;align-items:center}
.mbox.wide{width:520px}.ac{position:relative}.aclist{background:#0d1014;border:1px solid var(--line);border-top:none;
 border-radius:0 0 4px 4px;max-height:200px;overflow:auto;display:none}.aclist div{padding:5px 8px;cursor:pointer;font-size:13px}
.aclist div.on,.aclist div:hover{background:#243447}.hint{color:var(--dim);font-size:12px;margin:6px 0}#sgprev{font-size:12px;margin-top:6px;min-height:16px}#members td{vertical-align:middle}
#tip{position:fixed;z-index:2000;display:none;max-width:460px;background:#0d1014;border:1px solid var(--line);border-radius:6px;padding:8px 10px;font-size:12px;pointer-events:none;box-shadow:0 4px 18px #0008}
#tip h4{margin:0 0 4px;font-size:13px;color:var(--acc)}#tip .sec{margin-top:6px;color:var(--dim);text-transform:uppercase;font-size:10px;letter-spacing:.05em}
#rpts tr[data-i]{cursor:pointer}#rpts tr[data-i]:hover td{background:#222a33}#rpts tr.sel td{background:#243447}.good{color:var(--ok)}.mid{color:var(--warn)}.poor{color:var(--bad)}.small{font-size:12px}.kpis{display:flex;flex-wrap:wrap;gap:22px}.kpi b{font-size:18px;display:block}
</style></head><body>
<header><h1 id="rname">meshroom</h1><span class="dim" id="rinfo"></span><span class="dim" id="rclock"></span><span id="rsys" class="volt"></span><span id="rvolt" class="volt"></span>
<span style="margin-left:auto"><span id="who" class="dim small"></span> <button id="loginbtn" onclick="loginClick()">Log in</button></span>
<div id="hstats" class="hstats"></div></header>
<div id="suggestbox" class="modal"><div class="mbox wide"><h3 id="sgtitle">Suggest a route</h3>
<div class="hint">Repeaters in order from the room outward: the first is one the room hears directly, the last is nearest the member.
Separate with commas. Type a name or id for suggestions.</div>
<div class="ac"><input id="sgpath" placeholder="e.g. Seaside (E3C5), Williams Hill (4322)" autocomplete="off"><div id="aclist" class="aclist"></div></div>
<div id="sgprev" class="dim"></div><div id="sgerr" class="poor small"></div>
<div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end"><button onclick="closeSuggest()">Cancel</button><button onclick="doSuggest()">Add route</button></div></div></div>
<div id="loginbox" class="modal"><div class="mbox"><h3>Admin log in</h3><input id="pw" type="password" placeholder="Password" onkeydown="if(event.key==='Enter')doLogin()">
<div id="loginerr" class="poor small"></div><div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end"><button onclick="closeLogin()">Cancel</button><button onclick="doLogin()">Log in</button></div></div></div>
<main>
<div class="card"><div class="kpis" id="kpis"></div></div>
<div class="card" id="advcard" style="display:none"><h2>Room adverts</h2><div class="advrow">
<div class="adv"><button class="act" title="Advert: zero-hop, heard by direct neighbours" onclick="sendAdvert(false,this)"><img src="icons/advert.png" alt="advert"></button><div>Advert<br><span class="dim small">zero-hop</span></div></div>
<div class="adv"><button class="act" title="Flood advert: spreads across the whole mesh" onclick="sendAdvert(true,this)"><img src="icons/flood_advert.png" alt="flood advert"></button><div>Flood advert<br><span class="dim small">whole mesh</span></div></div>
<span id="advmsg" class="dim small"></span></div></div>
<div class="card" id="chatcard" style="display:none"><h2>Room chat</h2>
<div id="chatlog" class="chatlog"><div class="dim">loading...</div></div>
<div class="chatin"><input id="chatmsg" maxlength="400" placeholder="Message everyone in the room (sent as the room)" autocomplete="off">
<span id="chatleft" class="dim small"></span><button id="chatsend" onclick="sendChat()">Send</button></div>
<div id="chaterr" class="poor small"></div></div>
<div class="card"><h2>Best neighbour repeaters <span class="dim small">(by trace packet loss)</span></h2><table id="toplinks"></table></div>
<div class="card"><h2>Members</h2><table id="members"></table></div>
<div class="card"><h2>Banned</h2><table id="bans"></table></div>
<div class="card"><h2>Repeater map</h2>
<div class="mapwrap"><div><div id="map"></div><div id="mapnote" class="dim small"></div></div>
<div id="rdetail" class="rdetail"><div class="dim pick">Select a repeater from the map</div></div></div></div>
<div class="card"><h2>Repeaters heard</h2><table id="rpts"></table></div>
</main>
<script>
const $=id=>document.getElementById(id), esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function ago(t){if(!t)return"never";let d=Math.max(0,Date.now()/1000-t);return d<60?Math.round(d)+"s":d<3600?Math.round(d/60)+"m":d<86400?(d/3600).toFixed(1)+"h":(d/86400).toFixed(1)+"d"}
async function act(url,label){if(!confirm(label))return;const r=await fetch(url,{method:"POST"});if(r.status===401){await session();alert("Your admin session has expired: log in again.")}setTimeout(load,300)}
async function resync(m,btn){btn.disabled=true;await fetch("api/members/"+m.pub+"/resync",{method:"POST"});
 btn.title=m.outstanding?"Resync started":"Nothing outstanding for this member";setTimeout(load,300)}
function score(m){if(m.delivery==null)return'<span class="dim">new</span>';const c=m.delivery>=80?"good":m.delivery>=50?"mid":"poor";
 return `<span class="${c}">${m.delivery}%</span> <span class="dim small">${m.avg_attempts} tries &middot; ${m.deliveries}</span>`}
function route(r){return r==null?'<span class="dim">unknown (flood)</span>':r.length?r.map(esc).join(" &rsaquo; "):'direct'}
let map=null,layer=null,RPTS=[],MEMBERS=[],LAST=null,ADMIN=false,LOGIN_ON=false;
let CHAT_TS=0,CHAT_MAX=151,CHAT_BUSY=false;
function bytesOf(t){return new TextEncoder().encode(t).length}
function chatLeft(){const n=CHAT_MAX-bytesOf($("chatmsg").value);$("chatleft").textContent=n+" left";$("chatleft").className=n<0?"poor small":"dim small";$("chatsend").disabled=n<0}
async function loadChat(reset){if(!ADMIN||CHAT_BUSY)return;CHAT_BUSY=true;
 try{if(reset){CHAT_TS=0;$("chatlog").innerHTML=""}
  const r=await fetch("api/chat?since="+CHAT_TS);if(!r.ok){CHAT_BUSY=false;return}const d=await r.json();CHAT_MAX=d.max_bytes||151;
  const L=$("chatlog"),atBottom=L.scrollHeight-L.scrollTop-L.clientHeight<40;
  if(reset&&!d.messages.length)L.innerHTML='<div class="dim empty">no messages yet</div>';
  if(d.messages.length){const e=L.querySelector(".empty");if(e)e.remove()}
  d.messages.forEach(m=>{const div=document.createElement("div");div.className="msg";
   div.innerHTML=`<span class="when">${new Date(m.ts*1000).toLocaleString()}</span><span class="who ${m.room?"room":""}">${esc(m.who)}</span>${esc(m.text)}`;
   L.appendChild(div);CHAT_TS=Math.max(CHAT_TS,m.ts)});
  if(d.messages.length&&(atBottom||reset))L.scrollTop=L.scrollHeight}catch(e){}CHAT_BUSY=false}
async function sendAdvert(flood,btn){
 if(flood&&!confirm("Send a flood advert? It is relayed across the whole mesh."))return;
 btn.disabled=true;const r=await fetch("api/advert",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({flood})});
 let m=r.ok?(flood?"Flood advert sent":"Advert sent (zero-hop)"):"Could not send";try{if(!r.ok)m=(await r.json()).error||m}catch(e){}
 if(r.status===401){m="Your admin session has expired: log in again.";session()}
 $("advmsg").textContent=m+" · "+new Date().toLocaleTimeString();setTimeout(()=>btn.disabled=false,10000)}
async function sendChat(){const t=$("chatmsg").value.trim();if(!t)return;$("chaterr").textContent="";
 const r=await fetch("api/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text:t})});
 if(r.ok){$("chatmsg").value="";chatLeft();setTimeout(()=>loadChat(false),700)}
 else{let e="Could not send";try{e=(await r.json()).error||e}catch(x){}if(r.status===401){e="Your admin session has expired: log in again.";session()}$("chaterr").textContent=e}}
async function session(){try{const r=await (await fetch("api/session")).json();ADMIN=r.admin;LOGIN_ON=r.login_enabled}catch(e){}
 const was=$("chatcard").style.display!=="none";$("chatcard").style.display=ADMIN?"":"none";$("advcard").style.display=ADMIN?"":"none";if(ADMIN&&!was)loadChat(true);
 $("loginbtn").textContent=ADMIN?"Log out":"Log in";$("loginbtn").style.display=LOGIN_ON||ADMIN?"":"none";$("who").textContent=ADMIN?"admin":""}
function loginClick(){if(ADMIN){fetch("api/logout",{method:"POST"}).then(()=>session().then(load));return}
 $("loginerr").textContent="";$("pw").value="";$("loginbox").style.display="flex";setTimeout(()=>$("pw").focus(),50)}
function closeLogin(){$("loginbox").style.display="none"}
let SGM=null,ACI=-1;
function openSuggest(m){SGM=m;$("sgtitle").textContent="Suggest a route to "+(m.name||m.key);$("sgpath").value="";$("sgerr").textContent="";
 $("sgprev").textContent=m.route?"Current route: "+(m.route.length?m.route.join(" › "):"direct"):"Current route: none (floods)";
 $("suggestbox").style.display="flex";acHide();setTimeout(()=>$("sgpath").focus(),50)}
function closeSuggest(){$("suggestbox").style.display="none";acHide()}
function acHide(){$("aclist").style.display="none";ACI=-1}
function acItems(){const v=$("sgpath").value,tok=v.slice(v.lastIndexOf(",")+1).trim().toLowerCase();
 return RPTS.filter(r=>!tok||(r.name||"").toLowerCase().includes(tok)||r.hash.toLowerCase().startsWith(tok)).slice(0,12)}
function acShow(){const it=acItems(),L=$("aclist");if(!it.length){acHide();return}
 L.innerHTML=it.map((r,i)=>`<div data-i="${i}" class="${i===ACI?"on":""}">${esc(r.name||"unknown")} <span class="dim">${r.hash}</span></div>`).join("");
 L.style.display="block";L.querySelectorAll("div").forEach(d=>d.onmousedown=e=>{e.preventDefault();acPick(it[+d.dataset.i])})}
function acPick(r){const v=$("sgpath").value,head=v.slice(0,v.lastIndexOf(",")+1);
 $("sgpath").value=(head?head+" ":"")+(r.name?r.name+" ("+r.hash+")":r.hash)+", ";acHide();$("sgpath").focus()}
async function doSuggest(){const path=$("sgpath").value.replace(/[,\s]+$/,"");
 const r=await fetch("api/members/"+SGM.pub+"/route",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path})});
 if(r.ok){closeSuggest();setTimeout(load,400)}else{let e="Could not add the route";try{e=(await r.json()).error||e}catch(x){}
  if(r.status===401){e="Your admin session has expired: log in again.";session()}$("sgerr").textContent=e}}
async function doLogin(){const r=await fetch("api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:$("pw").value})});
 if(r.ok){closeLogin();await session();load()}else{$("loginerr").textContent=r.status===401?"Wrong password":"Login is not enabled on this room"}}
let SEL=null;
function hops(r){return r.routes.length?r.routes[0].path.length:null}
function hopsTxt(n){return n==null?"no route yet":n===1?"1 hop":n+" hops"}
function detail(r){
 const sn=x=>x==null?'<span class="dim">-</span>':(x>0?"+":"")+x+" dB";
 const nb=l=>l.length?"<table><tr><th>Repeater</th><th>Avg SNR</th><th>Seen</th></tr>"+l.map(x=>`<tr><td>${esc(x.name)}</td><td>${sn(x.snr)}</td><td>${x.seen}</td></tr>`).join("")+"</table>":'<span class="dim">none yet</span>';
 return `<h3>${esc(r.name||"Unknown repeater")}</h3><div class="dim small">${hopsTxt(hops(r))} from the room</div>`+
  `<div class="sec">Identity</div><table class="kv"><tr><td>ID</td><td class="mono">${r.hash}</td></tr>`+
  `<tr><td>Public key</td><td class="mono">${r.key?r.key:'<span class="dim">unknown (no advert heard)</span>'}</td></tr>`+
  `<tr><td>Position</td><td>${r.lat!=null?r.lat.toFixed(5)+", "+r.lon.toFixed(5):'<span class="dim">none sent</span>'}</td></tr>`+
  `<tr><td>Last advert</td><td>${r.last_advert?ago(r.last_advert)+" ago":'<span class="dim">never</span>'}</td></tr></table>`+
  `<div class="sec">Activity</div><table class="kv"><tr><td>Last seen</td><td>${ago(r.last)} ago</td></tr>`+
  `<tr><td>Heard directly</td><td>${r.last_direct?ago(r.last_direct)+" ago":'<span class="dim">never</span>'}</td></tr>`+
  `<tr><td>SNR at the room</td><td>${sn(r.snr)}</td></tr>`+
  `<tr><td>Hears the room at</td><td>${r.out_snr!=null?sn(r.out_snr):'<span class="dim">unknown (no discovery reply)</span>'}</td></tr>`+
  `<tr><td>Last discovery reply</td><td>${r.disc?ago(r.disc)+" ago":'<span class="dim">never</span>'}</td></tr>`+
  `<tr><td>Activity</td><td>${r.activity}</td></tr></table>`+
  `<div class="sec">Best routes from the room</div>${r.routes.length?"<table><tr><th>Route</th><th>Hops</th><th>Conf.</th></tr>"+r.routes.map(x=>`<tr><td>${route(x.path)}</td><td>${x.path.length}</td><td>${x.conf}%</td></tr>`).join("")+"</table>":'<span class="dim">none yet</span>'}`+
  `<div class="sec">Neighbours it has heard</div>${nb(r.heard)}`+
  `<div class="sec">Heard by</div>${nb(r.heard_by)}`}
function select(hash){SEL=hash;const r=RPTS.find(x=>x.hash===hash);
 $("rdetail").innerHTML=r?detail(r):'<div class="dim pick">Select a repeater from the map</div>';
 document.querySelectorAll("#rpts tr[data-i]").forEach(tr=>tr.classList.toggle("sel",RPTS[+tr.dataset.i]&&RPTS[+tr.dataset.i].hash===SEL));
 if(map&&layer)drawMap(LAST)}
async function load(){
 let st; try{st=await (await fetch("api/state")).json()}catch(e){return}
 if(!st.room)return; const R=st.room,S=st.stats;
 $("rname").textContent=R.name; document.title=R.name+" - meshroom";
 $("rinfo").textContent=(R.radio?(R.radio[0]/1e6).toFixed(3)+" MHz BW"+R.radio[1]/1e3+" SF"+R.radio[2]+" CR4/"+R.radio[3]:"")+"  key "+R.key.slice(0,12)+"  "+R.fw;
 const Sy=st.sys, lvl=v=>v>=85?"poor":v>=60?"mid":"";
 $("rsys").innerHTML=Sy?`<span class="dim">CPU</span> <span class="${lvl(Sy.cpu)}">${Sy.cpu}%</span> <span class="dim small">(${Sy.window_min>=10?"10m":Sy.window_min+"m"} avg ${Sy.cpu_avg}%)</span> &nbsp; `+
  `<span class="dim">Mem</span> <span class="${lvl(Sy.mem)}">${Sy.mem}%</span> <span class="dim small">(avg ${Sy.mem_avg}% of ${Sy.mem_total_mb} MB)</span>`:"";
 $("rvolt").innerHTML=R.batt_mv?`<span class="dim">modem</span> ${(R.batt_mv/1000).toFixed(2)} V`:'<span class="dim">modem voltage n/a</span>';
 const Hs=st.hour;
 $("hstats").innerHTML=Hs?[
  `<span><span class="dim">Noise floor</span><b>${Hs.nf_avg??"-"}</b> <span class="dim small">avg &middot; ${Hs.nf_min??"-"} / ${Hs.nf_max??"-"} min / max dBm</span></span>`,
  `<span><span class="dim">Channel use</span>TX <b>${Hs.tx_pct}%</b> &middot; RX <b>${Hs.rx_pct}%</b></span>`,
  `<span><span class="dim">Packets / min</span>RX <b>${Hs.rx_pm}</b> &middot; TX <b>${Hs.tx_pm}</b></span>`,
  `<span><span class="dim">Pushes / min</span><b>${Hs.pushes_pm}</b>${Hs.push_ok!=null?` &middot; <b class="${Hs.push_ok>=80?"good":Hs.push_ok>=50?"mid":"poor"}">${Hs.push_ok}%</b> delivered`:""}</span>`,
  `<span class="dim small">last ${Hs.minutes>=60?"hour":Hs.minutes+" min"}</span>`].join(""):'<span class="dim small">stats appear after the first minute</span>';
 $("rclock").textContent="up "+ago(Date.now()/1000-R.uptime).replace("s"," s")+(R.clock_ok?"":"  CLOCK NOT SYNCED");
 const k=[["Members",st.members.length],["Posts held",S.posts_held],["Pushes",S.pushes],["Delivered",S.acks],["Late ACKs",S.late_acks],["Timeouts",S.timeouts],["Floods failed",S.flood_fallbacks],["Duplicates dropped",S.deduped],["Traces heard",S.traces],["Noise floor",R.noise_floor+" dBm"],["RX / TX",S.recv+" / "+S.sent],["TX queue",S.tx_queue],["Names known",S.names_known]];
 $("kpis").innerHTML=k.map(x=>`<div class="kpi"><span class="dim small">${x[0]}</span><b>${esc(x[1])}</b></div>`).join("");
 const IC=n=>`<img src="icons/${n}.png" alt="${n}">`;
 $("members").innerHTML="<tr>"+(ADMIN?"<th></th>":"")+"<th>ID</th><th>Delivery</th><th>Last heard</th><th>Synced to</th><th>Behind</th><th>Push</th><th>Current route</th><th>Other routes</th><th>Usually near</th></tr>"+
  st.members.map((m,i)=>`<tr>${ADMIN?`<td class="acts"><button class="act" title="Force resync: clear backoff, retry now via best routes, then flood${m.outstanding?"":" (nothing outstanding)"}" onclick="resync(MEMBERS[${i}],this)">${IC("resync")}</button><button class="act" title="Suggest a route to this member" onclick="openSuggest(MEMBERS[${i}])">${IC("suggest")}</button><button class="act" title="Kick: remove from the room (they can rejoin)" onclick="act('api/members/${m.pub}/kick','Kick ${esc(m.name||m.key)}? They are removed as if they never joined, and can log in again.')">${IC("kick")}</button><button class="act" title="Ban: the room ignores them completely" onclick="act('api/members/${m.pub}/ban','Ban ${esc(m.name||m.key)}? The room will stop responding to them entirely.')">${IC("ban")}</button></td>`:""}
  <td class="idcell"><b>${esc(m.name)||'<span class="dim">unknown</span>'}</b><br><span class="dim mono4">${m.key.slice(0,4)}</span><br><span class="small">${m.role}</span></td><td>${score(m)}</td><td>${ago(m.last_activity)}</td><td>${ago(m.sync_since)}</td><td>${m.outstanding}</td>
  <td><span class="tag ${m.push}">${m.push}${m.retry_in?" "+Math.ceil(m.retry_in/60)+"m":""}</span></td>
  <td class="small rcell"><div><span class="dir tx">TX</span><span>${route(m.route)}</span></div><div><span class="dir rx">RX</span><span>${m.in_route==null?'<span class="dim">unknown</span>':m.in_route.length?m.in_route.map(esc).join(" &rsaquo; "):"direct"}</span></div></td>
  <td class="small rcell">${[...m.routes.filter(r=>!r.current).slice(0,5).map(r=>`<div><span class="dir tx">TX</span><span>${route(r.path)} <span class="dim">${r.rate}%</span></span></div>`),
   ...(m.in_routes||[]).slice(0,5).map(r=>`<div><span class="dir rx">RX</span><span>${r.path.length?r.path.map(esc).join(" &rsaquo; "):"direct"} <span class="dim">${r.share}%</span></span></div>`)].join("")||'<span class="dim">-</span>'}</td>
  <td class="small">${m.near.map(n=>esc(n.rpt)+` <span class="dim">${n.share}%</span>`).join("<br>")||'<span class="dim">-</span>'}</td></tr>`).join("");
 const TL=st.top_links||[], sn2=(a,b)=>`${a==null?"-":(a>0?"+":"")+a}<span class="dim"> / ${b==null?"-":(b>0?"+":"")+b}</span>`;
 $("toplinks").innerHTML=TL.length?"<tr><th>Repeater</th><th>Packet loss</th><th>SNR in (last / avg)</th><th>SNR out (last / avg)</th><th>Round trip</th><th>Last reply</th></tr>"+
  TL.map(r=>{const c=r.loss==null?"dim":r.loss<=5?"good":r.loss<=20?"mid":"poor";
   return `<tr><td>${esc(r.name)}</td><td>${r.loss==null?'<span class="dim">not traced yet</span>':`<span class="${c}">${r.loss.toFixed(1)}%</span> <span class="dim small">${r.traces} trace${r.traces==1?"":"s"}${r.few?" &middot; few traces":""}</span>`}</td>`+
   `<td>${sn2(r.in_last,r.in_avg)}</td><td>${sn2(r.out_last,r.out_avg)}</td><td>${r.rtt!=null?r.rtt+" ms":"-"}</td><td>${r.last_ok?ago(r.last_ok)+" ago":"never"}</td></tr>`}).join("")
  :`<tr><td class="dim">no neighbours yet: the room discovers its direct repeaters every ${st.discovery_min||15} minutes</td></tr>`;
 MEMBERS=st.members;
 const bans=st.bans||[];
 $("bans").innerHTML=bans.length?"<tr><th>Name</th><th>Key</th><th>Banned</th><th></th></tr>"+bans.map(b=>`<tr><td>${esc(b.name)||'<span class="dim">unknown</span>'}</td><td class="dim">${b.key}</td><td>${ago(b.ts)} ago</td><td>${ADMIN?`<button onclick="act('api/bans/${b.pub}/unban','Unban ${esc(b.name||b.key)}? They will be able to log in again.')">Unban</button>`:""}</td></tr>`).join(""):'<tr><td class="dim">nobody</td></tr>';
 $("rpts").innerHTML="<tr><th>Repeater</th><th>Activity</th><th>Last seen</th><th>Heard directly</th><th>SNR (direct)</th><th>Position</th><th>Best routes from room</th></tr>"+
  st.repeaters.map((r,i)=>`<tr data-i="${i}"><td>${esc(r.name)||'<span class="dim">?</span>'} <span class="dim">${r.hash}</span></td><td>${r.activity}</td><td>${ago(r.last)}</td><td>${r.last_direct?ago(r.last_direct):"-"}</td><td>${r.snr??"-"}</td><td class="small">${r.lat!=null?r.lat.toFixed(4)+", "+r.lon.toFixed(4):'<span class="dim">none sent</span>'}</td><td class="small">${r.routes.length?r.routes.map(x=>route(x.path)+` <span class="dim">${x.conf}%</span>`).join("<br>"):"-"}</td></tr>`).join("");
 RPTS=st.repeaters; LAST=st;
 document.querySelectorAll("#rpts tr[data-i]").forEach(tr=>{const r=RPTS[+tr.dataset.i];tr.onclick=()=>select(r.hash)});
 if(SEL)select(SEL); else drawMap(st);
}
function drawMap(st){
 if(typeof L==="undefined"){$("mapnote").textContent="Map needs internet access (Leaflet / OpenStreetMap). Tables above still work.";return}
 const R=st.room,pos={},tip={};st.repeaters.forEach(r=>{if(r.lat!=null&&(r.lat||r.lon)){pos[r.hash]=[r.lat,r.lon,r.name||r.hash];tip[r.hash]=`${esc(r.name||r.hash)} (${hopsTxt(hops(r))})`}});
 if(R.lat||R.lon)pos[""]=[R.lat,R.lon,R.name+" (room)"];
 const pts=Object.values(pos);
 if(!map){
  // the map must have a real view BEFORE anything is drawn on it, or Leaflet places markers off-screen
  const c=pts.length?pts[0]:[R.lat||0,R.lon||0], z=pts.length||R.lat||R.lon?11:2;
  map=L.map("map").setView([c[0],c[1]],z);
  // OSM's tile servers refuse requests without a Referer: set it on the tiles themselves so a strict
  // Referrer-Policy from a proxy / load balancer can't strip it
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",{maxZoom:18,attribution:"&copy; OpenStreetMap",
   referrerPolicy:"strict-origin-when-cross-origin"}).addTo(map);
 }
 const sig=Object.keys(pos).sort().join(",");
 if(pts.length&&map._sig!==sig){map.fitBounds(pts.map(p=>p.slice(0,2)),{padding:[30,30],maxZoom:12});map._sig=sig}
 if(layer)layer.remove(); layer=L.layerGroup().addTo(map);
 st.edges.forEach(e=>{const a=pos[e.a],b=pos[e.b];if(a&&b)L.polyline([a.slice(0,2),b.slice(0,2)],{weight:Math.min(6,1+Math.log2(1+e.w)),color:e.b===""?"#5cb3ff":"#8a94a3",opacity:.7}).bindTooltip(`${esc(a[2])} &rarr; ${esc(b[2])}<br>seen ${e.w}${e.snr!=null?"<br>SNR "+e.snr:""}`).addTo(layer)});
 Object.entries(pos).forEach(([h,p])=>{const sel=h===SEL;
  const mk=L.circleMarker(p.slice(0,2),{radius:h===""?8:sel?10:7,color:h===""?"#4caf7a":sel?"#ffd166":"#5cb3ff",weight:sel?3:2,fillOpacity:.9})
   .bindTooltip(tip[h]||esc(p[2]),{direction:"top",offset:[0,-6]}).addTo(layer);
  if(h!=="")mk.on("click",()=>select(h))});
 $("mapnote").textContent=pts.length?"":"No positions yet: repeaters appear once their adverts with GPS coordinates are heard.";
}
$("sgpath").addEventListener("input",()=>{ACI=-1;acShow()});
$("sgpath").addEventListener("blur",()=>setTimeout(acHide,150));
$("sgpath").addEventListener("keydown",e=>{const it=acItems();
 if(e.key==="ArrowDown"){ACI=Math.min(ACI+1,it.length-1);acShow();e.preventDefault()}
 else if(e.key==="ArrowUp"){ACI=Math.max(ACI-1,0);acShow();e.preventDefault()}
 else if((e.key==="Enter"||e.key==="Tab")&&ACI>=0&&$("aclist").style.display==="block"){acPick(it[ACI]);e.preventDefault()}
 else if(e.key==="Enter"){doSuggest()}else if(e.key==="Escape"){closeSuggest()}});
$("chatmsg").addEventListener("input",chatLeft);$("chatmsg").addEventListener("keydown",e=>{if(e.key==="Enter")sendChat()});chatLeft();
setInterval(()=>loadChat(false),3000);
session().then(load);setInterval(load,5000);setInterval(session,60000);
</script></body></html>"""


BUILTIN_ICONS = {   # fallbacks when data_dir/icons/<name>.png doesn't exist
    "resync": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M5 20.5 L16.2 6.8" stroke="#2a4fa8" stroke-width="2.6" '
              'stroke-linecap="round" fill="none"/><path d="M16.2 6.8 C17.2 3.9 20.3 3.4 21.6 5.4 C22.4 6.6 21.9 8 20.6 8.5" stroke="#2a4fa8" '
              'stroke-width="2.6" stroke-linecap="round" fill="none"/></svg>',
    "suggest": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><text x="12" y="19" font-size="18" text-anchor="middle">&#128161;</text></svg>',
    "kick": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><text x="12" y="19" font-size="18" text-anchor="middle">&#128098;</text></svg>',
    "advert": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><text x="12" y="19" font-size="18" text-anchor="middle">&#128227;</text></svg>',
    "flood_advert": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><text x="12" y="19" font-size="18" text-anchor="middle">&#127754;</text></svg>',
    "ban": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><text x="12" y="19" font-size="18" text-anchor="middle">&#128165;</text></svg>',
}


class WebUI:
    def __init__(self, room, events):
        import http.server
        import secrets
        cfg = room.cfg
        db_path = room.store.path
        sessions = {}                                       # token -> expiry (monotonic)
        slock = threading.Lock()
        SESSION_S = 12 * 3600
        # web traffic must never compete with the radio side: serialize each snapshot once (in the web
        # threads, not the main loop), cache the history query, and cap concurrent requests
        cache = {"state_obj": None, "state_bytes": b"{}"}
        clock_ = threading.Lock()
        slots = threading.BoundedSemaphore(16)
        last_advert = [float("-inf")]

        def state_bytes():
            st = room.web_state                             # the main loop swaps in a new dict; never mutated
            with clock_:
                if cache["state_obj"] is not st:
                    cache["state_bytes"] = json.dumps(st, default=str).encode()
                    cache["state_obj"] = st
                return cache["state_bytes"]

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _token(self):
                for part in (self.headers.get("Cookie") or "").split(";"):
                    k, _, v = part.strip().partition("=")
                    if k == "mr_session":
                        return v
                return None

            def _is_admin(self):
                tok = self._token()
                if not tok or not cfg.web_password:
                    return False
                with slock:
                    exp = sessions.get(tok)
                    if exp is None or exp < time.monotonic():
                        sessions.pop(tok, None)
                        return False
                    return True

            def _send(self, code, body, ctype="application/json", cookie=None):
                b = body if isinstance(body, bytes) else body.encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(b)))
                self.send_header("Cache-Control", "no-store")
                if cookie:
                    self.send_header("Set-Cookie", cookie)
                self.end_headers()
                try:
                    self.wfile.write(b)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass                                    # the client hung up (health check, closed tab): nothing to do

            def do_GET(self):
                if not slots.acquire(blocking=False):
                    return self._send(503, '{"error":"busy"}')    # flood guard: at most 16 requests at once
                try:
                    self._get()
                finally:
                    slots.release()

            def do_POST(self):
                if not slots.acquire(blocking=False):
                    return self._send(503, '{"error":"busy"}')
                try:
                    self._post()
                finally:
                    slots.release()

            def _get(self):
                path = self.path.split("?")[0]
                if path == "/api/session":
                    return self._send(200, json.dumps({"admin": self._is_admin(), "login_enabled": bool(cfg.web_password)}))
                if path.startswith("/static/"):
                    # files in data_dir/static (e.g. a local copy of Leaflet); Leaflet falls back to the CDN
                    root = os.path.realpath(os.path.join(cfg.data_dir, "static"))
                    f = os.path.realpath(os.path.join(root, path[8:]))
                    if f.startswith(root + os.sep) and os.path.isfile(f):
                        ctype = {".js": "application/javascript", ".css": "text/css", ".png": "image/png",
                                 ".svg": "image/svg+xml"}.get(os.path.splitext(f)[1], "application/octet-stream")
                        with open(f, "rb") as fh:
                            return self._send(200, fh.read(), ctype)
                    if path[8:] in ("leaflet.js", "leaflet.css") or path[8:].startswith("images/"):
                        self.send_response(302)
                        self.send_header("Location", "https://unpkg.com/leaflet@1.9.4/dist/" + path[8:])
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    return self._send(404, '{"error":"not found"}')
                if path.startswith("/icons/"):
                    name = path[7:].split(".")[0]
                    if name in ("resync", "suggest", "kick", "ban", "advert", "flood_advert"):
                        f = os.path.join(cfg.data_dir, "icons", name + ".png")
                        if os.path.exists(f):
                            with open(f, "rb") as fh:
                                return self._send(200, fh.read(), "image/png")
                        return self._send(200, BUILTIN_ICONS[name], "image/svg+xml")
                    return self._send(404, '{"error":"not found"}')
                if path in ("/", "/index.html"):
                    return self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")
                if path == "/api/state":
                    fresh = time.monotonic() - room.web_last_request > 20
                    room.web_last_request = time.monotonic()        # wakes up the main loop's refreshes
                    if fresh:
                        events.put(("web_wake",))                   # first view after idle: refresh right away
                    return self._send(200, state_bytes())
                if path == "/api/chat":
                    if not self._is_admin():
                        return self._send(401, '{"error":"log in first"}')
                    since = 0
                    qs = self.path.partition("?")[2]
                    for kv in qs.split("&"):
                        k, _, v = kv.partition("=")
                        if k == "since" and v.isdigit():
                            since = int(v)
                    posts = list(room.posts)                        # (the main loop only ever appends / swaps the list)
                    msgs = [dict(ts=ts, who=room.chat_label(a), room=(a == room.id.pub_key), text=txt)
                            for ts, a, txt, to in posts if to is None and ts > since]
                    return self._send(200, json.dumps({"messages": msgs, "max_bytes": MAX_POST_TEXT_LEN}))
                self._send(404, '{"error":"not found"}')

            def _post(self):
                parts = self.path.strip("/").split("/")
                if parts == ["api", "login"]:
                    if not cfg.web_password:
                        return self._send(403, '{"error":"admin login is off: set web_password in the config"}')
                    try:
                        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0) or 0) or b"{}")
                    except ValueError:
                        body = {}
                    if not hmac.compare_digest(str(body.get("password", "")).encode(), str(cfg.web_password).encode()):
                        time.sleep(1.0)                         # slow down guessing
                        return self._send(401, '{"error":"wrong password"}')
                    tok = secrets.token_hex(24)
                    with slock:
                        now_m = time.monotonic()
                        for k in [k for k, e in sessions.items() if e < now_m]:
                            del sessions[k]
                        sessions[tok] = now_m + SESSION_S
                    return self._send(200, '{"ok":true}', cookie="mr_session=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d" % (tok, SESSION_S))
                if parts == ["api", "logout"]:
                    tok = self._token()
                    with slock:
                        sessions.pop(tok, None)
                    return self._send(200, '{"ok":true}', cookie="mr_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
                if not self._is_admin():                        # everything below changes things: admins only
                    return self._send(401, '{"error":"log in first"}')
                if parts == ["api", "advert"]:
                    try:
                        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0) or 0) or b"{}")
                    except ValueError:
                        body = {}
                    with slock:
                        if time.monotonic() - last_advert[0] < 10:
                            return self._send(429, '{"error":"an advert was just sent: wait a few seconds"}')
                        last_advert[0] = time.monotonic()
                    flood = bool(body.get("flood"))
                    events.put(("advert", flood))                   # sent by the main loop
                    return self._send(200, json.dumps({"ok": True, "flood": flood}))
                if parts == ["api", "chat"]:
                    try:
                        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0) or 0) or b"{}")
                    except ValueError:
                        body = {}
                    text = str(body.get("text", "")).strip()
                    if not text:
                        return self._send(400, '{"error":"empty message"}')
                    if len(text.encode()) > MAX_POST_TEXT_LEN:
                        return self._send(400, json.dumps({"error": "too long: %d bytes max" % MAX_POST_TEXT_LEN}))
                    events.put(("say", text))                       # posted + pushed by the main loop
                    return self._send(200, '{"ok":true}')
                if len(parts) == 4 and parts[:2] == ["api", "members"] and parts[3] == "route":
                    try:
                        pub = bytes.fromhex(parts[2])
                        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0) or 0) or b"{}")
                        reps = [(r.get("name") or "", r["hash"]) for r in room.web_state.get("repeaters", [])]
                        hops = resolve_route(str(body.get("path", "")), reps)
                    except ValueError as e:
                        return self._send(400, json.dumps({"error": str(e)}))
                    events.put(("suggest", pub, hops))              # applied by the main loop
                    return self._send(200, json.dumps({"ok": True, "hops": [h.hex().upper() for h in hops]}))
                if len(parts) == 4 and parts[0] == "api" and (parts[1], parts[3]) in (("members", "kick"), ("members", "ban"), ("bans", "unban"),
                                                                                    ("members", "resync")):
                    try:
                        pub = bytes.fromhex(parts[2])
                    except ValueError:
                        return self._send(400, '{"error":"bad key"}')
                    if len(pub) != 32:
                        return self._send(400, '{"error":"bad key"}')
                    events.put((parts[3], pub))                 # applied by the main loop
                    return self._send(200, '{"ok":true}')
                self._send(404, '{"error":"not found"}')

        class Server(http.server.ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                # clients disconnecting early is routine: no traceback. Anything else is logged briefly.
                exc = sys.exc_info()[1]
                if isinstance(exc, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError)):
                    return
                log.warning("dashboard request from %s failed: %r", client_address[0], exc)

        self.server = Server((cfg.web_bind, int(cfg.web_port)), H)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, name="web", daemon=True).start()
        log.info("dashboard on http://%s:%d/", cfg.web_bind, int(cfg.web_port))


# ============================================================================
# Main
# ============================================================================

def main():
    ap = argparse.ArgumentParser(description="MeshCore room server over a KISS modem")
    ap.add_argument("--config", default="meshroom.json")
    ap.add_argument("--purge-map", action="store_true",
                    help="erase the learned repeater map (heard repeaters, links, routes to repeaters, member locations) and exit; "
                         "members, posts, routes to members, names and repeater names/positions are kept")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    sys.setswitchinterval(0.001)                            # 1 ms thread slices (default 5 ms): reader thread runs sooner
    cfg = Config(args.config)
    logging.getLogger().setLevel(getattr(logging, str(cfg.log_level).upper(), logging.INFO))
    os.makedirs(cfg.data_dir, exist_ok=True)
    if args.purge_map:
        dbp = os.path.join(cfg.data_dir, "room.db")
        if not os.path.exists(dbp):
            sys.exit("no database at %s" % dbp)
        db = sqlite3.connect(dbp)
        for tbl in ("rpt_routes", "edges", "heard", "member_rpts"):
            n = db.execute("SELECT COUNT(*) FROM %s" % tbl).fetchone()[0]
            db.execute("DELETE FROM %s" % tbl)
            log.info("purged %s: %d rows", tbl, n)
        db.commit()
        db.close()
        log.info("repeater map erased - start the room again to rebuild it")
        return

    events = queue.Queue()
    modem = KissModem(cfg.serial, cfg.baud, events)
    for attempt in range(10):                               # Ping; give a modem that just reset time to boot
        if modem.command(0x17, timeout=1.5) is not None:
            break
        if attempt == 0:
            log.info("waiting for the modem on %s ...", cfg.serial)
    else:
        log.error("no reply from a KISS modem on %s. Check: right port? KISS modem firmware flashed? "
                  "port in use by another program?", cfg.serial)
        modem.close()
        sys.exit(1)
    modem.set_param(0x01, cfg.kiss_txdelay)
    modem.set_param(0x02, cfg.kiss_persistence)
    modem.set_param(0x03, cfg.kiss_slottime)
    modem.command(0x19, b"\x01")                            # RxMeta (SNR/RSSI) on
    identity = ModemIdentity(modem) if cfg.identity == "modem" else LocalIdentity(cfg.identity)
    store = Store(os.path.join(cfg.data_dir, "room.db"))
    store.events = events
    room = RoomServer(cfg, modem, identity, store)
    room.events_put = events.put
    room.events_q = events
    if cfg.web_port:
        try:
            room.publish_web_state()
            WebUI(room, events)
        except OSError as e:
            log.error("dashboard could not start on port %s: %s", cfg.web_port, e)
            room.web_port_active = False
    room.apply_radio()
    if room.radio:
        log.info("radio: %.3f MHz, BW %.1f kHz, SF%d, CR4/%d", room.radio[0] / 1e6, room.radio[1] / 1e3, room.radio[2], room.radio[3])
    log.info("room %r, public key %s", cfg.name, hexs(identity.pub_key))

    def stop(*_):
        events.put(("quit",))
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def handle(ev):
        """One event. Returns False to stop."""
        kind = ev[0]
        if kind == "rx":
            room.on_rx(*ev[1:])
        elif kind == "txdone":
            room.on_txdone(ev[1])
        elif kind == "hw":
            room.on_hw(ev[1], ev[2])
        elif kind in ("kick", "ban", "unban", "resync"):
            getattr(room, "force_resync" if kind == "resync" else kind)(ev[1])
            room.web_dirty = True                           # refresh the dashboard once the radio is idle
        elif kind == "advert":
            room.send_advert(ev[1])
            log.info("%s sent from the dashboard", "flood advert" if ev[1] else "advert (zero-hop)")
        elif kind == "say":
            room.room_say(ev[1])
        elif kind == "suggest":
            room.suggest_route(ev[1], ev[2])
            room.web_dirty = True
        elif kind == "web_wake":
            room.web_dirty = True
        elif kind == "dberror":
            log.error("database write failed: %s", ev[1])
        elif kind == "txbusy":
            room.tx_busy_until = time.monotonic() + 0.5
        elif kind in ("quit", "serial_error"):
            return False
        return True

    running = True
    while running:
        # sleep until the next event, but wake exactly when a queued transmission (e.g. an ACK) is due
        timeout = 0.05
        if room.txq:
            due = min(e[0] for e in room.txq) - time.monotonic()
            timeout = min(timeout, max(due, room.tx_busy_until - time.monotonic(), 0.0005))
        try:
            ev = events.get(timeout=timeout)
        except queue.Empty:
            ev = None
        try:
            # packets first: handle everything already queued (radio packets, TX done, modem replies, clicks)
            # before any housekeeping, so ACKs and replies go out as early as possible
            while ev is not None and running:
                running = handle(ev)
                try:
                    ev = events.get_nowait()
                except queue.Empty:
                    ev = None
            if running:
                room.run_once()                             # push scheduler, transmit queue, periodic jobs
        except Exception:
            log.exception("main loop")
    log.info("shutting down: saving state")
    room.flush()
    room.flush_topology()
    store.close()                                           # waits for the writer thread to finish
    modem.close()


if __name__ == "__main__":
    main()
