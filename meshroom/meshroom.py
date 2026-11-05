#!/usr/bin/env python3
"""
meshroom.py - a MeshCore room server for Linux (e.g. Raspberry Pi Zero 2 W),
using a MeshCore KISS modem (examples/kiss_modem firmware) as the radio.

Ported from the C++ simple_room_server firmware (branch room-server-improvements),
including: persistent members/posts/routes (SQLite), multi-route table with scoring,
a self-adjusting push pace, hop-sorted push rounds, late-ACK handling, suspension (resumed on activity) for
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
import itertools
import hmac
import ipaddress
import collections
import gzip
import json
import socket
import ssl
import base64
import logging
import math
import os
import queue
import random
import re
import signal
import sqlite3
import struct
import sys
import threading
import time
import types
import urllib.parse

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
FIRMWARE_VERSION = "meshroom-py 4.9"
FIRMWARE_VER_LEVEL = 1

# ============================================================================
# Configuration
# ============================================================================

DEFAULT_CONFIG = {
    "serial": "/dev/ttyACM0",
    "baud": 115200,
    "name": "pyMeshRoom",           # this server's name on its dashboard (each room has its own)
    "lat": 0.0,
    "lon": 0.0,
    # Empty means disabled for admin, and open for the room.  Never give a
    # newly-created server a known administrator password.
    "admin_password": "",
    "room_password": "",
    "allow_read_only": False,
    "data_dir": "./meshroom_data",
    "max_posts": 100,               # posts kept (history depth)
    "catchup_max": 10,              # brand-new members get only the newest N
    "path_hash_mode": 0,            # 0/1/2 = 1/2/3-byte path hashes for floods we originate
    "advert_interval_min": 60,      # zero-hop advert (0 = off)
    "flood_advert_interval_h": 12,  # flood advert (0 = off)
    "push_pace_start_ms": 2000,     # gap between pushes: starts here, self-adjusts between min and max
    "push_pace_min_ms": 1500,
    "push_pace_max_ms": 8000,
    "push_gap_flood_ms": 10000,     # after a flood push: at most this long (ends early once the rebroadcasts pass)
    "radio_freq_mhz": 910.525,      # radio settings pushed to the modem at startup (it doesn't save them):
    "radio_bw_khz": 62.5,           #   US/Canada preset 910.525 MHz / BW 62.5 / SF7 / CR4:5
    "radio_sf": 7,
    "radio_cr": 5,
    "radio_tx_power_dbm": None,     # None = leave the modem's default
    "tx_duty_pct": 50,              # airtime ceiling: all this radio sends together, % of the time (see Airtime)
    "tx_weight_control": 10,        #   weights: each class's guaranteed share of it is its weight over the sum of all
    "tx_weight_relay": 15,          #   that are on. Control: ACKs, replies and path returns; relay: the virtual repeater
    "tx_weight_room": 10,           #   (when on); room: message delivery to members (all rooms);
    "tx_weight_web": 5,             #   web: MeshCore Web users;
    "tx_weight_companion": 2,       #   companion: the virtual companion (when on);
    "tx_weight_kaas": 3,            #   kaas: API clients;
    "tx_weight_background": 5,      #   background: adverts and traces
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
    "mqtt_enabled": False,          # MQTT augmentation: also listen to the observer network (RF stays the fallback)
    "mqtt_ack_ingest": False,       #   ACK ingestion: observers' ACKs confirm deliveries (no route credit). Off by
                                    #   default: anyone who can publish to the feed could mark a post delivered
    "mqtt_msg_ingest": True,        #   message ingestion: posts to the room captured by observers
    "mqtt_topo_ingest": True,       #   topology ingestion: links + SNR between repeaters we already know (never routes)
    "mqtt_advert_ingest": True,     #   advert ingestion: names, positions, where companions are (half weight)
    "mqtt_activity": True,          #   activity monitor: a suspended member seen anywhere resumes sync (max every 15 min)
    "mqtt_channels": ["Public"],    #   channels watched for members' activity: "Public" and/or "#hashtag" names
    "mqtt_host": "mqtt.gomesh.dev",
    "mqtt_port": 443,
    "mqtt_transport": "websockets", # or "tcp"
    "mqtt_ws_path": "/mqtt",
    "mqtt_tls": True,
    "mqtt_tls_verify": True,
    "mqtt_username": "",
    "mqtt_password": "",
    "mqtt_topics": ["meshcore/#"],
    "mqtt_queue_max": 1000,         # bounded ingress; newest observation is dropped under overload
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
    # MQTT observer is opt-in.  Disabled keeps MeshRoom's normal runtime free
    # of both the MQTT dependency and all observer activity.
    "observer_enabled": False,
    "observer_identity": "",        #   who it reports as: "repeater" (the virtual repeater) or a room's public key (hex)
    "observer_iata": "",
    "observer_status": True,
    "observer_packets": True,
    "observer_rx": True,
    "observer_gomesh": True,
    "observer_meshmapper": True,
    # None preserves the legacy GoMesh/MeshMapper pair; an admin-managed list
    # replaces that pair when custom observer destinations are saved.
    "observer_servers": None,
    "observer_queue_max": 1000,
    "log_level": "INFO",
    "repeater_enabled": False,      # virtual repeater: a second identity on the room's radio that relays like a repeater
    "repeater_relay": False,        #   relay packets (False = kill switch: still advertises, relays nothing)
    "repeater_name": "pyMeshRoom Virtual Repeater",
    "repeater_key": "",             #   private key, hex: 32-byte seed or 64-byte MeshCore key ("" = make one, saved here)
    "repeater_lat": 0.0,            #   its advertised position (0, 0 = the room's), e.g. a little apart so map icons
    "repeater_lon": 0.0,            #   don't sit on top of each other
    "repeater_advert_interval_min": 60,       # zero-hop advert (0 = off)
    "repeater_flood_advert_interval_h": 12,   # flood advert (0 = off)
    "repeater_scope_mode": "allow", #   scoped (region) floods: "allow" = relay only these regions, "deny" = all but these
    "repeater_regions": [],         #   region names ("#name" or "name"); unscoped floods are always relayed
    "repeater_loop_detect": "minimal",        # off / minimal / moderate / strict (the firmware's loop.detect)
    "companion_enabled": False,     # virtual companion: a chat node on the room's radio that MeshCore apps connect to over TCP
    "companion_name": "pyMeshRoom Companion",
    "companion_key": "",            #   private key, hex: 32-byte seed or 64-byte MeshCore key ("" = make one, saved here)
    "companion_port": 5000,         #   TCP port (as WiFi companion firmware); only open while the companion is enabled
    "companion_bind": "0.0.0.0",    #   address the port listens on ("127.0.0.1" = this machine only)
    "companion_allow": [],          #   IP addresses / networks allowed to connect ([] = anyone who can reach the port)
    "companion_lat": 0.0,           #   its position (set from the app; shared in adverts only if the app says so)
    "companion_lon": 0.0,
    "companion_auto_advert": False, #   advert on its own every companion_advert_interval_min
    "companion_advert_interval_min": 60,
    "companion_advert_flood": False,          # auto adverts: flood (whole mesh) instead of zero-hop
    "tenant_rooms": [],             # tenant rooms: [{"name", "path", "public_key"}]; everything else is in tenants/{key}.db
    "kaas_keys": [],                # KaaS API keys (made on the dashboard): only a hash of each key is kept, never the key
    "kaas_send_burst": 3,           #   per key: at most this many packets...
    "kaas_send_window_s": 20,       #   ...in any this many seconds (ACKs and path returns excepted)
    "web_login": False,             # MeshCore Web: people log in by signing with their node's private key (no API key)
    "web_max_clients": 32,          #   web sessions at once (bots' API keys have their own limit)
    "web_approved": [],             #   public keys (hex) the admin let send although never heard on this radio
    "web_banned": [],               #   [{"pub", "name", "ts"}]: may not log in
    "web_banned_ips": [],           #   [{"ip", "name", "ts"}]: addresses refused MeshCore Web logins and sessions
    "web_unknown_key_message":      #   what a web user whose key may not send yet is told
        "Your key must be heard on RF before you can send messages. Please send a flood advert.",
    "web_motd_enabled": False,      #   show web users a message of the day when they log in...
    "web_motd": "",                 #   ...this one (plain text, line breaks kept; at most 1000 characters)
    "web_hosts": [],                #   the names MeshCore Web is reached by (a domain, a proxy): logins signed for others are refused
    "web_page_password": "",        #   a password for the MeshCore Web page and its logins (hashed; "" = none)
    "web_giphy_key": "",            #   a Giphy API key for MeshCore Web's GIF picker ("" = no picker; links still show)
    "web_backlog_days": 30,         #   keep channel messages and DMs this many days, so web users catch up (0 = off)
    "web_backlog_mqtt": False,      #   ...including those MQTT observers reported (each packet is kept once)
}


# The dashboard's headers. Its scripts are inline (and so are its handlers), so the policy can't pin them by hash; it
# keeps everything else to this server: no script, stylesheet, connection or form target elsewhere, except Leaflet
# (from unpkg when it isn't installed locally) and the map tiles. Never framed.
DASHBOARD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; "
                               "style-src 'self' 'unsafe-inline' https://unpkg.com; "
                               "img-src 'self' data: https://unpkg.com https://tile.openstreetmap.org "
                               "https://*.tile.openstreetmap.org; connect-src 'self'; object-src 'none'; base-uri 'none'; "
                               "form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "strict-origin-when-cross-origin"}

HTTP_TIMEOUT_S = 30                   # a dashboard / API connection idle (or trickling) this long is closed
HTTP_MAX_BODY = 64 * 1024             # a request body larger than this is refused (413)
FAIL_LIMIT = 20                       # wrong passwords / keys / tickets from one address within FAIL_WINDOW_S...
FAIL_WINDOW_S = 600                   # ...and its POSTs and websockets get 429 until the oldest is this old
CROSS_SITE_POSTS = {"/api/v1/web/challenge", "/api/v1/web/login", "/api/v1/web/ticket"}   # (CORS: any origin)
HTTP_MAX_THREADS = 400                # connections beyond this many threads in the process are closed at once
# per visitor's address (not for private addresses: the LAN, or a proxy that doesn't say who it forwarded for)
LAN_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]
IP_LOGINS_PER_MIN = 10                # web login challenges an address may ask for a minute
IP_WS_PER_MIN = 30                    # websockets an address may open a minute (web logins and API keys)
IP_WEB_SESSIONS = 4                   # web sessions open at once from an address
KAAS_MSG_RATE = 20                    # messages a second a websocket client may send, on average...
KAAS_MSG_BURST = 40                   # ...in bursts of up to this many; one this far over the limit is disconnected

REPEATERS_MAX = 2000                  # repeaters known by key (heard, or from MQTT): beyond it the longest silent go


class RepeaterTable(dict):
    """The repeater table: adding a new one past REPEATERS_MAX drops the tenth that advertised longest ago (never the
    one keep() says is ours), so neither the air nor an MQTT feed can grow it without end."""

    def __init__(self, keep):
        super().__init__()
        self.keep = keep

    def __setitem__(self, k, v):
        new = k not in self
        super().__setitem__(k, v)
        if new and len(self) > REPEATERS_MAX:
            old = sorted((r.get("last_advert") or 0, pub) for pub, r in self.items() if pub != k and not self.keep(pub))
            for _, pub in old[:len(self) - REPEATERS_MAX + REPEATERS_MAX // 10]:
                del self[pub]


TX_CLASSES = ("control", "relay", "room", "web", "companion", "kaas", "background")
TX_BUCKET_S = 60                      # each share saves up at most this many seconds' worth, so a burst goes at once
TX_STALE_S = {"relay": 20.0, "web": 120.0, "companion": 120.0, "kaas": 120.0}   # held this long past due by the
                                      # airtime limits: dropped (a late relay is useless)
TX_USAGE_S = 600                      # airtime used, as the dashboard shows it: over the last 10 minutes
TX_CONTROL_OVER_MS = 10000            # the rooms' ACKs and replies may go this far over the ceiling before they wait too


def tx_class(pkt, deferrable, relay, src, tag):
    """Which share of airtime a packet comes out of."""
    if relay:
        return "relay"
    if src == "vc":
        return "companion"
    if tag is not None:                                     # (conn, request id) of a KaaS client
        return "web" if getattr(tag[0], "web", None) else "kaas"
    if pkt.ptype in (PT_ADVERT, PT_TRACE):
        return "background"
    return "room" if deferrable else "control"


class Airtime:
    """One ceiling for everything this radio sends (tx_duty_pct of the time), and a guaranteed share of it for each
    class of traffic, in proportion to its weight among the classes that are on (off() names those that aren't: the
    virtual repeater or companion when disabled), like Linux's HTB: a class spends its own share first, then borrows what the others leave unused,
    up to the ceiling. So a class alone on the air may use the whole ceiling; when all are busy, each still gets its
    share. Token buckets in ms of airtime, refilled at their rates and holding TX_BUCKET_S worth. Sending always
    charges the ceiling's bucket (down to minus its depth); borrowing needs it positive. The rooms' ACKs and replies
    (control), useless late, may also go over the ceiling by up to TX_CONTROL_OVER_MS, a burst; only after that do
    they wait like the rest."""

    def __init__(self, cfg, off=lambda: ()):
        self.cfg, self.off = cfg, off
        self.t = self.start = time.monotonic()
        self.own = dict.fromkeys(TX_CLASSES)
        self.pool = None
        self.used = collections.deque()                     # (monotonic, class, ms), the last TX_USAGE_S
        self.dropped = dict.fromkeys(TX_CLASSES, 0)

    def weights(self):
        """{class: weight}, 0 for a class that's off."""
        off = set(self.off())
        return {k: 0.0 if k in off else max(0.0, float(getattr(self.cfg, "tx_weight_" + k, 0) or 0)) for k in TX_CLASSES}

    def rates(self):
        """(ceiling, {class: guaranteed share}) as fractions of the time: the ceiling split by weight."""
        ceiling = max(1.0, min(100.0, float(getattr(self.cfg, "tx_duty_pct", 50) or 0))) / 100.0
        w = self.weights()
        total = sum(w.values())
        return ceiling, {k: ceiling * v / total if total else 0.0 for k, v in w.items()}

    def refill(self):
        now = time.monotonic()
        dt, self.t = max(0.0, now - self.t) * 1000.0, now
        ceiling, shares = self.rates()
        cap = ceiling * TX_BUCKET_S * 1000.0
        self.pool = cap if self.pool is None else min(cap, self.pool + dt * ceiling)
        for k, r in shares.items():
            depth = r * TX_BUCKET_S * 1000.0
            self.own[k] = depth if self.own[k] is None else min(depth, self.own[k] + dt * r)
        return cap

    def can(self, cls, ms):
        """May a packet of this class, ms long, go now? (A full bucket lets even a packet longer than it go.)"""
        cap = self.refill()
        if cls == "control":
            return self.own[cls] >= ms or self.pool >= min(ms, cap) - TX_CONTROL_OVER_MS
        return self.own[cls] >= ms or self.pool >= min(ms, cap)

    def charge(self, cls, ms):
        cap = self.refill()
        _, shares = self.rates()
        if self.own[cls] >= ms:
            self.own[cls] -= ms
        self.pool = max(self.pool - ms, -cap - TX_CONTROL_OVER_MS)
        now = time.monotonic()
        self.used.append((now, cls, ms))
        while self.used and now - self.used[0][0] > TX_USAGE_S:
            self.used.popleft()

    def state(self):
        ceiling, shares = self.rates()
        now = time.monotonic()
        span = max(60.0, min(float(TX_USAGE_S), now - self.start)) * 1000.0
        used = dict.fromkeys(TX_CLASSES, 0.0)
        for t, k, ms in self.used:
            if now - t <= TX_USAGE_S:
                used[k] += ms
        r = lambda x: round(100.0 * x, 1)
        w, off = self.weights(), set(self.off())
        return dict(ceiling_pct=r(ceiling), share_pct={k: r(v) for k, v in shares.items()},
                    weight={k: getattr(self.cfg, "tx_weight_" + k, 0) for k in TX_CLASSES}, off=sorted(off),
                    weight_total=round(sum(w.values()), 2),
                    used_pct={k: r(v / span) for k, v in used.items()}, total_pct=r(sum(used.values()) / span),
                    dropped=dict(self.dropped), window_s=int(span / 1000))


def airtime_changes(body):
    """Dashboard airtime settings -> {config key: value}, validated."""
    if not isinstance(body, dict):
        raise ValueError("bad request")
    ch = {}

    def pct(v, what, lo):
        try:
            v = float(v)
        except (TypeError, ValueError):
            raise ValueError("%s: not a number" % what)
        if not lo <= v <= 100:
            raise ValueError("%s: %g to 100 %%" % (what, lo))
        return int(v) if v == int(v) else v
    if "duty_pct" in body:
        ch["tx_duty_pct"] = pct(body["duty_pct"], "ceiling", 1)
    weights = body.get("weight") or {}
    if not isinstance(weights, dict):
        raise ValueError("bad request")
    for k, v in weights.items():
        if k not in TX_CLASSES:
            raise ValueError("unknown class %r" % k)
        try:
            v = float(v)
        except (TypeError, ValueError):
            raise ValueError("%s: not a number" % k)
        if not 0 <= v <= 10000:
            raise ValueError("%s: a weight of 0 to 10000" % k)
        ch["tx_weight_" + k] = int(v) if v == int(v) else v
    return ch


def valid_iata(code):
    """An observer's region code: three letters (an airport code, like SJC)."""
    return isinstance(code, str) and len(code) == 3 and code.isascii() and code.isalpha() and code.isupper()


# settings older versions had: ignored quietly
RETIRED_SETTINGS = {"web_trust_observers", "repeater_airtime_pct", "kaas_airtime_pct", "tx_share_control_pct",
                    "tx_share_relay_pct", "tx_share_room_pct", "tx_share_users_pct", "tx_share_background_pct"}


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
        if k in RETIRED_SETTINGS:
            return                                          # (no longer a setting: left in the file, unused)
        if k not in DEFAULT_CONFIG:
            log.warning("config: '%s'%s is not a setting this version uses (ignored)", k, " in section '%s'" % section if section else "")
        self.data[k] = v
        self.where[k] = section

    def __getattr__(self, k):
        try:
            return self.__dict__["data"][k]
        except KeyError:
            raise AttributeError(k)

    def set(self, k, v, save=True):
        """Change a setting, and write the file (unless save=False: the caller saves later, see save())."""
        self.data[k] = v
        sec = self.where.get(k)
        if sec is not None and isinstance(self.layout.get(sec), dict):
            self.layout[sec][k] = v                         # update it where it lives
        else:
            self.layout[k] = v
            self.where[k] = None
        if save:
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

PLAN_ROUTES = 4                   # attempt plan: the top routes, then PLAN_FLOODS floods
PLAN_FLOODS = 2
ROUTES_PER_MEMBER = 3
ROUTE_DROP_FAILS = 2
ROUTE_HALFLIFE_H = 24
ROUTE_MAX_AGE_D = 7
FLOOD_ACK_S = 30.0               # wait for a flood's ACK
DIRECT_ACK_MAX_S = 60.0          # cap on a direct attempt's wait (firmware formula, see ack_wait)
LATE_ACK_S = 120                 # an attempt's ACK still credits its route this long after its own timeout
PACE_MAX_HOPS = 2                # only pushes over routes this short count toward the shared pace (local congestion)
RETRY_BEFORE_SUSPEND_S = 60      # one retry (best route + floods) a minute after a plan fails, then suspension
SUSPENDED_PROBE_S = 6 * 3600     # while suspended: a single flood this often, in case they listen but never transmit
MAX_NEIGHBOURS = 50
NAME_CACHE_MAX = 1000
NODES_MAX = 5000                 # every node heard advertising (any type), kept with its full key: the oldest go first
NODES_ANSWER_MAX = 2000                # a KaaS "nodes" answer: at most this many, the most recently heard
ROOM_ANSWER_MAX = 500                 # posts in one "room" answer (a web login reading a room on this server)

SLOT_FLOOD = "flood"


def ack_wait(plen, airtime_ms):
    """Seconds to wait for an ACK. Direct: the firmware's own timeout (SEND_TIMEOUT_BASE_MILLIS 500 +
    (DIRECT_SEND_PERHOP_FACTOR 6 x airtime + DIRECT_SEND_PERHOP_EXTRA_MILLIS 250) per leg, hops + 1 legs), capped.
    Flood (plen None): FLOOD_ACK_S."""
    if plen is None:
        return FLOOD_ACK_S
    return min((500 + (airtime_ms * 6 + 250) * ((plen & 63) + 1)) / 1000.0, DIRECT_ACK_MAX_S)


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


MAP_MAX_AGE_S = 72 * 3600             # repeaters not heard for this long are left off the map


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


# Ed25519 signing from an expanded key [scalar || prefix], as MeshCore stores private keys (orlp ed25519). The
# cryptography package only signs from a 32-byte seed, and a firmware key can't be turned back into one.
_ED_D = -121665 * pow(121666, _P - 2, _P) % _P
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493


def _ed_add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _ED_D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _ed_mul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        s >>= 1
    return q


def _ed_encode(p):
    zi = pow(p[2], _P - 2, _P)
    x, y = p[0] * zi % _P, p[1] * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_base():
    y = 4 * pow(5, _P - 2, _P) % _P
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if x & 1:
        x = _P - x
    return (x, y, 1, x * y % _P)


_ED_B = _ed_base()


class RepeaterIdentity:
    """The virtual repeater's (or companion's) own key, from the config: a 32-byte seed or a 64-byte MeshCore private key."""

    def __init__(self, key):
        if len(key) == 32:
            h = bytearray(hashlib.sha512(key).digest())
            h[0] &= 248; h[31] &= 127; h[31] |= 64
            key = bytes(h)
        if len(key) != 64:
            raise ValueError("repeater_key must be 32 or 64 bytes of hex")
        self._a = int.from_bytes(key[:32], "little") & ((1 << 255) - 1)
        self._prefix = key[32:]
        self.pub_key = _ed_encode(_ed_mul(self._a, _ED_B))
        self._x = X25519PrivateKey.from_private_bytes(key[:32])   # (the virtual companion's key exchange)

    def sign(self, msg):
        r = int.from_bytes(hashlib.sha512(self._prefix + msg).digest(), "little") % _ED_L
        big_r = _ed_encode(_ed_mul(r, _ED_B))
        h = int.from_bytes(hashlib.sha512(big_r + self.pub_key + msg).digest(), "little") % _ED_L
        return big_r + ((r + h * self._a) % _ED_L).to_bytes(32, "little")

    def shared_secret(self, other_pub):
        """ed25519_key_exchange: X25519 with the key's scalar and the peer's Ed25519 key converted (as LocalIdentity)."""
        return self._x.exchange(X25519PublicKey.from_public_bytes(ed25519_pub_to_x25519(other_pub)))


def transport_key(region):
    """MeshCore auto (hashtag) region key: SHA-256 of "#name", first 16 bytes (TransportKeyStore::getAutoKeyFor;
    RegionMap treats a plain name as "#name"). "$" private regions need a key store, which the firmware lacks too."""
    name = region if region.startswith("#") else "#" + region
    return hashlib.sha256(name.encode()).digest()[:16]


def transport_code(key, pkt):
    """TransportKey::calcTransportCode: HMAC-SHA256(key, type || payload), first 2 bytes little-endian;
    0000 and FFFF are reserved."""
    code = struct.unpack("<H", hmac.new(key, bytes([pkt.ptype]) + pkt.payload, hashlib.sha256).digest()[:2])[0]
    return 1 if code == 0 else 0xFFFE if code == 0xFFFF else code


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
        if not raw or len(raw) < 2:
            return None                                     # empty / truncated (e.g. a bad observer message)
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

    def copy(self):
        p = Packet()
        p.header, p.transport_codes, p.path_len, p.path, p.payload = self.header, self.transport_codes, self.path_len, self.path, self.payload
        p.snr, p.rssi, p.raw_len = self.snr, self.rssi, self.raw_len
        return p


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
                    "deliveries INT", "in_path BLOB", "in_path_len INT", "in_ts INT", "last_heard INT", "suspended_at INT"),
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
        "nodes": ("pubkey BLOB PRIMARY KEY", "type INT", "name TEXT", "lat REAL", "lon REAL", "adv_ts INT", "rf INT", "obs INT"),
        "backlog": ("seq INTEGER PRIMARY KEY", "hash BLOB UNIQUE", "ts INT", "raw BLOB", "src TEXT", "snr REAL", "ptype INT",
                    "ch INT", "dst INT"),
        "heard": ("hash BLOB PRIMARY KEY", "last INT", "w REAL", "t INT", "last_direct INT", "snr REAL", "disc INT", "out_snr REAL"),
        "bans": ("pubkey BLOB PRIMARY KEY", "name TEXT", "ts INT"),
        "probes": ("hash BLOB PRIMARY KEY", "data TEXT"),
        "obs_edges": ("a BLOB", "b BLOB", "w REAL", "t INT", "snr REAL", "PRIMARY KEY (a, b)"),
        "settings": ("k TEXT PRIMARY KEY", "v TEXT"),     # (a tenant room's own settings)
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
                                       "out_path, out_path_len, given_up, secret, attempts_avg, deliveries, in_path, in_path_len, in_ts, "
                                       "last_heard, suspended_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", c["members"])
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


def mqtt_changes(body):
    """Dashboard MQTT settings -> config changes. Credentials are write-only."""
    if not isinstance(body, dict):
        raise ValueError("bad request")
    ch = {k: bool(body[j]) for j, k in (("enabled", "mqtt_enabled"), ("ack_ingest", "mqtt_ack_ingest"),
                                         ("msg_ingest", "mqtt_msg_ingest"), ("topo_ingest", "mqtt_topo_ingest"),
                                         ("advert_ingest", "mqtt_advert_ingest"), ("activity", "mqtt_activity")) if j in body}
    if "username" in body or "password" in body:
        username = str(body.get("username") or "").strip()
        password = str(body.get("password") or "")
        if not username or not password:
            raise ValueError("subscriber username and password are both required")
        if len(username.encode()) > 256 or len(password.encode()) > 512 or "\0" in username or "\0" in password:
            raise ValueError("subscriber credentials are invalid or too long")
        # These keys are saved in the local, owner-protected configuration but
        # deliberately never included in dashboard state or a response body.
        ch["mqtt_username"] = username
        ch["mqtt_password"] = password
    if "host" in body:
        host = str(body["host"] or "").strip()
        if not host or len(host) > 253 or any(c.isspace() for c in host) or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:" for c in host):
            raise ValueError("broker host is invalid")
        ch["mqtt_host"] = host
    if "port" in body:
        try:
            port = int(body["port"])
        except (TypeError, ValueError):
            raise ValueError("broker port is invalid")
        if not 1 <= port <= 65535:
            raise ValueError("broker port must be 1 to 65535")
        ch["mqtt_port"] = port
    if "transport" in body:
        transport = str(body["transport"])
        if transport not in ("websockets", "tcp"):
            raise ValueError("transport must be websockets or tcp")
        ch["mqtt_transport"] = transport
    if "ws_path" in body:
        ws_path = str(body["ws_path"] or "").strip()
        if not ws_path.startswith("/") or len(ws_path) > 256 or any(c.isspace() for c in ws_path):
            raise ValueError("WebSocket path must start with / and contain no spaces")
        ch["mqtt_ws_path"] = ws_path
    for j, k in (("tls", "mqtt_tls"), ("tls_verify", "mqtt_tls_verify")):
        if j in body:
            ch[k] = bool(body[j])
    if "topics" in body:
        raw_topics = body["topics"]
        if isinstance(raw_topics, str):
            topics = [t.strip() for t in raw_topics.replace("\n", ",").split(",") if t.strip()]
        elif isinstance(raw_topics, list):
            topics = [str(t).strip() for t in raw_topics if str(t).strip()]
        else:
            raise ValueError("topic filters must be text or a list")
        if not topics or len(topics) > 16:
            raise ValueError("configure 1 to 16 MQTT topic filters")
        for topic in topics:
            levels = topic.split("/")
            if len(topic) > 256 or any(not level and len(levels) == 1 for level in levels) or any("+" in level and level != "+" for level in levels) or any("#" in level and (level != "#" or i != len(levels) - 1) for i, level in enumerate(levels)):
                raise ValueError("invalid MQTT topic filter: %s" % topic)
        ch["mqtt_topics"] = topics
    return ch


def observer_servers_changes(servers):
    """Validate admin-managed standard MeshCore JWT observer destinations."""
    if not isinstance(servers, list) or len(servers) > 16:
        raise ValueError("configure 0 to 16 observer servers")
    out, ids = [], set()
    for item in servers:
        if not isinstance(item, dict):
            raise ValueError("observer server must be an object")
        name = str(item.get("name") or "").strip()
        sid = str(item.get("id") or name.lower().replace(" ", "-")).strip().lower()
        host = str(item.get("host") or "").strip()
        audience = str(item.get("audience") or host).strip()
        ws_path = str(item.get("ws_path") or "/").strip()
        prefix = str(item.get("topic_prefix") or "meshcore").strip("/")
        try: port = int(item.get("port"))
        except (TypeError, ValueError): raise ValueError("observer server port is invalid")
        if (not name or len(name) > 40 or not sid or sid in ids or len(sid) > 40 or
            any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in sid) or not host or len(host) > 253 or
            any(c.isspace() for c in host) or not 1 <= port <= 65535 or not audience or len(audience) > 253 or
            not ws_path.startswith("/") or len(ws_path) > 256 or not prefix or len(prefix) > 128):
            raise ValueError("observer server has invalid name, host, port, audience, path, or topic prefix")
        ids.add(sid)
        out.append(dict(id=sid, name=name, enabled=bool(item.get("enabled", True)), host=host, port=port,
                        audience=audience, ws_path=ws_path, tls=bool(item.get("tls", True)),
                        tls_verify=bool(item.get("tls_verify", True)), topic_prefix=prefix))
    return out


def repeater_changes(body):
    """Dashboard repeater settings -> {config key: value}, validated. Raises ValueError with a readable message."""
    if not isinstance(body, dict):
        raise ValueError("bad request")

    def num(j):
        try:
            v = float(body[j])
        except (TypeError, ValueError):
            raise ValueError("%s: not a number" % j)
        return int(v) if v == int(v) else v
    ch = {}
    for j, k in (("enabled", "repeater_enabled"), ("relay", "repeater_relay")):
        if j in body:
            ch[k] = bool(body[j])
    if "private_key" in body:
        key = str(body["private_key"]).strip().lower()
        if len(key) not in (64, 128) or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("private key must be 64 or 128 hexadecimal characters")
        # Never return this value through dashboard state or logs.  The POST
        # handler permits replacement only while the repeater is off.
        RepeaterIdentity(bytes.fromhex(key))
        ch["repeater_key"] = key
    if "name" in body:
        name = str(body["name"]).strip()
        if not name or len(name.encode()) > 31:
            raise ValueError("name: 1 to 31 bytes")
        ch["repeater_name"] = name
    if "scope_mode" in body:
        if body["scope_mode"] not in ("allow", "deny"):
            raise ValueError("scope mode: allow or deny")
        ch["repeater_scope_mode"] = body["scope_mode"]
    if "regions" in body:
        regs = body["regions"]
        if isinstance(regs, str):
            regs = regs.split(",")
        regs = [str(r).strip() for r in regs if str(r).strip()]
        for r in regs:                                      # RegionMap::is_name_char, after an optional leading #
            if len(r) > 30 or r.startswith("$") or not all(c in "-$#" or "0" <= c <= "9" or c >= "A" for c in r):
                raise ValueError("region %r: letters, digits and - only (private $ regions aren't supported)" % r)
        ch["repeater_regions"] = regs
    if "airtime_cap" in body:                               # (its airtime weight: see Airtime)
        v = num("airtime_cap")
        if not 0 <= v <= 10000:
            raise ValueError("airtime weight: 0 to 10000")
        ch["tx_weight_relay"] = v
    if "loop_detect" in body:
        if body["loop_detect"] not in ("off", "minimal", "moderate", "strict"):
            raise ValueError("loop detection: off, minimal, moderate or strict")
        ch["repeater_loop_detect"] = body["loop_detect"]
    for j, k, hi in (("lat", "repeater_lat", 90), ("lon", "repeater_lon", 180)):
        if j in body:
            v = 0.0 if body[j] in ("", None) else float(num(j))   # blank = the room's position
            if not -hi <= v <= hi:
                raise ValueError("%s: -%d to %d" % (j, hi, hi))
            ch[k] = v
    for j, k, hi in (("advert_min", "repeater_advert_interval_min", 1440), ("flood_advert_h", "repeater_flood_advert_interval_h", 168)):
        if j in body:
            v = num(j)
            if not 0 <= v <= hi:
                raise ValueError("%s: 0 to %d" % (j, hi))
            ch[k] = v
    return ch


def make_advert(identity, atype, name, lat, lon):
    """A signed advert: type, position (only when set), name (cut to fit, never mid-character)."""
    flags = atype
    body = b""
    if lat or lon:
        flags |= ADV_LATLON_MASK
        body += struct.pack("<ii", int(lat * 1e6), int(lon * 1e6))
    name = str(name).encode()[:MAX_ADVERT_DATA_SIZE - 1 - len(body)]
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
    sig = identity.sign(identity.pub_key + ts + app_data)
    return Packet(PT_ADVERT, identity.pub_key + ts + sig + app_data)


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
        self.push_private = False         # the post being pushed is a private message (doesn't move sync_since)
        self.push_delivered = False       # the post being pushed was delivered (its other attempts' ACKs only credit routes)
        self.push_sent = 0.0
        self.push_hops = 0xFF
        self.attempt_no = 0               # attempts on the current post so far: picks the attempt bits (0..3, in turn)
        self.ack_map = {}                 # expected ACK -> its attempt (see push_post), kept LATE_ACK_S past its timeout
        self.routes = []                  # ProvenRoute list
        self.plan = None                  # attempt plan for the post being delivered
        self.plan_retry = False           # plan is a backoff retry (best route, then floods)
        self.inflight = None              # plan entry of the attempt in flight
        self.backoff = 0
        self.retry_at = 0.0
        self.stuck_since = 0.0
        self.given_up = False             # = suspended: no pushes until we hear from them (plus a rare probe)
        self.new_member = False
        self.next_probe = 0.0
        self.fresh = None                 # (plen, path): route reversed from where we just heard them (tried first)
        self.last_heard = 0               # any packet from them: ACKs, keepalives, logins, posts, requests, adverts
        self.obs_wake_at = -1e9           # last wake from suspension triggered by an observer sighting
        self.obs_confirmed = None         # a push an observer confirmed first: its RF ACK is still credited (2 min)
        self.suspended_at = 0             # when they were suspended (wall clock)
        self.pace_sample = None           # the push in flight counts toward the shared pace: {"p": expected, "ok": ...}
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
    TENANT = False

    def __init__(self, cfg, modem, identity, store):
        self.cfg, self.modem, self.id, self.store = cfg, modem, identity, store
        self.self_hash = identity.pub_key[0]
        self.members = {}                 # pubkey -> Member
        self.bans = {}                    # pubkey -> dict(name, ts): the room ignores them completely
        self.notices = []                 # kick/ban messages being retried until ACKed
        self.last_pushed = None           # member of the most recent push (its ACK ends the gap early)
        self.last_push_at, self.last_push_flood = 0.0, False
        self.pace = cfg.push_pace_start_ms / 1000.0       # seconds between pushes (self-adjusting)
        self.pace_hist = collections.deque(maxlen=30)      # samples: {"ok", "p" (route's rate when sent), "who"}
        self.pace_last_slow = time.monotonic()
        self.pace_last_ease = time.monotonic()
        self.inpaths = {}                 # member key8 -> {(plen, path): [w, t]}  paths their floods took to reach us
        self.obs_edges = {}               # (a, b) -> [w, t, snr]: links between known repeaters, as observers heard them
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
        self.login_fails = {}             # member key -> recent wrong passwords (monotonic): see login_failed
        self.max_issued = 0
        self.names = {}                   # key8 -> (ts, name)
        self.neighbours = {}              # pubkey -> dict(advert_ts, heard, snr4, name)
        self.seen = {}                    # packet hash -> None (insertion ordered)
        self.txq = []                     # heap (due, prio, seq, raw, ptype, is_flood, deferrable, relay, tag, class)
        self.air = Airtime(cfg, lambda: [k for k, node in (("relay", getattr(self, "vr", None)),
                                                            ("companion", getattr(self, "vc", None))) if node is None])
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
                          acks=0, late_acks=0, timeouts=0, flood_fallbacks=0, deduped=0, traces=0,
                          obs_acks=0, obs_posts=0, obs_wakes=0, delivered=0, rf_after_obs=0, obs_links=0, obs_adverts=0,
                          obs_channel=0)
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
        self.repeaters = RepeaterTable(lambda pub: self.vr is not None and pub == self.vr.pub)
        #                                   repeater pubkey -> dict(name, lat, lon, adv_ts, last_advert), at most REPEATERS_MAX
        self.nodes = {}                   # pubkey -> dict(type, name, lat, lon, adv_ts, rf, obs): every node heard
        self.nodes_dirty, self.nodes_gone = set(), set()     # advertising; rf/obs: when, by this radio / an observer
        self.heard = {}                   # repeater hash -> dict(last, w, t, last_direct, snr)
        self.next_topo_flush = time.monotonic() + 60
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
        self.web_map = {}
        self.next_map = 0.0
        self.map_shape, self.map_version = None, 0
        self.web_clients = (0, 0)         # (dashboard viewers, of which admins) in the last 15 s (set by the web thread)
        self.observer = None            # attached by main when explicitly enabled
        self.vr = None                    # VirtualRepeater while repeater_enabled
        self.vc = None                    # VirtualCompanion while companion_enabled (started by main: needs the event queue)
        self.web_vc_admin = {}
        self.tenants = {}                 # public key -> TenantRoom (main room only)
        self.bus = []                     # heap: tenants' packets, offered to the other nodes on this radio when due
        self.push_gate, self.push_turn, self.push_owner = 0.0, 0, None   # one push at a time across all rooms (one radio)
        self.web_tenants, self.web_tenant_rows = {}, []    # for the web thread: path -> TenantRoom, admin list
        self.consumed = False             # set while handling a packet that turned out to be for the room
        self.feed = None                  # ObserverFeed while MQTT augmentation is on         # (dashboard viewers, of which admins) in the last 15 s (set by the web thread)
        self.kaas = None if self.TENANT else KaasHub(self)   # API clients (websocket): the main room only
        self.web_port_active = bool(cfg.web_port)
        self.web_last_request = 0.0
        self.web_dirty = False
        self.events_q = None              # main event queue (set by main): housekeeping yields to waiting packets
        self.next_web = 0.0
        self.load()
        self.repeater_apply()

    # ------------------------------------------------------------------ persistence

    def load(self):
        st = self.store
        for row in st.read("SELECT pubkey, perms, last_timestamp, last_activity, sync_since, out_path, out_path_len, given_up, secret, "
                           "attempts_avg, deliveries, in_path, in_path_len, in_ts, last_heard, suspended_at FROM members"):
            m = Member(bytes(row[0]))
            m.perms, m.last_timestamp, m.last_activity, m.sync_since = row[1], row[2], row[3], row[4]
            m.out_path = bytes(row[5] or b"")
            m.out_path_len = row[6]
            m.given_up = bool(row[7])
            if m.given_up:                                  # suspended across a restart: probes spread over the next hour
                m.next_probe = time.monotonic() + random.uniform(1800, 3600)
            m.secret = bytes(row[8]) if row[8] else None   # saved: no modem key exchange needed after restart
            m.attempts_avg = row[9]
            m.deliveries = row[10] or 0
            m.in_path, m.in_path_len, m.in_ts = bytes(row[11] or b""), row[12], row[13] or 0
            m.last_heard = row[14] or row[3] or 0
            m.suspended_at = (row[15] or m.last_heard) if m.given_up else 0
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
        for a, b, w, t, snr in st.read("SELECT a, b, w, t, snr FROM obs_edges"):
            self.obs_edges[(bytes(a), bytes(b))] = [w, t, snr]
        for k8, plen, path, w, t in st.read("SELECT key8, plen, path, w, t FROM member_inroutes"):
            self.inpaths.setdefault(bytes(k8), {})[(plen, bytes(path))] = [w, t]
        for a, b, w, t, snr in st.read("SELECT a, b, w, t, snr FROM edges"):
            self.edges[(bytes(a), bytes(b))] = [w, t, snr]
        for pub, name, lat, lon, adv_ts, last in st.read("SELECT pubkey, name, lat, lon, adv_ts, last_advert FROM repeaters"):
            self.repeaters[bytes(pub)] = dict(name=name, lat=lat, lon=lon, adv_ts=adv_ts, last_advert=last)
        for pub, typ, name, lat, lon, adv_ts, rf, obs in st.read("SELECT pubkey, type, name, lat, lon, adv_ts, rf, obs FROM nodes"):
            self.nodes[bytes(pub)] = dict(type=typ, name=name or "", lat=lat, lon=lon, adv_ts=adv_ts or 0, rf=rf, obs=obs)
        for h, last, w, t, last_direct, snr, disc, out_snr in st.read("SELECT hash, last, w, t, last_direct, snr, disc, out_snr FROM heard"):
            self.heard[bytes(h)] = dict(last=last, w=w, t=t, last_direct=last_direct, snr=snr, disc=disc or 0, out_snr=out_snr)
        if not self.TENANT and (self.members or self.posts):
            # the main room is the host now: rooms are all Rooms (tenants). An older main room's data stays in
            # room.db, untouched, but isn't served
            log.warning("room.db still holds a room of its own (%d members, %d posts): the server hosts Rooms only "
                        "now, so they're kept in room.db but not used", len(self.members), len(self.posts))
            self.members, self.posts = {}, []
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
                int(m.given_up), m.secret, m.attempts_avg, m.deliveries, m.in_path, m.in_path_len, m.in_ts, m.last_heard,
                m.suspended_at)

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

    def radio_stats(self):
        return self.stats

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

    def queue_tx(self, pkt, prio, delay=0.0, deferrable=False, relay=False, src=None, tag=None):
        if self.vc is not None and src is None:          # (tenants' and the companion's were offered already)
            if self.vc.claims(pkt):                         # for the companion on this radio: handed over, never on the air
                if not relay:
                    self.seen_mark(pkt)
                if self.vr is not None:
                    self.vr.seen_mark(pkt)
                self.vc.deliver(pkt.copy(), delay)
                return
            self.vc.deliver(pkt.copy(), delay)              # it hears everything this radio sends
        raw = pkt.encode()
        if not relay:
            self.seen_mark(pkt)
        if self.vr is not None:
            self.vr.seen_mark(pkt)                          # the virtual repeater never relays what this radio sent
        self.txseq += 1
        heapq.heappush(self.txq, (time.monotonic() + delay, prio, self.txseq, raw, pkt.ptype, pkt.is_flood, deferrable, relay,
                                  tag, tx_class(pkt, deferrable, relay, src, tag)))

    def service_tx(self):
        now = time.monotonic()
        if now < self.tx_busy_until or not self.txq:
            return
        quiet = now - self.last_rx_mono >= self.cfg.push_quiet_ms / 1000.0
        # pushes aren't urgent: they wait for a quiet gap (floods arrive as bursts of rebroadcasts);
        # ACKs and replies go straight out. The modem's own CSMA still guards the instant of transmit.
        late = [e for e in self.txq if e[9] in TX_STALE_S and now - e[0] > TX_STALE_S[e[9]]]
        if late:                                            # relays and clients' packets the airtime limits held too long
            self.txq[:] = [e for e in self.txq if e not in late]
            heapq.heapify(self.txq)
            for e in late:
                self.air.dropped[e[9]] += 1
                if e[7] and self.vr is not None:
                    self.vr.stats["drop_airtime"] += 1
                if e[8] is not None and self.kaas is not None:
                    self.kaas.dropped(e[8], "held too long by the airtime limits (the channel is busy)")
        # within the airtime ceiling, and each class's share of it (borrowing what others leave unused)
        due = [e for e in self.txq if e[0] <= now and (quiet or not e[6]) and self.air.can(e[9], self.airtime_ms(len(e[3])))]
        if not due:
            return
        # the room's own ACKs and replies first, then the virtual repeater's relays, then pushes, then API clients';
        # within each, highest priority, then FIFO
        best = min(due, key=lambda e: (3 if e[8] is not None else 2 if e[6] else 1 if e[7] else 0, e[1], e[2]))
        self.txq.remove(best)
        heapq.heapify(self.txq)
        raw, is_flood, tag = best[3], best[5], best[8]
        self.modem.send_packet(raw)
        if self.kaas is not None:
            if tag is not None:
                self.kaas.sent(tag)
            self.kaas.publish("tx", raw)
        at = self.airtime_ms(len(raw))
        self.tx_busy_until = now + at / 1000.0 + 3.0       # cleared early by TxDone
        self.stats["sent"] += 1
        self.stats["sent_flood" if is_flood else "sent_direct"] += 1
        self.stats["airtime_ms"] += at
        self.air.charge(best[9], at)

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
        if self.vr is not None and path_len & 63:
            path, path_len = self.vr.strip_first_hops(path, path_len)    # our own repeater is this radio: skip it
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
        return make_advert(self.id, ADV_TYPE_ROOM, self.cfg.name, float(self.cfg.lat), float(self.cfg.lon))

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
        if self.kaas is not None:
            self.kaas.publish("rx", raw, snr, rssi)
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
        if pkt.ptype == PT_ADVERT:
            a = self.parse_advert(pkt)
            if a is not None:
                self.note_node(a, "rf")                     # heard on the air here (not a packet a node here made)
        consumed = self._room_rx(pkt)
        for t in self.tenants.values():
            if t.wants(pkt):
                consumed = t._room_rx(pkt.copy()) or consumed
        if self.vc is not None:
            consumed = self.vc.on_rx(pkt.copy(), raw) or consumed
        if self.vr is not None:
            self.vr.on_rx(pkt, consumed)

    def internal_rx(self, pkt):
        """A packet the virtual repeater is about to send on its last hop: the room gets it first, internally.
        True if it was for the room (then it isn't transmitted)."""
        pkt.snr, pkt.rssi = VIRTUAL_LINK_SNR, 0
        consumed = self._room_rx(pkt.copy())
        for t in self.tenants.values():
            if t.wants(pkt):
                consumed = t._room_rx(pkt.copy()) or consumed
        return consumed

    def _room_rx(self, pkt):
        """The room's own handling of a packet. Returns True if it was for the room (it decrypted as ours, or it is
        an ACK we were waiting for): the virtual repeater doesn't relay those, as firmware doesn't relay its own."""
        self.consumed = False
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
                if self.trace_reply(pkt):                    # our own neighbour trace coming back?
                    self.consumed = True
                else:
                    self.relay_trace(pkt)                    # else take part when a trace names the room as next hop
            except Exception:
                log.exception("trace")
            return self.consumed
        if pkt.is_direct and pkt.hop_count > 0:
            return False                                   # being routed via others: not for the room itself
        t = pkt.ptype
        if t == PT_ACK:
            if len(pkt.payload) >= 4 and not self.check_dup(pkt):
                self.consumed = self.process_ack(pkt.payload[:4])
        elif t == PT_MULTIPART:
            if len(pkt.payload) >= 5 and (pkt.payload[0] & 0x0F) == PT_ACK:
                tmp = Packet(PT_ACK, pkt.payload[1:])
                tmp.header = pkt.header
                if not self.check_dup(tmp):
                    self.consumed = self.process_ack(tmp.payload[:4])
        elif t in (PT_PATH, PT_REQ, PT_RESPONSE, PT_TXT_MSG):
            self.on_peer_packet(pkt)
        elif t == PT_ANON_REQ:
            self.on_anon_req(pkt)
        elif t == PT_ADVERT:
            self.on_advert(pkt)
        elif t == PT_CONTROL and pkt.is_direct and pkt.hop_count == 0:
            self.on_control(pkt)
        return self.consumed

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
                        self.consumed = True
                        self.process_ack(data[k + 1:k + 5])
                        return
        for m in [m for m in self.members.values() if m.pub[0] == p[1]]:
            data = mac_then_decrypt(self.secret_for(m), p[2:])
            if data is None:
                continue
            self.consumed = True
            self.heard_from(m)
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
        if not self.TENANT:
            return                                          # the host takes no logins: Rooms do
        if len(p) <= 1 + PUB_KEY_SIZE + 2 or self.check_dup(pkt) or p[0] != self.self_hash:
            return
        sender = p[1:1 + PUB_KEY_SIZE]
        if sender in self.bans:
            return                                          # banned: the room never answers them
        known = self.members.get(sender)
        secret = known.secret if known and known.secret else self.id.shared_secret(sender)
        data = mac_then_decrypt(secret, p[1 + PUB_KEY_SIZE:])
        if data is None:
            return
        self.consumed = True                                # addressed to the room (whatever the password)
        if len(data) < 9:
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
                self.member_active(m, pkt)
                self.mark_dirty()
        if m is None:
            if self.login_blocked(sender):
                return                                      # too many wrong passwords from this key lately: no answer
            # An empty admin password disables RF admin access; without this
            # guard, a blank login would accidentally become an admin login.
            if self.cfg.admin_password and same_text(password, self.cfg.admin_password):
                perm = PERM_ADMIN
            elif same_text(password, self.cfg.room_password):
                perm = PERM_READ_WRITE
            elif self.cfg.allow_read_only:
                perm = PERM_GUEST
            else:
                self.login_failed(sender)
                return                                      # no response: client times out
            m = self.members.get(sender) or self.put_member(sender)
            if sender_ts <= m.last_timestamp:
                return                                      # replay
            m.last_timestamp = sender_ts
            m.sync_since = sync_since
            m.pending_ack = None
            self.member_active(m, pkt)
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

    def login_blocked(self, pub):
        q = self.login_fails.get(pub)
        now = time.monotonic()
        while q and now - q[0] >= ROOM_LOGIN_FAIL_WINDOW_S:
            q.popleft()
        return bool(q) and len(q) >= ROOM_LOGIN_FAILS

    def login_failed(self, pub):
        """A wrong room / admin password from this key: after ROOM_LOGIN_FAILS in ROOM_LOGIN_FAIL_WINDOW_S, its logins
        go unanswered until they age (a key is free to make, but each try costs airtime, or a web key's send budget)."""
        self.login_fails.setdefault(pub, collections.deque(maxlen=ROOM_LOGIN_FAILS)).append(time.monotonic())
        if len(self.login_fails) > 4096:
            now = time.monotonic()
            for k in [k for k, q in self.login_fails.items() if not q or now - q[-1] >= ROOM_LOGIN_FAIL_WINDOW_S]:
                del self.login_fails[k]

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
            wait = ack_wait(n["plen"], airtime)
        else:
            self.send_flood(pkt)
            wait = ack_wait(None, airtime)
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
        self.member_active(m, pkt)
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
        hub = (self.host if self.TENANT else self).kaas
        if hub is not None:
            hub.room_post_added(self, (ts, author, text, to))
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
        self.member_active(m, pkt)
        self.mark_dirty()
        if data[4] == REQ_KEEP_ALIVE and pkt.is_direct:
            force_since = struct.unpack_from("<I", data, 5)[0] if len(data) >= 9 else 0
            if force_since:
                m.sync_since = force_since
            m.pending_ack = None                            # (the abandoned attempt's ACK still counts: ack_map)
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
            s = self.radio_stats()
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
        now = time.monotonic()
        for m in self.members.values():
            rec = m.ack_map.get(ack)
            if rec is not None and now >= rec["until"]:
                rec = None
            cur = m.pending_ack is not None and ack == m.pending_ack
            if not cur and rec is None:
                continue
            if rec is not None and rec["credited"]:
                return True                                 # this attempt's ACK again: already counted
            oc = m.obs_confirmed
            if oc and now < oc["until"] and ack in oc["acks"]:
                self.rf_after_observer(m, ack)
                return True
            if not cur and (rec["post"] != m.push_post_ts or m.push_delivered):
                self.late_credit(m, rec)                    # another attempt of a post already delivered
                return True
            self.heard_from(m)                              # their ACK: heard from them
            lat_ms = None
            if cur and m.push_sent:
                lat_ms = int((now - m.push_sent) * 1000)
                b = 5 if m.push_hops == 0xFF else min(m.push_hops, 4)
                self.lat_sum[b] += lat_ms
                self.lat_cnt[b] += 1
            self.stats["acks" if cur else "late_acks"] += 1
            if rec is not None:
                rec["credited"] = True
            entry = m.inflight if cur else rec["entry"]
            self.attempt_result(m, entry, True, lat_ms)
            if cur and m.pace_sample is not None:
                m.pace_sample["ok"] = True
                self.pace_outcome(m.pace_sample)
            elif not cur and rec["timed"] is not None:
                rec["timed"]["ok"] = True                   # a late ACK: that "timeout" was delivered after all
            m.pace_sample = None
            if cur and m.pub == self.last_pushed and self.last_push_flood:
                self.next_push = min(self.next_push, now + 0.5)   # flood ACK back: the wave is done
            if m.attempts_cur:
                self.delivery_sample(m, m.attempts_cur)
                m.deliveries += 1
                m.attempts_cur = 0
            self.stats["delivered"] += 1
            m.obs_confirmed = None
            m.pending_ack = None                            # (the other attempts' ACKs still credit their routes)
            m.inflight = None
            m.push_delivered = True
            if not m.push_private:                          # (a private message is delivered out of order)
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

    def late_credit(self, m, rec):
        """The ACK of an earlier attempt of a post that was already delivered: that route delivered too. Route credit
        (and its pace sample, if it timed out) only; the delivery itself was already counted."""
        rec["credited"] = True
        self.heard_from(m)
        self.stats["late_acks"] += 1
        self.attempt_result(m, rec["entry"], True)
        if rec["timed"] is not None:
            rec["timed"]["ok"] = True
        self.mark_dirty()

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
        vr = self.vr.pub if self.vr is not None else None
        if pkt.ptype == PT_ADVERT and len(p) > hdr and (p[hdr] & 0x0F) == ADV_TYPE_REPEATER and p[:32] != self.id.pub_key \
                and p[:32] != vr:
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
        elif pkt.ptype == PT_ADVERT and vr is not None and p[:32] == vr:
            path = vr[:sz] + path                           # our own repeater's advert, relayed back to us
            k += 1
        hashes = [path[i * sz:(i + 1) * sz] for i in range(k)]
        if vr is not None and vr[:sz] in hashes:
            # our virtual repeater is this radio: what came before it the room heard itself at the time; the
            # first repeater after it heard this radio directly
            hashes = hashes[len(hashes) - hashes[::-1].index(vr[:sz]):]
            if hashes:
                self._link(b"", hashes[0][:2], None, now_s(), self.thalf())
        if not hashes:
            return
        self._observe_hashes(hashes, sz, pkt.snr)

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
        if self.vr is not None and self.vr.trace_next_is_me(fwd):
            fwd.snr = VIRTUAL_LINK_SNR                      # next hop is our own repeater, on this radio
            self.vr.relay_trace(fwd)
            return
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
        if self.vr is not None:
            hops = [b"" if h == self.vr.pub[:2] else h for h in hops]     # our own repeater = this radio = the room
        snrs = [struct.unpack("b", bytes([b]))[0] / 4.0 for b in pkt.path[:pkt.hop_count]]
        now = now_s()
        th = self.thalf()
        done = min(len(snrs), len(hops))                    # hops completed so far
        for i in range(1, done):                            # hops[i] received it from hops[i-1] at snrs[i]
            if hops[i - 1] != hops[i]:
                self._link(hops[i - 1], hops[i], snrs[i], now, th)
        for h in hops[:done]:
            if h:
                self._touch_heard(h, direct=False)
        if done and hops[done - 1]:                         # we heard the repeater that forwarded it last
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
        for key in [k for k, e in self.obs_edges.items() if fade(e[0], e[1], now, th) < 0.05 or k[0] not in self.heard
                    or k[1] not in self.heard]:
            del self.obs_edges[key]                         # faded, or a repeater we no longer know
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

    def link_graph(self):
        """link_graph_build(), at most every LINK_GRAPH_TTL_S: rebuilding it on every route question cost tens of ms,
        and its weights fade over hours (callers only read it)."""
        now = time.monotonic()
        cached = getattr(self, "_link_graph", None)
        if cached is None or now - cached[0] >= LINK_GRAPH_TTL_S:
            cached = self._link_graph = (now, self.link_graph_build())
        return cached[1]

    def link_graph_build(self):
        """Repeater links for route suggestions: a -> {b: confidence 0..1} (b hears a). From what this radio traced
        and what the observers reported. A busy link is seen hundreds of times, so what counts is how it compares
        with a's other links: a's strongest link scores 1, one with a quarter of its traffic 0.5. Links seen only once
        or twice, weak ones (SNR below 0 dB, where known) and ones seen only the other way count for less, and every
        hop costs a little, so shorter routes win ties. b"" is this radio, a usable hop only while its virtual
        repeater relays."""
        now, th = now_s(), self.thalf()
        seen = {}                                           # (a, b) -> [weight, snr]
        for tab in (self.edges, self.obs_edges):
            for (a, b), e in tab.items():
                w = fade(e[0], e[1], now, th)
                if w < 0.05 or a == b or len(a) not in (0, 2) or len(b) not in (0, 2):
                    continue                                # (suggested paths use 2-byte ids)
                old = seen.get((a, b))
                if old is None or w > old[0]:
                    seen[(a, b)] = [w, e[2] if e[2] is not None else (old[1] if old else None)]
        strongest = {}
        for (a, b), (w, snr) in seen.items():
            strongest[a] = max(strongest.get(a, 0.0), w)
        relay = self.vr is not None and self.cfg.repeater_relay
        g = {}
        for (a, b), (w, snr) in seen.items():
            if not relay and b"" in (a, b):
                continue
            c = (1.0 - 0.5 ** w) * math.sqrt(w / strongest[a]) * ROUTE_HOP_COST
            if snr is not None and snr < 0:
                c *= max(0.5, 1.0 + snr / 30.0)
            g.setdefault(a, {})[b] = max(g.get(a, {}).get(b, 0.0), c)
            if (b, a) not in seen:
                g.setdefault(b, {})[a] = max(g.get(b, {}).get(a, 0.0), c * 0.5)
        return g

    def suggest_routes(self, src, dst, k=3, max_hops=10):
        """The k best repeater chains from a node near the src repeaters to one near the dst repeaters.
        src, dst: {repeater hash (b"" = this radio): share}. Returns [(hops, score 0..1)], best first: a score is the
        chance the ends use those repeaters times each link's confidence. Yen's k shortest paths over -log(score)."""
        g = self.link_graph()
        relay = self.vr is not None and self.cfg.repeater_relay
        src = {h: s for h, s in src.items() if s > 0 and (h or relay)}
        dst = {h: s for h, s in dst.items() if s > 0 and (h or relay)}
        S, T = ("src",), ("dst",)                           # virtual ends

        def nbrs(u, banned_nodes, banned_edges):
            if u == S:
                items = src.items()
            else:
                items = list(g.get(u, {}).items()) + ([(T, dst[u])] if u in dst else [])
            for v, c in items:
                if v not in banned_nodes and (u, v) not in banned_edges and c > 0:
                    yield v, -math.log(c)

        def shortest(start, banned_nodes, banned_edges, depth0):
            dist, prev, n_hops = {start: 0.0}, {}, {start: depth0}
            heap, seq = [(0.0, 0, start)], itertools.count(1)
            while heap:
                d, _, u = heapq.heappop(heap)
                if u == T:
                    path = [u]
                    while path[-1] != start:
                        path.append(prev[path[-1]])
                    return d, path[::-1]
                if d > dist.get(u, float("inf")):
                    continue
                for v, w in nbrs(u, banned_nodes, banned_edges):
                    hops = n_hops[u] + (0 if v == T else 1)
                    if hops > max_hops:
                        continue
                    if d + w < dist.get(v, float("inf")):
                        dist[v], prev[v], n_hops[v] = d + w, u, hops
                        heapq.heappush(heap, (d + w, next(seq), v))
            return None

        def cost(path):
            return sum(dict(nbrs(u, (), ()))[v] for u, v in zip(path, path[1:]))
        first = shortest(S, set(), set(), 0)
        if first is None:
            return []
        found, cands = [first[1]], []
        while len(found) < k:
            last = found[-1]
            for i in range(len(last) - 2):                  # spur from each node but the last real hop
                root = last[:i + 1]
                banned_edges = {(p[i], p[i + 1]) for p in found if p[:i + 1] == root}
                spur = shortest(root[-1], set(root[:-1]), banned_edges, i)
                if spur is None:
                    continue
                path = root[:-1] + spur[1]
                if path not in found and all(path != c[1] for c in cands):
                    cands.append((cost(path), path))
            if not cands:
                break
            cands.sort(key=lambda x: x[0])
            found.append(cands.pop(0)[1])
        out = []
        for path in found:
            hops = path[1:-1]
            out.append(([(self.vr.pub[:2] if h == b"" else h) for h in hops], math.exp(-cost(path))))
        return out

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
        return self.locations(m.pub[:8])

    def locations(self, k8):
        """Where a companion is: [(repeater hash or b"", share 0..1)] most likely first."""
        tab = self.mrpts.get(k8)
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
        plan = self._build_plan(m, retry)
        if m.fresh is not None:                             # just heard from them: go back the way they came, first
            plen, path = m.fresh
            m.fresh = None
            first = dict(plen=plen, path=path, score=0.9, proven=self.find_route(m, plen, path), built="fresh")
            plan = [first] + [e for e in plan if e["plen"] is None or (e["plen"], e["path"]) != (plen, path)]
        return plan

    def _build_plan(self, m, retry=False):
        """Attempts for one post: the top PLAN_ROUTES distinct routes (the rest only if they score at least 20%),
        then PLAN_FLOODS floods. Straight to the floods if nothing scores at least 35%. Retry: best route, floods."""
        floods = [dict(plen=None, path=None, score=0.0, proven=None, built=None) for _ in range(PLAN_FLOODS)]
        cands = self.candidates(m)
        if not cands or cands[0]["score"] < 0.35:
            return floods
        if retry:
            return [cands[0]] + floods
        return [cands[0]] + [c for c in cands[1:] if c["score"] >= 0.2][:PLAN_ROUTES - 1] + floods

    # ------------------------------------------------------------------ observer feed (MQTT augmentation)

    def observer_event(self, ev):
        """One relevant packet from the observer feed (already filtered and de-duplicated by its thread)."""
        k = ev[1]
        if k == "ack" and self.cfg.mqtt_ack_ingest:
            self.observer_ack(ev[2])
        elif k == "pkt":
            self.observer_packet(ev[2])
        elif k == "advert":
            self.observer_advert(ev[2], ev[3])
        elif k == "grp":
            self.observer_group(ev[2])
        elif k == "topo" and self.cfg.mqtt_topo_ingest:
            self.observer_topology(ev[2], ev[3], ev[4])
        elif k == "backlog" and self.kaas is not None:
            self.kaas.backlog_mqtt(ev[2], ev[3])

    def observer_ack(self, ack):
        """An ACK some observer heard. If it confirms one of our pushes: delivered. No route credit, no pace or
        delivery-score effect (we can't know which way it travelled); RF stays the source of all routing."""
        for n in self.notices:
            if ack == n["ack"]:
                self.notices.remove(n)
                self.stats["obs_acks"] += 1
                return True
        now = time.monotonic()
        for m in self.members.values():
            cur = m.pending_ack is not None and ack == m.pending_ack
            rec = m.ack_map.get(ack)
            late = (rec is not None and now < rec["until"] and rec["post"] == m.push_post_ts and m.push_post_ts
                    and not m.push_delivered)
            if not (cur or late):
                continue
            # keep every attempt of this post: its RF ACK may still arrive, and RF stays the source of route credit
            acks = {a: (r["entry"], False) for a, r in m.ack_map.items()
                    if r["post"] == m.push_post_ts and now < r["until"] and not r["credited"]}
            if m.pending_ack is not None:
                acks[m.pending_ack] = (m.inflight, True)
            m.obs_confirmed = dict(acks=acks, sent=m.push_sent, hops=m.push_hops, pace=m.pace_sample,
                                   attempts=m.attempts_cur, until=now + 120)
            m.push_delivered = True
            if not m.push_private:
                m.sync_since = max(m.sync_since, m.push_post_ts)
            self.drop_private(m.pub, m.push_post_ts)
            m.pending_ack, m.inflight = None, None
            m.pace_sample = None
            m.push_failures, m.plan, m.plan_retry = 0, None, False
            m.backoff, m.retry_at, m.stuck_since, m.attempts_cur = 0, 0.0, 0.0, 0
            self.stats["obs_acks"] += 1
            self.stats["delivered"] += 1                    # counted once per push, whichever confirmation came first
            log.info("delivery to %s confirmed by an observer's ACK", self.member_label(m))
            self.observer_wake(m)
            self.mark_dirty()
            return True
        return False

    def rf_after_observer(self, m, ack):
        """The RF ACK of a push an observer already confirmed: credit it exactly like any RF ACK (route, latency,
        delivery score, pace, last heard). The delivery itself was already counted."""
        oc = m.obs_confirmed
        entry, latest = oc["acks"][ack]
        rec = m.ack_map.get(ack)
        if rec is not None:
            rec["credited"] = True
        self.heard_from(m)
        lat_ms = int((time.monotonic() - oc["sent"]) * 1000) if latest and oc["sent"] else None
        self.stats["acks" if latest else "late_acks"] += 1
        self.stats["rf_after_obs"] += 1
        self.attempt_result(m, entry, True, lat_ms)
        if latest and oc["pace"] is not None:
            oc["pace"]["ok"] = True
            self.pace_outcome(oc["pace"])
        elif not latest and rec is not None and rec["timed"] is not None:
            rec["timed"]["ok"] = True
        if oc["attempts"]:
            self.delivery_sample(m, oc["attempts"])
            m.deliveries += 1
        m.obs_confirmed = None
        self.mark_dirty()

    def observer_packet(self, raw):
        """A packet addressed to the room (by its first byte) that some observer heard: verified by decrypting with
        a member's secret. Posts are stored and ACKed; path returns may carry an ACK. Its path is never used."""
        pkt = Packet.parse(raw)
        if pkt is None:
            return
        p = pkt.payload
        for m in [m for m in self.members.values() if m.pub[0] == p[1]]:
            data = mac_then_decrypt(self.secret_for(m), p[2:])
            if data is None:
                continue                                    # not theirs (or addressed to another node with our first byte)
            if pkt.ptype == PT_PATH and self.cfg.mqtt_ack_ingest and path_valid(data[0]):
                k = 1 + path_bytes(data[0])
                if k < len(data) and (data[k] & 0x0F) == PT_ACK and len(data) >= k + 5:
                    self.observer_ack(data[k + 1:k + 5])
            elif pkt.ptype == PT_TXT_MSG and self.cfg.mqtt_msg_ingest:
                self.observer_txt(m, data)
            self.observer_wake(m)
            return

    def observer_txt(self, m, data):
        if len(data) <= 5 or (data[4] >> 2) != TXT_TYPE_PLAIN or m.role == PERM_GUEST:
            return                                          # posts only (CLI commands need a reply path: RF only)
        sender_ts = struct.unpack_from("<I", data, 0)[0]
        if sender_ts < m.last_timestamp:
            return                                          # old / replayed
        is_retry = sender_ts == m.last_timestamp
        text_b = data[5:].split(b"\0", 1)[0]
        text = text_b.decode(errors="replace")
        if not is_retry and self.is_manual_resend(m, text):
            is_retry = True
        m.last_timestamp = sender_ts
        if not is_retry:
            self.store_post(m.pub, text)
            self.stats["obs_posts"] += 1
            log.info("post from %s captured by an observer: %s", self.member_label(m), text)
        ack = sha256(data[:5 + len(text_b)], m.pub)[:4]

        class _Req:                                         # (flood ACKs use the room's own path id size)
            hash_size = (int(self.cfg.path_hash_mode) or 0) + 1
        self.send_post_ack(m, ack, _Req)                    # direct if we know where they are, flood otherwise
        self.mark_dirty()

    def channel_hashes(self):
        return {h for h, _k in self.channel_keys()}

    def channel_keys(self):
        """(1-byte channel id, secret) for the channels in mqtt_channels: "Public" (the well-known key) or "#name"
        (key = first 16 bytes of SHA-256 of the name). Messages only count if they verify with the key."""
        names = tuple(self.cfg.mqtt_channels or [])
        if getattr(self, "_chan_cache", (None,))[0] != names:
            keys = []
            for n in names:
                n = (n or "").strip()
                if n.lower() == "public":
                    k = base64.b64decode("izOH6cXN6mrJ5e26oRXNcg==")
                elif n.startswith("#"):
                    k = hashlib.sha256(n.encode()).digest()[:16]
                else:
                    continue
                keys.append((hashlib.sha256(k).digest()[0], k + bytes(16)))
            self._chan_cache = (names, keys)
        return self._chan_cache[1]

    def observer_topology(self, raw, origin, snr):
        """Links between repeaters we ALREADY know, from what observers heard: flood paths (each consecutive pair),
        the observer's own reading of the last hop, and per-hop SNR in traces. Kept apart from RF data (obs_edges)
        and never used for routes; no new repeaters are added."""
        pkt = Packet.parse(raw)
        if pkt is None:
            return
        known = self.heard
        obs = origin[:2] if len(origin) >= 2 and origin[:2] in known else None
        if pkt.ptype == PT_TRACE and pkt.is_direct:
            p = pkt.payload
            if len(p) < 9:
                return
            sz = 1 << (p[8] & 3)
            hops = [p[9 + k * sz:9 + (k + 1) * sz][:2] for k in range((len(p) - 9) // sz)] if sz >= 2 else []
            for k in range(1, min(len(hops), len(pkt.path))):
                a, b = hops[k - 1], hops[k]
                if a in known and b in known and a != b:
                    self.obs_link(a, b, ((pkt.path[k] ^ 0x80) - 0x80) / 4.0)
            return
        sz = pkt.hash_size
        hops = [pkt.path[k * sz:(k + 1) * sz][:2] for k in range(pkt.hop_count)]
        for a, b in zip(hops, hops[1:]):
            if a in known and b in known and a != b:
                self.obs_link(a, b, None)
        if obs is not None and hops and hops[-1] in known and hops[-1] != obs:
            self.obs_link(hops[-1], obs, snr)               # the observer measured this one itself

    def obs_link(self, a, b, snr):
        now = now_s()
        e = self.obs_edges.get((a, b))
        if e is None:
            if len(self.obs_edges) >= 5000:
                del self.obs_edges[min(self.obs_edges, key=lambda k: self.obs_edges[k][1])]
            e = self.obs_edges[(a, b)] = [0.0, now, None]
        e[0] = fade(e[0], e[1], now, self.thalf()) + 1.0
        e[1] = now
        if snr is not None:
            e[2] = snr if e[2] is None else e[2] * 0.7 + snr * 0.3
        self.stats["obs_links"] += 1

    def observer_advert(self, raw, origin):
        """A signed advert some observer heard: names and positions (advert ingestion), where a companion is
        (half weight: first relaying repeater, or the observer itself for a zero-hop advert), and activity."""
        pkt = Packet.parse(raw)
        if pkt is None:
            return
        a = self.parse_advert(pkt)
        if a is None or a["pub"] == self.id.pub_key:
            return
        pub, atype = a["pub"], a["type"]
        if self.cfg.mqtt_advert_ingest:
            if atype == ADV_TYPE_REPEATER:
                old = self.repeaters.get(pub, {})
                if a["lat"] is not None and (old.get("lat"), old.get("lon")) != (a["lat"], a["lon"]):
                    self.next_map = 0.0
                self.repeaters[pub] = dict(name=a["name"] or old.get("name", ""),
                                           lat=a["lat"] if a["lat"] is not None else old.get("lat"),
                                           lon=a["lon"] if a["lon"] is not None else old.get("lon"),
                                           adv_ts=a["ts"], last_advert=old.get("last_advert") or now_s())
                self._rpt_idx = None
            self.note_node(a, "obs")
            if atype == ADV_TYPE_CHAT:
                if pkt.hop_count and pkt.hash_size >= 2:
                    self.observe_near(pub, pkt.path[:pkt.hash_size], weight=0.5)
                elif not pkt.hop_count and len(origin) >= 2 and origin[:2] in self.heard:
                    self.observe_near(pub, origin[:2], weight=0.5)      # right next to that observer
                if a["name"]:
                    self.learn_name(pub, a["ts"], a["name"])
            self.stats["obs_adverts"] += 1
        m = self.members.get(pub)
        if m is not None:
            self.observer_wake(m)

    def observer_group(self, raw):
        """A message on a watched channel: the sender is named in the text ("name: message"), not keyed, so it's
        only used to wake a suspended member with that name (harmless if spoofed: one extra delivery attempt)."""
        pkt = Packet.parse(raw)
        if pkt is None or len(pkt.payload) < 4:
            return
        for h, key in self.channel_keys():
            if pkt.payload[0] != h:
                continue
            data = mac_then_decrypt(key, pkt.payload[1:])
            if data is None or len(data) < 6:
                continue
            sender = data[5:].split(b"\0", 1)[0].decode(errors="replace").split(": ", 1)[0]
            for m in self.members.values():
                nm = self.names.get(m.pub[:8])
                if nm and nm[1] == sender:
                    self.stats["obs_channel"] += 1
                    self.observer_wake(m)
            return

    def observer_wake(self, m):
        """Activity monitor: a suspended member seen anywhere on the mesh resumes sync, at most once every 15
        minutes (if the room still can't reach them, the normal plan + retry suspends them again)."""
        if not self.cfg.mqtt_activity:
            return
        if m.given_up and time.monotonic() - m.obs_wake_at >= 900:
            m.obs_wake_at = time.monotonic()
            self.reset_push_state(m)
            self.round = [m.pub] + [k for k in self.round if k != m.pub]
            self.next_push = min(self.next_push, time.monotonic() + 0.1)
            self.stats["obs_wakes"] += 1
            log.info("%s seen by an observer: resuming sync", self.member_label(m))

    def mqtt_apply(self, restart=False):
        """Start or stop the observer feed to match the settings."""
        if restart and self.feed is not None:
            self.feed.stop()
            self.feed = None
        want = bool(self.cfg.mqtt_enabled and self.cfg.mqtt_host)
        if want and self.feed is None and self.events_q is not None:
            self.feed = ObserverFeed(self, self.events_q)
        elif not want and self.feed is not None:
            self.feed.stop()
            self.feed = None

    def mqtt_state(self):
        f = self.feed
        pps, rel = f.rates() if f else (0.0, 0.0)
        return dict(enabled=bool(self.cfg.mqtt_enabled), connected=bool(f and f.connected), host=self.cfg.mqtt_host,
                    port=int(self.cfg.mqtt_port), transport=self.cfg.mqtt_transport, ws_path=self.cfg.mqtt_ws_path,
                    tls=bool(self.cfg.mqtt_tls), tls_verify=bool(self.cfg.mqtt_tls_verify), topics=list(self.cfg.mqtt_topics or []),
                    error=(f.error if f else ""), pps=pps, rel_pps=rel, ack_ingest=bool(self.cfg.mqtt_ack_ingest),
                    msg_ingest=bool(self.cfg.mqtt_msg_ingest), topo_ingest=bool(self.cfg.mqtt_topo_ingest),
                    advert_ingest=bool(self.cfg.mqtt_advert_ingest), activity=bool(self.cfg.mqtt_activity),
                    channels=list(self.cfg.mqtt_channels or []), acks=self.stats["obs_acks"], posts=self.stats["obs_posts"],
                    wakes=self.stats["obs_wakes"], links=len(self.obs_edges), adverts=self.stats["obs_adverts"],
                    channel_msgs=self.stats["obs_channel"], queue_depth=(f.depth() if f else 0),
                    queue_max=int(self.cfg.mqtt_queue_max), dropped=(f.dropped if f else 0),
                    credentials_configured=bool(self.cfg.mqtt_username and self.cfg.mqtt_password),
                    diagnostics=(dict(f.diag) if f else {}),
                    subscriptions=(f.subscription_state() if f else {}),
                    subscription_error=(f.subscription_error if f else ""))

    # ------------------------------------------------------------------ virtual repeater

    def repeater_apply(self):
        """Start, stop or update the virtual repeater from the config (startup and every settings change)."""
        c = self.cfg
        if not c.repeater_enabled:
            if self.vr is not None:
                self.vr.purge()
                log.info("virtual repeater off")
            self.vr = None
            return
        if not c.repeater_key:                              # first start: a random identity, saved in the config
            while True:
                seed = os.urandom(32)
                ident = RepeaterIdentity(seed)
                if ident.pub_key[0] not in (0x00, 0xFF):    # (reserved: firmware won't import such a key)
                    break
            c.set("repeater_key", seed.hex())
            log.info("virtual repeater: new identity %s (key saved in the config)", hexs(ident.pub_key[:8]))
        try:
            ident = RepeaterIdentity(bytes.fromhex(str(c.repeater_key)))
        except ValueError as e:
            log.error("repeater_key: %s - the virtual repeater stays off until the config has its key", e)
            if self.vr is not None:
                self.vr.purge()
            self.vr = None
            return
        if self.vr is None or self.vr.pub != ident.pub_key:
            self.vr = VirtualRepeater(self, ident)
            log.info("virtual repeater %r on, id %s, %s", c.repeater_name, hexs(ident.pub_key[:2]),
                     "relaying" if c.repeater_relay else "not relaying")
        if not c.repeater_relay:
            n = self.vr.purge()
            if n:
                log.info("virtual repeater: relaying off, %d queued relay(s) dropped", n)
        lat, lon = self.vr.position()
        old = self.repeaters.get(self.vr.pub, {})
        new = dict(name=c.repeater_name, lat=lat if (lat or lon) else None, lon=lon if (lat or lon) else None,
                   adv_ts=old.get("adv_ts", 0), last_advert=old.get("last_advert", 0))
        if old and (old.get("name"), old.get("lat"), old.get("lon")) != (new["name"], new["lat"], new["lon"]):
            self.vr.next_zero_advert = min(self.vr.next_zero_advert, time.monotonic() + 3)   # tell neighbours soon
            self.next_map = 0.0
        self.repeaters[self.vr.pub] = new
        self._rpt_idx = None                                # its name labels paths that go through it

    def vr_state(self):
        c = self.cfg
        out = dict(enabled=self.vr is not None, relay=bool(c.repeater_relay), name=c.repeater_name, lat=float(c.repeater_lat or 0), lon=float(c.repeater_lon or 0),
                   scope_mode=c.repeater_scope_mode, regions=list(c.repeater_regions or []),
                   airtime_cap=c.tx_weight_relay, loop_detect=c.repeater_loop_detect,
                   advert_min=c.repeater_advert_interval_min, flood_advert_h=c.repeater_flood_advert_interval_h)
        if self.vr is not None:
            out.update(self.vr.state(), key=hexs(self.vr.pub), id=hexs(self.vr.pub[:2]))
        return out

    def companion_apply(self):
        """Start, stop or update the virtual companion from the config (startup and every settings change). Its TCP
        port is open only while it is enabled."""
        c = self.cfg
        if not c.companion_enabled:
            if self.vc is not None:
                self.vc.close()
                log.info("virtual companion off (TCP port closed)")
            self.vc = None
            return
        if not c.companion_key:                             # first start: a random identity, saved in the config
            while True:
                seed = os.urandom(32)
                if RepeaterIdentity(seed).pub_key[0] not in (0x00, 0xFF):   # (reserved hashes)
                    break
            c.set("companion_key", seed.hex())
        try:
            ident = RepeaterIdentity(bytes.fromhex(str(c.companion_key)))
        except ValueError as e:
            log.error("companion_key: %s - the virtual companion stays off until the config has its key", e)
            if self.vc is not None:
                self.vc.close()
            self.vc = None
            return
        if self.vc is None or self.vc.pub != ident.pub_key:
            if self.vc is not None:
                self.vc.close()
            self.vc = VirtualCompanion(self, ident, CompanionStore(os.path.join(c.data_dir, "companion.db")))
            log.info("virtual companion %r on, id %s", c.companion_name, hexs(ident.pub_key[:2]))
            try:                                            # introduce the Rooms (and repeater) and the companion to each other
                for t in list(self.tenants.values()):
                    self.vc.deliver(t.make_advert())
                if self.vr is not None:
                    lat, lon = self.vr.position()
                    self.vc.deliver(make_advert(self.vr.id, ADV_TYPE_REPEATER, c.repeater_name, lat, lon))
                adv = self.vc.make_self_advert()
                adv.header = (adv.header & ~0x03) | ROUTE_DIRECT
                adv.snr = VIRTUAL_LINK_SNR
                self._room_rx(adv)
            except Exception as e:
                log.warning("virtual companion: introductions failed: %s", e)
        self.vc.listen()

    def companion_tx(self, pkt, prio):
        """A packet from the virtual companion. The room hears it first, internally (and the virtual repeater, for
        traces and discovery); it goes on the air unless it was only for them."""
        consumed = self.offer(pkt, self.vc)
        if consumed and (pkt.is_flood or pkt.hop_count == 0 or pkt.ptype == PT_TRACE):
            self.vc.stats["internal_out"] += 1
            return
        self.queue_tx(pkt, prio, 0.0, src="vc")

    def companion_event(self, ev):
        """vc_conn / vc_disc / vc_cmd from the TCP threads, and vc_cfg from the dashboard."""
        if ev[0] == "vc_cfg":
            for k, v in ev[1].items():
                self.cfg.set(k, v)
            self.companion_apply()
        elif self.vc is not None:
            self.vc.app_event(ev)
        if ev[0] != "vc_cmd":
            self.web_dirty = True                           # (not per command: an app syncing sends hundreds)

    def vc_state(self):
        """For everyone viewing the dashboard: no addresses (those are in vc_admin_state)."""
        c = self.cfg
        out = dict(enabled=self.vc is not None, name=c.companion_name, port=c.companion_port,
                   auto_advert=bool(c.companion_auto_advert), advert_min=c.companion_advert_interval_min,
                   advert_flood=bool(c.companion_advert_flood))
        if self.vc is not None:
            out.update(self.vc.state(), key=hexs(self.vc.pub), id=hexs(self.vc.pub[:2]))
        return out

    def vc_admin_state(self):
        link = self.vc.link if self.vc is not None else None
        return dict(bind=self.cfg.companion_bind, allow=list(self.cfg.companion_allow or []),
                    client=link.peer if link is not None else None)

    # ------------------------------------------------------------------ the other nodes on this radio

    def offer(self, pkt, src):
        """A packet from a node on this radio (a tenant room or the companion): every other node here hears it first,
        internally (and the virtual repeater takes traces and discovery meant for it). True if it was for one of them;
        then it doesn't go on the air."""
        rx = pkt.copy()
        rx.snr, rx.rssi = VIRTUAL_LINK_SNR, 0
        consumed = False
        if src is not self:
            consumed = self._room_rx(rx.copy())
        for t in list(self.tenants.values()):
            if t is not src and t.wants(rx):
                consumed = t._room_rx(rx.copy()) or consumed
        vc = self.vc
        if vc is not None and src is not vc:
            if vc.claims(pkt):
                consumed = True
            vc.deliver(pkt.copy())
        t, p = pkt.ptype, pkt.payload
        if t == PT_TRACE and pkt.is_direct and len(p) >= 9:
            es = 1 << (p[8] & 3)
            nxt = p[9 + pkt.path_len * es:9 + (pkt.path_len + 1) * es]
            if nxt == self.id.pub_key[:es] or any(nxt == x.id.pub_key[:es] for x in self.tenants.values() if x is not src):
                consumed = True                             # its first hop is a room here: relayed (or not) by it
            elif self.vr is not None and nxt == self.vr.pub[:es]:
                v = pkt.copy()
                v.snr = VIRTUAL_LINK_SNR
                self.vr.on_rx(v, False)
                consumed = True
        elif t == PT_CONTROL and self.vr is not None:
            v = pkt.copy()
            v.snr = VIRTUAL_LINK_SNR
            self.vr.on_rx(v, consumed)                      # e.g. node discovery: the repeater next to it answers
        return consumed

    def bus_send(self, src, pkt, prio, delay, deferrable):
        self.txseq += 1
        heapq.heappush(self.bus, (time.monotonic() + delay, self.txseq, src, pkt, prio, deferrable))

    def service_bus(self):
        """Tenant rooms' packets, when due: offered here first, then on the air unless they were only for us."""
        now = time.monotonic()
        while self.bus and self.bus[0][0] <= now:
            _, _, src, pkt, prio, deferrable = heapq.heappop(self.bus)
            if self.tenants.get(src.id.pub_key) is not src:
                continue                                    # (the room was deleted)
            if self.offer(pkt, src) and (pkt.is_flood or pkt.hop_count == 0 or pkt.ptype == PT_TRACE):
                continue
            self.queue_tx(pkt, prio, 0.0, deferrable, src=src)

    def push_rooms(self):
        """Every room on this radio shares its airtime: one push at a time, rooms taking turns."""
        now = time.monotonic()
        rooms = [self] + list(self.tenants.values())
        owner = self.push_owner
        gate_open = now >= self.push_gate or (owner is not None and owner.flood_gap_done(now))
        start = self.push_turn % len(rooms)
        for i in range(len(rooms)):
            r = rooms[(start + i) % len(rooms)]
            if r.push_tick(allow=gate_open):
                gate_open = False
                self.push_gate, self.push_owner = r.next_push, r
                self.push_turn = (start + i + 1) % len(rooms)

    # ------------------------------------------------------------------ tenant rooms

    def tenant_db(self, key_hex):
        return os.path.join(self.cfg.data_dir, TENANT_DIR, key_hex + ".db")

    def tenants_load(self):
        """Start the tenant rooms listed in the config (startup)."""
        for e in list(self.cfg.tenant_rooms or []):
            try:
                pub = bytes.fromhex(str(e["public_key"]))
                path = self.tenant_db(hexs(pub))
                if not os.path.exists(path):
                    log.error("tenant room %r: its database %s is missing - not started", e.get("name"), path)
                    continue
                t = TenantRoom(self, Store(path))
                if t.id.pub_key != pub:
                    log.error("tenant room %r: the key in %s doesn't match the config - not started", e.get("name"), path)
                    t.store.close()
                    continue
                self.tenants[pub] = t
                log.info("tenant room %r on /%s/, id %s, %d members", t.cfg.name, t.cfg.path, hexs(pub[:2]), len(t.members))
            except (KeyError, ValueError, TypeError, sqlite3.Error) as ex:
                log.error("tenant room %r: %s - not started", e.get("name") if isinstance(e, dict) else e, ex)
        self.tenants_changed()

    def tenants_changed(self):
        self.web_tenants = {t.cfg.path: t for t in self.tenants.values()}
        self.web_tenant_rows = [t.admin_row() for t in self.tenants.values()]
        self.web_dirty = True

    def tenant_create(self, spec):
        if len(self.tenants) >= TENANT_MAX:
            return log.error("tenant room %r not created: the limit is %d rooms", spec["name"], TENANT_MAX)
        if spec["path"] in {t.cfg.path for t in self.tenants.values()}:
            return log.error("tenant room %r not created: path /%s/ is taken", spec["name"], spec["path"])
        taken = self.own_node_keys()
        if spec["private_key"]:
            key = bytes.fromhex(spec["private_key"])
        else:
            while True:                                     # a random identity (not a reserved or used hash)
                key = os.urandom(32)
                pub = RepeaterIdentity(key).pub_key
                if pub[0] not in (0x00, 0xFF) and pub not in taken:
                    break
        ident = RepeaterIdentity(key)
        if ident.pub_key in taken:
            return log.error("tenant room %r not created: its key is already used here", spec["name"])
        os.makedirs(os.path.join(self.cfg.data_dir, TENANT_DIR), mode=0o700, exist_ok=True)
        path = self.tenant_db(hexs(ident.pub_key))
        for f in (path, path + "-wal", path + "-shm"):      # (left over from an earlier room with this key)
            if os.path.exists(f):
                os.remove(f)
        store = Store(path)
        tcfg = TenantConfig(self.cfg, store)
        for k in ("name", "path", "room_password", "admin_password", "web_password_hash"):
            tcfg.set(k, spec[k])
        tcfg.set("lat", float(spec.get("lat") or 0.0))
        tcfg.set("lon", float(spec.get("lon") or 0.0))
        tcfg.set("private_key", key.hex())
        t = TenantRoom(self, store, tcfg)
        t.next_zero_advert, t.next_flood_advert = time.monotonic() + 3, time.monotonic() + 10   # announce it now
        self.tenants[ident.pub_key] = t
        if self.vc is not None:
            self.vc.deliver(t.make_advert())                # (the companion's app lists it at once)
        self.cfg.set("tenant_rooms", list(self.cfg.tenant_rooms or []) +
                     [dict(name=spec["name"], path=spec["path"], public_key=hexs(ident.pub_key))])
        log.info("tenant room %r created on /%s/, id %s", spec["name"], spec["path"], hexs(ident.pub_key[:2]))
        self.tenants_changed()

    def tenant_delete(self, pub):
        """Remove a tenant room and erase everything it kept (members, posts, settings, key)."""
        t = self.tenants.pop(pub, None)
        if t is None:
            return
        t.store.close()
        path = self.tenant_db(hexs(pub))
        for f in (path, path + "-wal", path + "-shm"):
            try:
                os.remove(f)
            except FileNotFoundError:
                pass
        self.cfg.set("tenant_rooms", [e for e in (self.cfg.tenant_rooms or []) if str(e.get("public_key", "")).upper() != hexs(pub)])
        if self.push_owner is t:
            self.push_owner = None
        log.info("tenant room %r deleted (%d members, %d posts erased)", t.cfg.name, len(t.members), len(t.posts))
        self.tenants_changed()

    def tenant_event(self, ev):
        """t_create / t_delete / t_webpw / t_loc from the main admin, t_act / t_say / t_advert from a tenant's page."""
        kind = ev[0]
        if kind == "t_create":
            return self.tenant_create(ev[1])
        t = self.tenants.get(bytes.fromhex(ev[1]))
        if t is None:
            return
        if kind == "t_delete":
            self.tenant_delete(t.id.pub_key)
        elif kind == "t_webpw":
            t.cfg.set("web_password_hash", ev[2])
            log.info("tenant room %r: web UI password reset", t.cfg.name)
        elif kind == "t_loc":
            t.cfg.set("lat", ev[2])
            t.cfg.set("lon", ev[3])
            now = time.monotonic()                          # tell neighbours and the maps soon
            t.next_zero_advert, t.next_flood_advert = min(t.next_zero_advert, now + 3), min(t.next_flood_advert, now + 10)
            self.tenants_changed()
            log.info("tenant room %r: location set to %s, %s", t.cfg.name, ev[2], ev[3])
        elif kind == "t_say":
            t.room_say(ev[2])
        elif kind == "t_welcome":
            for k, v in ev[2].items():
                t.cfg.set(k, v)
            log.info("room %r: welcome DM settings changed", t.cfg.name)
        elif kind == "t_advert":
            t.dashboard_advert(ev[2])
        elif kind == "t_act":
            verb, pub = ev[2], ev[3]
            if verb == "suggest":
                t.suggest_route(pub, ev[4])
            elif verb == "resync":
                t.force_resync(pub)
            elif verb in ("kick", "ban", "unban"):
                getattr(t, verb)(pub)
        t.web_dirty = True
        t.next_web = 0.0

    def heard_from(self, m):
        """Any packet we can attribute to m: the 'Last heard' time (saved with the member)."""
        m.last_heard = now_s()
        self.mark_dirty()

    def member_active(self, m, pkt):
        """We just heard from m. If they were struggling or suspended, resume at once: front of the queue, and the
        first attempt goes back the way this packet came (they may have moved)."""
        self.heard_from(m)
        struggling = m.given_up or m.stuck_since or (m.plan is not None and m.push_failures > 0)
        was_suspended = m.given_up
        self.reset_push_state(m)
        if not struggling:
            return
        m.fresh = self.fresh_route_from(m, pkt)
        if self.unsynced_count(m):
            self.round = [m.pub] + [k for k in self.round if k != m.pub]
            self.next_push = min(self.next_push, time.monotonic() + 0.3)
        log.info("%s %s: heard from them, first try %s", "resuming" if was_suspended else "retrying", self.member_label(m),
                 "flood" if m.fresh is None else " > ".join(self.path_names(*m.fresh) or ["direct"]))

    def fresh_route_from(self, m, pkt):
        """Route back to m from the packet we just heard: a flood carries their path (reverse it); a direct packet
        means their stored route to us works (reverse that); none if we know neither."""
        if pkt is not None and pkt.is_flood:
            sz, k = pkt.hash_size, pkt.hop_count
            hops = [pkt.path[i * sz:(i + 1) * sz] for i in range(k)]
            return (((sz - 1) << 6) | k, b"".join(reversed(hops)))
        if m.in_ts and m.in_path_len is not None:
            sz, k = (m.in_path_len >> 6) + 1, m.in_path_len & 63
            hops = [m.in_path[i * sz:(i + 1) * sz] for i in range(k)]
            return (m.in_path_len, b"".join(reversed(hops)))
        return None

    def reset_push_state(self, m):
        m.push_failures = 0
        m.plan, m.plan_retry = None, False
        m.backoff, m.retry_at, m.stuck_since = 0, 0.0, 0.0
        if m.given_up:
            m.given_up = False
            m.suspended_at = 0
            self.mark_dirty()

    def push_eligible(self, m):
        if m.pending_ack is not None or m.last_activity == 0:
            return False
        if m.given_up:                                      # suspended: only the rare probe
            return time.monotonic() >= m.next_probe
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

    def pace_outcome(self, sample):
        """Shared push pace. Each counted push carries the success rate its route had when it was sent, so the window
        is judged against what those routes normally deliver: distance alone never looks like congestion. Slow down
        only when deliveries fall well below that baseline AND the channel is genuinely busy; recover otherwise."""
        self.pace_hist.append(sample)
        lo, hi = self.cfg.push_pace_min_ms / 1000.0, self.cfg.push_pace_max_ms / 1000.0
        n = len(self.pace_hist)
        if n < 12 or len({x["who"] for x in self.pace_hist}) < 2:
            return                                          # not enough evidence (and no single member can swing it)
        delivered = sum(1 for x in self.pace_hist if x["ok"])
        expected = sum(x["p"] for x in self.pace_hist)
        busy = self.channel_use(5)
        if delivered < 0.75 * expected and busy >= 15.0:
            old = self.pace
            self.pace = min(self.pace * 1.5, hi)
            self.pace_hist.clear()                          # judge the new pace on fresh evidence
            self.pace_last_slow = self.pace_last_ease = time.monotonic()
            if self.pace != old:
                log.info("push pace %.1f s -> %.1f s (delivered %d of %d, routes would normally deliver %.1f; channel use %.0f%%)",
                         old, self.pace, delivered, n, expected, busy)
        elif sample["ok"] and delivered >= 0.95 * expected:
            self.pace = max(self.pace - 0.1, lo)

    def pace_ease(self):
        """Every 3 minutes without a slowdown, ease 20% back toward the minimum, so the pace can never stick at the top."""
        now = time.monotonic()
        lo = self.cfg.push_pace_min_ms / 1000.0
        if self.pace > lo and now - self.pace_last_slow >= 180 and now - self.pace_last_ease >= 180:
            old = self.pace
            self.pace = max(lo, self.pace * 0.8)
            self.pace_last_ease = now
            log.info("push pace %.1f s -> %.1f s (no congestion for 3+ min)", old, self.pace)

    def channel_use(self, minutes):
        """The room's measured channel use (TX + RX airtime), % over the last few minutes."""
        ms = list(self.minutes)[-minutes:]
        if not ms:
            return 0.0
        return 100.0 * sum(x["tx_ms"] + x["rx_ms"] for x in ms) / (len(ms) * 60000.0)

    def flood_gap_done(self, now):
        """After a flooded push, stop waiting once the rebroadcast wave around us has passed: at least 2 s, and the
        channel quiet for push_quiet_ms (rebroadcasts we hear keep resetting that). push_gap_flood_ms stays the cap."""
        q = self.cfg.push_quiet_ms / 1000.0
        return (self.last_push_flood and q > 0 and now - self.last_push_at >= 2.0 and now - self.last_rx_mono >= q
                and now - self.last_push_at >= q)

    def gap_for(self, hops):
        """Wait after a push: the shared pace for direct routes; floods wait out their rebroadcast wave (capped)."""
        if hops == 0xFF:
            return self.cfg.push_gap_flood_ms / 1000.0
        return self.pace

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
            if m.ack_map:
                for a in [a for a, r in m.ack_map.items() if now >= r["until"]]:
                    del m.ack_map[a]
            if m.pending_ack is None or now < m.ack_timeout:
                continue
            entry = m.inflight
            rec = m.ack_map.get(m.pending_ack)              # (its late ACK still counts until rec["until"])
            m.push_failures += 1
            m.pending_ack = None
            m.inflight = None
            self.stats["timeouts"] += 1
            self.attempt_result(m, entry, False)
            if m.pace_sample is not None:
                m.pace_sample["ok"] = False
                if rec is not None:
                    rec["timed"] = m.pace_sample            # kept: a late ACK can still correct it
                self.pace_outcome(m.pace_sample)
                m.pace_sample = None
            if m.plan is not None and m.push_failures >= len(m.plan):
                if m.attempts_cur:                          # undelivered after all of them: a bad sample
                    self.delivery_sample(m, m.attempts_cur + 1)
                    m.attempts_cur = 0
                if m.given_up:                              # a suspended probe went unanswered
                    m.next_probe = now + SUSPENDED_PROBE_S
                elif not m.plan_retry:                      # the plan failed: one retry a minute from now
                    m.stuck_since = m.stuck_since or now
                    m.retry_at = now + RETRY_BEFORE_SUSPEND_S
                else:                                       # the retry failed too: suspend until we hear from them
                    m.given_up = True
                    m.suspended_at = now_s()
                    m.next_probe = now + SUSPENDED_PROBE_S
                    log.info("suspending %s: no ACK on the plan or its retry; resuming when we hear from them", self.member_label(m))
            self.mark_dirty()

    # ------------------------------------------------------------------ push loop

    def push_tick(self, allow=True):
        """One step of the push round. allow=False (another room on this radio is pushing): only check ACK timeouts.
        Returns True if it pushed."""
        now = time.monotonic()
        if not self.members:
            return False
        if now < self.next_push and not self.flood_gap_done(now):
            return False
        self.check_ack_timeouts()
        if not allow:
            return False
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
            mine = next((p for p in self.posts if p[3] == m.pub), None)
            if mine is not None:
                # private messages (the welcome DM) go first, before any catch-up history. They're stamped just before
                # the first history post (so apps list them first too) and delivering one doesn't move sync_since
                # (that would skip the history)
                ts, author, text, _ = mine
                first = next((p[0] for p in self.posts if p[3] is None and p[0] > m.sync_since and p[1][:4] != m.pub[:4]), None)
                self.push_post(m, ts, author, text, wire_ts=min(ts, first - 1) if first else ts)
                did_push = True
            else:
                for ts, author, text, to in self.posts:
                    if t >= ts + POST_SYNC_DELAY_SECS and ts > m.sync_since and to is None and author[:4] != m.pub[:4]:
                        self.push_post(m, ts, author, text)
                        did_push = True
                        break
        self.next_push = now + (self.gap_for(m.push_hops) if did_push else SYNC_SKIP_INTERVAL)
        if did_push:
            self.last_pushed = m.pub
            self.last_push_at = now
            self.last_push_flood = m.push_hops == 0xFF
        return did_push

    def push_post(self, m, ts, author, text, wire_ts=None):
        if ts != m.push_post_ts:
            m.attempt_no = 0                                # different post: attempt bits start again at 0
            m.push_delivered = False
            if not m.plan_retry or m.plan is None:
                m.plan, m.push_failures = None, 0
        if m.given_up:                                      # suspended probe: a single flood
            m.plan, m.plan_retry, m.push_failures = [dict(plen=None, path=None, score=0.0, proven=None, built=None)], True, 0
        elif m.plan is None:
            m.plan, m.plan_retry, m.push_failures = self.build_plan(m), False, 0
        elif m.push_failures >= len(m.plan):                # the one retry: best route, then floods
            m.plan, m.plan_retry, m.push_failures = self.build_plan(m, retry=True), True, 0
        entry = m.plan[m.push_failures]
        r_ = entry.get("proven")
        online = now_s() - max(m.last_heard or 0, m.last_activity or 0) < 900
        first = m.push_failures == 0 and not m.plan_retry
        local = entry["plen"] is not None and path_hops(entry["plen"]) <= PACE_MAX_HOPS
        m.pace_sample = (dict(ok=None, p=max(0.05, min(0.95, r_.rate(now_s(), self.rhalf()))), who=m.pub[:4])
                         if (online and first and not m.given_up and local and r_ is not None) else None)
        m.attempts_cur += 1
        # the attempt bits count 0, 1, 2, 3, 0...: each of a post's 4 possible ACKs names its latest attempt
        data = struct.pack("<I", ts if wire_ts is None else wire_ts) + bytes([(TXT_TYPE_SIGNED_PLAIN << 2) | (m.attempt_no & 3)]) \
            + author[:4] + text.encode()
        m.attempt_no += 1
        m.pending_ack = sha256(data, m.pub)[:4]
        m.push_post_ts = ts
        m.push_private = any(p[0] == ts and p[3] is not None for p in self.posts)
        m.push_sent = time.monotonic()
        m.inflight = entry
        plen, path = entry["plen"], entry["path"]
        m.push_hops = path_hops(plen)
        pkt = self.make_datagram(PT_TXT_MSG, m.pub, self.secret_for(m), data)
        airtime = self.airtime_ms(pkt.raw_length() + (path_bytes(plen) if plen is not None else 0))
        wait = ack_wait(plen, airtime)
        if plen is None:
            self.send_flood(pkt, deferrable=True)
        else:
            self.send_direct(pkt, path, plen, deferrable=True)
            r = entry["proven"]
            if r is not None and r.lat_n >= 3:              # learned from this route's own ACK times
                wait = min(max(3.0, r.lat * 2.5 / 1000.0 + 1.5), wait * 1.5)
        m.ack_timeout = time.monotonic() + wait
        m.ack_map[m.pending_ack] = dict(entry=entry, post=ts, until=m.ack_timeout + LATE_ACK_S, timed=None, credited=False)
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
            if lat is not None and (old_r.get("lat"), old_r.get("lon")) != (lat, lon):
                self.next_map = 0.0                         # new or moved on the map: rebuild the map part now
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
            if m:
                self.heard_from(m)                          # flood or zero-hop advert: they're on the air
            if m and (m.given_up or m.push_failures > 0 or m.stuck_since) and m.pending_ack is None:
                self.member_active(m, pkt)                  # signed advert: they're on the air
                if m.last_activity == 0:
                    m.last_activity = now_s()
                self.mark_dirty()
            if name:
                self.learn_name(pub, ts, name)

    @staticmethod
    def parse_advert(pkt):
        """Signed advert -> dict(pub, ts, type, name, lat, lon), or None if malformed or the signature fails."""
        p = pkt.payload
        if len(p) < PUB_KEY_SIZE + 4 + SIGNATURE_SIZE:
            return None
        pub, ts, sig = p[:32], struct.unpack_from("<I", p, 32)[0], p[36:100]
        app = p[100:100 + MAX_ADVERT_DATA_SIZE]
        if not app or not ed25519_verify(pub, sig, pub + p[32:36] + app):
            return None
        flags, i = app[0], 1
        lat = lon = None
        if flags & ADV_LATLON_MASK:
            if len(app) < 9:
                return None
            la, lo = struct.unpack_from("<ii", app, 1)
            if la or lo:
                lat, lon = la / 1e6, lo / 1e6
            i += 8
        if flags & ADV_FEAT1_MASK:
            i += 2
        if flags & ADV_FEAT2_MASK:
            i += 2
        if len(app) < i:
            return None
        name = app[i:].split(b"\0", 1)[0].decode(errors="replace") if flags & ADV_NAME_MASK else ""
        name = "".join(c if ord(c) >= 0x20 else " " for c in name)
        return dict(pub=pub, ts=ts, type=flags & 0x0F, name=name, lat=lat, lon=lon)

    def learn_name(self, pub, ts, name):
        """Companion name cache: newer adverts win; members are never evicted."""
        k8 = pub[:8]
        old = self.names.get(k8)
        if old and ts <= old[0]:
            return
        if not old and len(self.names) >= NAME_CACHE_MAX:
            members8 = {mm.pub[:8] for mm in self.members.values()}
            cands = [k for k in self.names if k not in members8]
            if not cands:
                return
            del self.names[min(cands, key=lambda k: self.names[k][0])]
        self.names[k8] = (ts, name)
        self.mark_dirty()

    def note_node(self, a, via):
        """A signed advert (parse_advert's dict), heard on this radio (via "rf") or by an MQTT observer ("obs"):
        the node directory. Name and position come from its newest advert; rf/obs say when it was last heard."""
        pub = a["pub"]
        if pub in self.own_node_keys():
            return
        n = self.nodes.get(pub)
        if n is None:
            if len(self.nodes) >= NODES_MAX:
                old = min(self.nodes, key=lambda k: max(self.nodes[k]["rf"] or 0, self.nodes[k]["obs"] or 0))
                del self.nodes[old]
                self.nodes_dirty.discard(old)
                self.nodes_gone.add(old)
            n = self.nodes[pub] = dict(type=a["type"], name="", lat=None, lon=None, adv_ts=-1, rf=None, obs=None)
            self.nodes_gone.discard(pub)
        if a["ts"] >= n["adv_ts"]:
            n.update(type=a["type"], name=a["name"] or n["name"], adv_ts=a["ts"])
            if a["lat"] is not None:
                n["lat"], n["lon"] = a["lat"], a["lon"]
        n[via] = now_s()
        self.nodes_dirty.add(pub)

    def observer_choices(self):
        """Who the MQTT observer may report as: the virtual repeater (while on) or a room."""
        out = [dict(id="repeater", label="Virtual repeater: %s" % self.cfg.repeater_name, key=hexs(self.vr.pub))] \
            if self.vr is not None else []
        return out + [dict(id=hexs(t.id.pub_key), label="Room: %s" % t.cfg.name, key=hexs(t.id.pub_key))
                      for t in list(self.tenants.values())]

    def observer_who(self):
        """(identity, name) the observer reports as, or None while what was chosen doesn't exist."""
        sel = str(self.cfg.observer_identity or "")
        if sel == "repeater":
            return (self.vr.id, self.cfg.repeater_name) if self.vr is not None else None
        try:
            t = self.tenants.get(bytes.fromhex(sel)) if sel else None
        except ValueError:
            t = None
        return (t.id, t.cfg.name) if t is not None else None

    def own_node_keys(self):
        """Every node identity this server has: the room, tenants, and the virtual repeater and companion (their
        configured keys too, while they're off: turning one back on mustn't give two nodes one key)."""
        keys = {self.id.pub_key} | {t.id.pub_key for t in self.tenants.values()}
        if self.vr is not None:
            keys.add(self.vr.pub)
        if self.vc is not None:
            keys.add(self.vc.pub)
        for k in (self.cfg.repeater_key, self.cfg.companion_key):
            try:
                keys.add(RepeaterIdentity(bytes.fromhex(str(k))).pub_key) if k else None
            except ValueError:
                pass
        return keys

    def heard_on_rf(self, pub, trust_observers=False):
        """When this radio last heard the node advertise (or an observer did, if trusted), or None. Any thread."""
        n = self.nodes.get(bytes(pub))
        if n is None:
            return None
        return n["rf"] or (n["obs"] if trust_observers else None)

    def node_by_name(self, name):
        """key8 of the node advertising this name (ignoring case). Several: the one with known repeaters, then the
        newest advert."""
        want = name.casefold()
        hits = [k for k, (ts, nm) in self.names.items() if nm.strip().casefold() == want]
        return max(hits, key=lambda k: (bool(self.mrpts.get(k)), self.names[k][0]), default=None)

    def dashboard_advert(self, flood, node="repeater"):
        """The host dashboard's advert buttons: the virtual repeater's or the companion's (a room's page sends the
        room's)."""
        n = self.vr if node == "repeater" else self.vc if node == "companion" else None
        if n is not None:
            n.send_advert(flood)
            log.info("virtual %s: %s sent from the dashboard", node, "flood advert" if flood else "advert (zero-hop)")

    def send_advert(self, flood):
        if not self.TENANT:
            return                                          # the host isn't a room: only Rooms advertise
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
                        "push.pace": "now %.1fs (min %sms, max %sms), flood gap %sms" % (self.pace, c.push_pace_min_ms, c.push_pace_max_ms, c.push_gap_flood_ms)}
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
                elif k in ("push.pace.min", "push.pace.max", "push.pace.start"):
                    c.set("push_pace_%s_ms" % k.split(".")[-1], max(500, min(60000, int(v))))
                elif k == "push.gap.flood":
                    c.set("push_gap_flood_ms", max(0, min(120000, int(v))))
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
        if self.vr is not None:
            self.vr.periodic()
        if self.vc is not None:
            self.vc.periodic()
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
            self.next_topo_flush = now + 60
        self.pace_ease()
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
            self.next_web = now + 1
            if now >= self.next_map:
                self.publish_map()                           # the slow part: every 30 s
                self.next_map = now + 30
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
        oe_rows = [(a, b, e[0], e[1], e[2]) for (a, b), e in self.obs_edges.items()]
        ed_rows = [(a, b, e[0], e[1], e[2]) for (a, b), e in self.edges.items()]
        rp_rows = [(pub, r["name"], r["lat"], r["lon"], r["adv_ts"], r["last_advert"]) for pub, r in self.repeaters.items()]
        hd_rows = [(h, d["last"], d["w"], d["t"], d["last_direct"], d["snr"], d.get("disc", 0), d.get("out_snr")) for h, d in self.heard.items()]
        nd_rows = [(pub, n["type"], n["name"], n["lat"], n["lon"], n["adv_ts"], n["rf"], n["obs"])
                   for pub, n in ((k, self.nodes.get(k)) for k in self.nodes_dirty) if n is not None]
        nd_gone = [(pub,) for pub in self.nodes_gone]
        self.nodes_dirty, self.nodes_gone = set(), set()
        self.store.execmany([
            ("DELETE FROM nodes WHERE pubkey = ?", nd_gone), ("INSERT OR REPLACE INTO nodes VALUES (?,?,?,?,?,?,?,?)", nd_rows),
            ("DELETE FROM rpt_routes", None), ("INSERT OR REPLACE INTO rpt_routes VALUES (?,?,?,?,?,?,?)", rr_rows),
            ("DELETE FROM member_rpts", None), ("INSERT OR REPLACE INTO member_rpts VALUES (?,?,?,?)", mr_rows),
            ("DELETE FROM member_inroutes", None), ("INSERT OR REPLACE INTO member_inroutes VALUES (?,?,?,?,?)", ir_rows),
            ("DELETE FROM obs_edges", None), ("INSERT OR REPLACE INTO obs_edges VALUES (?,?,?,?,?)", oe_rows),
            ("DELETE FROM edges", None), ("INSERT OR REPLACE INTO edges VALUES (?,?,?,?,?)", ed_rows),
            ("DELETE FROM repeaters", None), ("INSERT OR REPLACE INTO repeaters VALUES (?,?,?,?,?,?)", rp_rows),
            ("DELETE FROM heard", None), ("INSERT OR REPLACE INTO heard (hash, last, w, t, last_direct, snr, disc, out_snr) VALUES (?,?,?,?,?,?,?,?)", hd_rows),
        ])

    # ------------------------------------------------------------------ per-minute stats (dashboard header)

    def record_metric(self):
        """Once a minute: deltas of the counters + noise-floor range, kept in memory for the dashboard header."""
        s = self.stats
        cur = (s["recv"], s["sent"], s["airtime_ms"], self.rx_airtime_ms, s["pushes"], s["acks"] + s["late_acks"], s["delivered"])
        prev = self.metric_prev or cur
        self.metric_prev = cur
        if len(prev) != len(cur):
            prev = cur
        rx, tx, tx_ms, rx_ms, pushes, acks, delivered = [c - p for c, p in zip(cur, prev)]
        self.minutes.append(dict(nf=self.noise_floor, nf_min=self.m_nf_min or self.noise_floor, nf_max=self.m_nf_max or self.noise_floor,
                                 rx=rx, tx=tx, tx_ms=tx_ms, rx_ms=rx_ms, pushes=pushes, acks=acks, delivered=delivered))
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
        delivered = sum(x.get("delivered", x["acks"]) for x in ms)
        return dict(minutes=n,
                    nf_avg=round(sum(nfs) / len(nfs)) if nfs else None,
                    nf_min=min((x["nf_min"] for x in ms if x["nf_min"]), default=None),
                    nf_max=max((x["nf_max"] for x in ms if x["nf_max"]), default=None),
                    tx_pct=round(100.0 * sum(x["tx_ms"] for x in ms) / (n * 60000.0), 1),
                    rx_pct=round(100.0 * sum(x["rx_ms"] for x in ms) / (n * 60000.0), 1),
                    rx_pm=round(sum(x["rx"] for x in ms) / n, 1), tx_pm=round(sum(x["tx"] for x in ms) / n, 1),
                    pushes_pm=round(pushes / n, 1), push_ok=round(100.0 * min(delivered, pushes) / pushes) if pushes else None,
                    push_rf=round(100.0 * min(acks, pushes) / pushes) if pushes else None,
                    pace=round(self.pace, 1))

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

    def publish_map(self):
        """The slow-changing part of the dashboard (repeater list, detail panes, map links), rebuilt every 30 s while
        someone's watching. Only the repeaters actually sent get their routes and neighbour lists computed."""
        t = now_s()
        self.build_rpt_index()
        th = self.thalf()
        heard_by_x, x_heard_by = {}, {}                     # index the links once: O(links)
        for (a, b), e in self.edges.items():
            w = fade(e[0], e[1], t, th)
            if w < 0.2:
                continue
            item = (w, e[2], False)
            heard_by_x.setdefault(b, []).append((a,) + item)
            x_heard_by.setdefault(a, []).append((b,) + item)
        for (a, b), e in self.obs_edges.items():            # links only observers have heard (marked "via observers")
            if (a, b) in self.edges:
                continue
            w = fade(e[0], e[1], t, th)
            if w < 0.2:
                continue
            item = (w, e[2], True)
            heard_by_x.setdefault(b, []).append((a,) + item)
            x_heard_by.setdefault(a, []).append((b,) + item)

        def nlist(items):
            items = sorted(items, key=lambda x: -x[1])[:8]
            return [dict(name=self.rpt_label(n) if n else "room", seen=round(w, 1), snr=None if snr is None else round(snr, 1), obs=o)
                    for n, w, snr, o in items]

        def has_pos(h):
            hit = self.rpt_lookup(h)
            return bool(hit and hit[1].get("lat") is not None and (hit[1].get("lat") or hit[1].get("lon")))
        positioned = {h for h in self.heard if has_pos(h) and t - (self.heard[h]["last"] or 0) <= MAP_MAX_AGE_S}
        act = {h: fade(d["w"], d["t"], t, 6 * 3600.0) for h, d in self.heard.items()}
        shown = sorted(self.heard, key=lambda h: -act[h])[:200]
        shown += [h for h in positioned if h not in set(shown)]         # everything that can go on the map (heard in 72 h)
        rpts = []
        for h in shown:
            d = self.heard[h]
            hit = self.rpt_lookup(h)
            info_pub, info = hit if hit else (None, None)
            rpts.append(dict(hash=hexs(h), name=(info or {}).get("name") or "", lat=(info or {}).get("lat"), lon=(info or {}).get("lon"),
                             on_map=h in positioned,
                             key=hexs(info_pub) if info_pub else None, last_advert=(info or {}).get("last_advert"),
                             last=d["last"], last_direct=d["last_direct"], activity=round(act[h], 1),
                             disc=d.get("disc") or 0, out_snr=None if d.get("out_snr") is None else round(d["out_snr"], 1),
                             snr=None if d["snr"] is None else round(d["snr"], 1),
                             routes=[dict(path=self.path_names(rr.plen, rr.path), conf=round(c * 100)) for rr, c in self.top_rpt_routes(h)],
                             heard=nlist(heard_by_x.get(h, [])), heard_by=nlist(x_heard_by.get(h, []))))
        rpts.sort(key=lambda r: -r["activity"])
        if self.cfg.lat or self.cfg.lon:
            positioned.add(b"")                             # the room, when it has a position
        edges = [dict(a=hexs(a), b=hexs(b) if b else "", w=round(fade(e[0], e[1], t, th), 1),
                      snr=None if e[2] is None else round(e[2], 1)) for (a, b), e in self.edges.items()
                 if a in positioned and b in positioned and fade(e[0], e[1], t, th) >= 0.5]
        edges += [dict(a=hexs(a), b=hexs(b), w=round(fade(e[0], e[1], t, th), 1), snr=None if e[2] is None else round(e[2], 1), obs=True)
                  for (a, b), e in self.obs_edges.items()
                  if (a, b) not in self.edges and a in positioned and b in positioned and fade(e[0], e[1], t, th) >= 0.5]
        # the map's *shape* (positions + drawable links): its version only changes when the drawing would
        shape = repr((sorted((r["hash"], r["lat"], r["lon"]) for r in rpts if r["on_map"]),
                      sorted((e["a"], e["b"]) for e in edges), self.cfg.lat, self.cfg.lon))
        if shape != self.map_shape:
            self.map_shape = shape
            self.map_version += 1
        self.web_map = dict(room=dict(name=self.cfg.name, lat=self.cfg.lat, lon=self.cfg.lon), repeaters=rpts, edges=edges,
                            time=t, version=self.map_version)

    def publish_web_state(self):
        """Build a fresh, self-contained dict; the web thread only ever reads the latest one."""
        t = now_s()
        self.build_rpt_index()
        rh = self.rhalf()
        members = []
        for m in self.members.values():
            nm = self.names.get(m.pub[:8])
            in_backoff = m.plan is not None and m.push_failures >= len(m.plan) and time.monotonic() < m.retry_at
            outstanding = self.unsynced_count(m)
            # synced: nothing to send; queued: posts waiting, none tried yet; sent: first attempt out; retry: the
            # latest attempt on this post is retry number tries - 1 (in flight, or waiting its turn)
            tries = m.attempt_no if m.push_post_ts and not m.push_delivered else 0
            push = ("suspended" if m.given_up else "backoff" if in_backoff else "retry" if tries > 1
                    else "sent" if tries == 1 else "queued" if outstanding else "synced")
            members.append(dict(
                pub=hexs(m.pub), key=m.key6, name=nm[1] if nm else "",
                delivery=self.delivery_score(m), avg_attempts=None if m.attempts_avg is None else round(m.attempts_avg, 2),
                deliveries=m.deliveries, role={PERM_ADMIN: "admin", PERM_GUEST: "guest"}.get(m.role, "member"),
                last_activity=m.last_activity, last_heard=max(m.last_heard or 0, m.last_activity or 0), sync_since=m.sync_since, outstanding=outstanding,
                push=push, retries=max(0, tries - 1),
                retry_in=int(m.retry_at - time.monotonic()) if in_backoff else 0,
                route=self.path_names(m.out_path_len, m.out_path), route_hex=self.path_hex(m.out_path_len, m.out_path),
                in_route_hex=self.path_hex(m.in_path_len, m.in_path) if m.in_ts else None, suspended_at=m.suspended_at,
                in_route=self.path_names(m.in_path_len, m.in_path) if m.in_ts else None, in_age=m.in_ts,
                in_routes=self.member_inroutes(m),
                routes=[dict(path=self.path_names(r.len, r.path), hex=self.path_hex(r.len, r.path), rate=round(r.rate(t, rh) * 100),
                             evidence=round(r.evidence(t, rh)[1], 1), lat_ms=int(r.lat), current=self.is_current(m, r))
                        for r in sorted(m.routes, key=lambda r: -r.rate(t, rh))],
                near=[dict(rpt=self.rpt_label(k) if k else "direct", hex=hexs(k) if k else "direct", share=round(sh * 100))
                      for k, sh in self.member_locations(m)]))
        s = self.stats
        self.web_state = dict(
            room=dict(name=self.cfg.name, key=hexs(self.id.pub_key), lat=self.cfg.lat, lon=self.cfg.lon, fw=FIRMWARE_VERSION,
                      host=not self.TENANT, rooms=len(self.tenants) if not self.TENANT else None,
                      radio=list(self.radio) if self.radio else None, uptime=int(time.monotonic() - self.boot), time=t,
                      clock_ok=t > 1735689600, noise_floor=self.noise_floor, batt_mv=self.batt_mv),
            stats=dict(s, posts_held=sum(1 for p in self.posts if p[3] is None), names_known=len(self.names),
                       tx_queue=len(self.txq)),
            members=sorted(members, key=lambda x: (x["delivery"] is None, -(x["delivery"] or 0), -x["last_activity"])),
            bans=[dict(pub=hexs(k), key=hexs(k[:6]), name=v["name"], ts=v["ts"]) for k, v in sorted(self.bans.items(), key=lambda x: -x[1]["ts"])],
            top_links=self.top_links(), discovery_min=self.cfg.discovery_interval_min, hour=self.hour_stats(),
            map_version=self.map_version, web=dict(viewers=self.web_clients[0], admins=self.web_clients[1]),
            sys=self.sys_stats(), observer=dict(self.observer.status() if self.observer else dict(
                enabled=bool(self.cfg.observer_enabled), iata=str(self.cfg.observer_iata).upper(),
                status=bool(self.cfg.observer_status), packets=bool(self.cfg.observer_packets), rx=bool(self.cfg.observer_rx),
                public_key="", queue_depth=0, queue_max=int(self.cfg.observer_queue_max), dropped=0,
                uptime=0, last_rx=0, last_error="", brokers={
                    "gomesh": dict(enabled=bool(self.cfg.observer_gomesh), connected=False, last_publish=0, last_error=""),
                    "meshmapper": dict(enabled=bool(self.cfg.observer_meshmapper), connected=False, last_publish=0, last_error="")}), identity=str(self.cfg.observer_identity or ""), choices=self.observer_choices()),
            mqtt=self.mqtt_state(), repeater=self.vr_state(), companion=self.vc_state(), airtime=self.air.state())
        self.web_vc_admin = self.vc_admin_state()          # (served to admins only)
        if self.tenants:
            self.web_tenant_rows = [t.admin_row() for t in self.tenants.values()]

    def member_inroutes(self, m, n=5):
        """Other paths the member's floods took to reach us (member side first), most seen first, excluding the current."""
        tab = self.inpaths.get(m.pub[:8]) or {}
        t = now_s()
        cur = (m.in_path_len, m.in_path) if m.in_ts else None
        ws = {k: fade(e[0], e[1], t, self.rhalf()) for k, e in tab.items() if k != cur}
        tot = sum(fade(e[0], e[1], t, self.rhalf()) for e in tab.values()) or 1.0
        top = sorted(ws.items(), key=lambda kv: -kv[1])[:n]
        return [dict(path=self.path_names(plen, path), hex=self.path_hex(plen, path), share=round(100 * w / tot))
                for (plen, path), w in top if w > 0.05]

    def top_links(self, n=25):
        """Neighbours ranked by trace reliability (most reliable first, more traces first), untraced ones after; at
        most n, our own virtual repeater (first, when it's on) among them."""
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
                rtt=None if st["rtt"] is None else int(st["rtt"]), last_ok=st["last_ok"],
                last_test=st["tr_t"] if st["tr_n"] > 0 else st["last_ok"])))     # last trace (or discovery reply)
        rows.sort(key=lambda r: r[0])
        out = [r[1] for r in rows[:n - (self.vr is not None)]]
        if self.vr is not None:                             # our own repeater: the same radio, a perfect link
            snr = VIRTUAL_LINK_SNR
            out.insert(0, dict(name="%s (virtual)" % self.rpt_label(self.vr.pub[:2]), hash=hexs(self.vr.pub[:2]), loss=0.0,
                               traces=0, few=False, in_last=snr, in_avg=snr, out_last=snr, out_avg=snr, rtt=None,
                               last_ok=now_s(), last_test=None, virtual=True))
        return out

    @staticmethod
    def path_hex(plen, path):
        if plen is None:
            return None
        sz = (plen >> 6) + 1
        return [hexs(path[i * sz:(i + 1) * sz]) for i in range(plen & 63)]

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
        if self.tenants:
            self.push_rooms()
        else:
            self.push_tick()
        if self.vc is not None:
            self.vc.service()                               # packets between the companion and the room, when due
        for t in list(self.tenants.values()):
            t.run_once()
        if self.bus:
            self.service_bus()
        self.service_tx()
        if self.kaas is not None:
            self.kaas.periodic()
        self.periodic()


# ============================================================================
# Virtual repeater: a second identity on the room's radio, relaying like MeshCore's simple_repeater
# ============================================================================

VIRTUAL_LINK_SNR = 12.0               # room <-> its own repeater: the same radio, reported as a perfect link
RPT_FLOOD_MAX = 64                    # firmware flood.max / flood.max.unscoped
RPT_FLOOD_MAX_ADVERT = 8              # firmware flood.max.advert
RPT_TX_DELAY_FACTOR = 0.5             # firmware tx_delay_factor (floods)
RPT_DIRECT_TX_DELAY_FACTOR = 0.3      # firmware direct_tx_delay_factor
RPT_MAX_QUEUED = 16                   # relays waiting to go out at once (the firmware's packet pool is 32)
RPT_LOOP_MAX = {"minimal": {1: 4, 2: 2, 3: 1}, "moderate": {1: 2, 2: 1, 3: 1}, "strict": {1: 1, 2: 1, 3: 1}}


class VirtualRepeater:
    """A light repeater sharing the room's radio, with its own key. It follows the firmware's relay rules
    (Mesh.cpp onRecvPacket / routeRecvPacket, simple_repeater MyMesh.cpp allowPacketForward, onControlDataRecv) with
    its own duplicate table. No logins or remote management. Room <-> repeater traffic never goes on the air: the
    repeater doesn't relay the room's transmissions or packets for the room, hands the room anything it would
    forward to it on a last hop, and the room skips it at the start of its own direct routes."""

    def __init__(self, room, ident):
        self.room, self.id, self.pub = room, ident, ident.pub_key
        self.seen = {}                                      # packet hash -> None (insertion ordered)
        self.stats = dict(flood=0, direct=0, acks=0, traces=0, discovery=0, internal=0, adverts=0, dups=0,
                          drop_scope=0, drop_hops=0, drop_loop=0, drop_airtime=0, drop_queue=0, drop_off=0)
        self.recent = collections.deque()                   # (monotonic, airtime ms) of each relay, last 10 minutes
        self.disc_window = [0, 0]                           # discovery answers: window start (s), count
        self.started = now_s()                              # the firmware's discovery_mod_timestamp
        self.next_zero_advert = time.monotonic() + 8
        self.next_flood_advert = time.monotonic() + 20
        self._region_cache = (None, [])

    cfg = property(lambda s: s.room.cfg)

    # ---------------------------------------------------------------- duplicates

    def was_seen(self, pkt):
        return pkt.packet_hash() in self.seen

    def seen_mark(self, pkt):
        self.seen[pkt.packet_hash()] = None
        while len(self.seen) > 512:
            self.seen.pop(next(iter(self.seen)))

    # ---------------------------------------------------------------- relay policy

    def regions(self):
        names = tuple(str(r).strip() for r in (self.cfg.repeater_regions or []) if str(r).strip())
        if self._region_cache[0] != names:
            self._region_cache = (names, [(n, transport_key(n)) for n in names])
        return self._region_cache[1]

    def scope_ok(self, pkt):
        """Unscoped floods are always relayed. A scoped flood carries a code computed from its region's key
        (RegionMap::findMatch): "allow" relays only listed regions, "deny" everything but them. Code 0 means
        'send to nowhere' (shares) and FFFF is reserved: never relayed."""
        if pkt.route_type != ROUTE_TRANSPORT_FLOOD:
            return True
        code = pkt.transport_codes[0]
        if code in (0, 0xFFFF):
            return False
        match = any(transport_code(key, pkt) == code for _, key in self.regions())
        return match if self.cfg.repeater_scope_mode != "deny" else not match

    def looped(self, pkt):
        """MyMesh::isLooped: this repeater already appears in the path too often (per path id size)."""
        maxes = RPT_LOOP_MAX.get(str(self.cfg.repeater_loop_detect))
        if not maxes:
            return False
        sz, k = pkt.hash_size, pkt.hop_count
        mine = self.pub[:sz]
        n = sum(1 for i in range(k) if pkt.path[i * sz:(i + 1) * sz] == mine)
        return n >= maxes.get(sz, 1)

    def allow_forward(self, pkt):
        """MyMesh::allowPacketForward."""
        if not self.cfg.repeater_relay:
            self.stats["drop_off"] += 1
            return False
        if pkt.is_flood:
            hops = pkt.hop_count
            if hops >= RPT_FLOOD_MAX or (pkt.ptype == PT_ADVERT and hops >= RPT_FLOOD_MAX_ADVERT):
                self.stats["drop_hops"] += 1
                return False
            if not self.scope_ok(pkt):
                self.stats["drop_scope"] += 1
                return False
            if self.looped(pkt):
                self.stats["drop_loop"] += 1
                return False
        return True

    def tx_delay(self, pkt, factor):
        """Firmware getRetransmitDelay / getDirectRetransmitDelay: random 0..5 x (airtime x factor), in seconds."""
        t = int(self.room.airtime_ms(path_bytes(pkt.path_len) + len(pkt.payload) + 2) * factor)
        return random.randint(0, 5 * t) / 1000.0

    def transmit(self, fwd, prio, delay, kind):
        if sum(1 for e in self.room.txq if e[7]) >= RPT_MAX_QUEUED:
            self.stats["drop_queue"] += 1
            return False
        at = self.room.airtime_ms(fwd.raw_length())
        if not self.room.air.can("relay", at):             # (its share, or what others leave unused, is spent)
            self.stats["drop_airtime"] += 1
            return False
        self.room.queue_tx(fwd, prio, delay, relay=True)
        self.stats[kind] += 1
        now = time.monotonic()
        self.recent.append((now, at))
        while self.recent and now - self.recent[0][0] > 600:
            self.recent.popleft()
        return True

    def purge(self):
        """Kill switch: drop every relay still waiting to go out."""
        n = len(self.room.txq)
        self.room.txq[:] = [e for e in self.room.txq if not e[7]]
        heapq.heapify(self.room.txq)
        return n - len(self.room.txq)

    # ---------------------------------------------------------------- receive

    def on_rx(self, pkt, for_room):
        try:
            if pkt.is_flood:
                self.relay_flood(pkt, for_room)
            elif pkt.ptype == PT_TRACE:
                self.relay_trace(pkt)
            elif pkt.ptype == PT_CONTROL and pkt.payload[:1] and pkt.payload[0] & 0x80:
                if pkt.hop_count == 0:
                    self.on_control(pkt)                    # (only zero-hop control packets of this kind)
            elif pkt.hop_count > 0:
                self.forward_direct(pkt)
        except Exception:
            log.exception("virtual repeater")

    def relay_flood(self, pkt, for_room):
        p, t = pkt.payload, pkt.ptype
        if t == PT_ACK:
            ok = len(p) >= 4
        elif t in (PT_PATH, PT_REQ, PT_RESPONSE, PT_TXT_MSG):
            ok = len(p) > 2 + CIPHER_MAC_SIZE
        elif t == PT_ANON_REQ:
            ok = len(p) > 1 + PUB_KEY_SIZE + 2
        elif t in (PT_GRP_TXT, PT_GRP_DATA):
            ok = len(p) > 1 + 2
        elif t == PT_ADVERT:
            ok = len(p) >= PUB_KEY_SIZE + 4 + SIGNATURE_SIZE and p[:32] not in (self.pub, self.room.id.pub_key)
        else:
            return                                          # traces, multipart, control, raw, unknown: never flooded on
        if not ok:
            return
        if self.was_seen(pkt):
            self.stats["dups"] += 1
            return
        self.seen_mark(pkt)
        if t == PT_ADVERT and not ed25519_verify(p[:32], p[36:100], p[:36] + p[100:100 + MAX_ADVERT_DATA_SIZE]):
            return                                          # forged: not relayed
        if for_room:
            self.stats["internal"] += 1                     # it was for the room: the destination has it
            return
        n, sz = pkt.hop_count, pkt.hash_size
        if (n + 1) * sz > MAX_PATH_SIZE or n + 1 > 63:     # (the hop count is 6 bits: the firmware's size check
            self.stats["drop_hops"] += 1                    #  alone lets a 64th 1-byte hop overflow into the id size)
            return
        if not self.allow_forward(pkt):
            return
        fwd = pkt.copy()
        fwd.path = pkt.path[:n * sz] + self.pub[:sz]        # append our id at the packet's id size
        fwd.path_len = (pkt.path_len & ~63) | (n + 1)
        self.transmit(fwd, n + 1, self.tx_delay(fwd, RPT_TX_DELAY_FACTOR), "flood")   # closer sources first

    def forward_direct(self, pkt):
        """Direct routing: we are the next hop -> consume our hop and pass it on (Mesh.cpp)."""
        sz = pkt.hash_size
        if pkt.path[:sz] != self.pub[:sz] or not self.allow_forward(pkt):
            return
        p, t = pkt.payload, pkt.ptype
        if t == PT_MULTIPART:
            if len(p) >= 5 and (p[0] & 0x0F) == PT_ACK:     # a multipart ACK: forwarded as a plain ACK
                tmp = Packet(PT_ACK, p[1:])
                tmp.header, tmp.path_len, tmp.path = pkt.header, pkt.path_len, pkt.path
                if not self.was_seen(tmp):
                    self.seen_mark(tmp)
                    self.direct_ack(self.consume_hop(tmp), ((p[0] >> 4) + 1) * 0.3)
            return
        if self.was_seen(pkt):
            self.stats["dups"] += 1
            return
        self.seen_mark(pkt)
        fwd = self.consume_hop(pkt)
        if t == PT_ACK:
            self.direct_ack(fwd, 0.0)
            return
        if fwd.hop_count == 0 and self.room.internal_rx(fwd.copy()):
            self.stats["internal"] += 1                     # last hop to the room itself
            return
        self.transmit(fwd, 0, self.tx_delay(fwd, RPT_DIRECT_TX_DELAY_FACTOR), "direct")

    @staticmethod
    def consume_hop(pkt):
        fwd = pkt.copy()
        sz = pkt.hash_size
        fwd.path = pkt.path[sz:path_bytes(pkt.path_len)]
        fwd.path_len = (pkt.path_len & ~63) | (pkt.hop_count - 1)
        return fwd

    def direct_ack(self, pkt, delay):
        """Mesh::routeDirectRecvAcks (no extra ACKs: multi_acks 0): a fresh direct ACK on the remaining path."""
        ack = Packet(PT_ACK, pkt.payload)
        ack.header = (ack.header & ~0x03) | ROUTE_DIRECT
        ack.path_len, ack.path = pkt.path_len, pkt.path
        if ack.hop_count == 0 and self.room.internal_rx(ack.copy()):
            self.stats["internal"] += 1
            return
        self.transmit(ack, 0, delay, "acks")

    def trace_next_is_me(self, pkt):
        p = pkt.payload
        if len(p) < 9 or pkt.path_len >= MAX_PATH_SIZE:
            return False
        es = 1 << (p[8] & 0x03)
        off = pkt.path_len * es
        return off < len(p) - 9 and p[9 + off:9 + off + es] == self.pub[:es]

    def relay_trace(self, pkt):
        """Mesh.cpp TRACE: if the next entry in its route is us, append the SNR we heard it at and send it on."""
        if not self.trace_next_is_me(pkt) or not self.allow_forward(pkt) or self.was_seen(pkt):
            return
        self.seen_mark(pkt)
        fwd = pkt.copy()
        fwd.path = pkt.path[:pkt.path_len] + struct.pack("b", max(-128, min(127, int(pkt.snr * 4))))
        fwd.path_len = pkt.path_len + 1
        es = 1 << (pkt.payload[8] & 0x03)
        off = fwd.path_len * es
        if pkt.payload[9 + off:9 + off + es] == self.room.id.pub_key[:es] and off < len(pkt.payload) - 9:
            fwd.snr = VIRTUAL_LINK_SNR                      # next hop is the room itself, on this radio
            self.stats["internal"] += 1
            self.room.relay_trace(fwd)
            return
        self.transmit(fwd, 5, self.tx_delay(fwd, RPT_DIRECT_TX_DELAY_FACTOR), "traces")

    def on_control(self, pkt):
        """Answer node discovery (MyMesh::onControlDataRecv): at most 4 answers every 2 minutes, randomised."""
        p = pkt.payload
        if (p[0] & 0xF0) != 0x80 or len(p) < 6 or not self.cfg.repeater_relay:
            return
        now = now_s()
        if now < self.disc_window[0] + 120:                 # RateLimiter(4, 120)
            self.disc_window[1] += 1
            if self.disc_window[1] > 4:
                return
        else:
            self.disc_window[:] = [now, 1]
        since = struct.unpack_from("<I", p, 6)[0] if len(p) >= 10 else 0
        if not (p[1] & (1 << ADV_TYPE_REPEATER)) or self.started < since:
            return
        prefix_only = p[0] & 1
        data = bytes([0x90 | ADV_TYPE_REPEATER]) + struct.pack("b", max(-128, min(127, int(pkt.snr * 4)))) + p[2:6] \
            + self.pub[:8 if prefix_only else PUB_KEY_SIZE]
        resp = Packet(PT_CONTROL, data)
        resp.header = (resp.header & ~0x03) | ROUTE_DIRECT
        resp.path_len, resp.path = 0, b""
        self.room.queue_tx(resp, 0, self.tx_delay(resp, RPT_TX_DELAY_FACTOR) * 4, relay=True)
        self.stats["discovery"] += 1

    # ---------------------------------------------------------------- the room's side

    def strip_first_hops(self, path, path_len):
        sz, k = (path_len >> 6) + 1, path_len & 63
        mine = self.pub[:sz]
        while k and path[:sz] == mine:
            path, k = path[sz:], k - 1
        return path, (path_len & ~63) | k

    # ---------------------------------------------------------------- adverts

    def position(self):
        """Its own position if set, else the room's (if the room has one), else none (0, 0)."""
        lat, lon = float(self.cfg.repeater_lat or 0), float(self.cfg.repeater_lon or 0)
        if lat or lon:
            return lat, lon
        return float(self.cfg.lat or 0), float(self.cfg.lon or 0)

    def send_advert(self, flood):
        lat, lon = self.position()
        pkt = make_advert(self.id, ADV_TYPE_REPEATER, self.cfg.repeater_name, lat, lon)
        if flood:
            self.room.send_flood(pkt)
        else:
            self.room.send_zero_hop(pkt)
        self.stats["adverts"] += 1
        log.info("virtual repeater: sent %s advert", "flood" if flood else "zero-hop")

    def periodic(self):
        now = time.monotonic()
        c = self.cfg
        if c.repeater_advert_interval_min and now >= self.next_zero_advert:
            self.send_advert(False)
            self.next_zero_advert = now + float(c.repeater_advert_interval_min) * 60
        if c.repeater_flood_advert_interval_h and now >= self.next_flood_advert:
            self.send_advert(True)
            self.next_flood_advert = now + float(c.repeater_flood_advert_interval_h) * 3600

    def state(self):
        now = time.monotonic()
        recent = [x for x in self.recent if now - x[0] <= 600]
        span = max(60.0, min(600.0, now - self.room.boot))
        relayed = sum(self.stats[k] for k in ("flood", "direct", "acks", "traces"))
        return dict(self.stats, relayed=relayed, per_min=round(len(recent) / (span / 60.0), 1),
                    airtime_used=round(100.0 * sum(x[1] for x in recent) / (span * 1000.0), 1))

# ============================================================================
# Virtual companion: a chat node on the room's radio that MeshCore apps reach over TCP
# ============================================================================

VC_FIRMWARE_VER_CODE = 10             # companion protocol level answered (v10: repeat flag + path hash mode in DEVICE_INFO)
VC_MAX_CONTACTS = 350                 # as the firmware's larger builds
VC_MAX_CHANNELS = 40
VC_QUEUE_MAX = 64                     # messages waiting for the app (firmware: 16)
VC_MAX_FRAME = 176                    # BaseSerialInterface MAX_FRAME_SIZE
VC_MAX_TEXT_LEN = 160                 # BaseChatMesh MAX_TEXT_LEN
VC_ACK_TABLE = 8
VC_ACK_COPY_S = 30                    # an ACK's other copies (multipart, plain, retries) are still its for this long
VC_ADVERT_PATHS = 16
VC_MAX_SIGN = 8 * 1024
VC_PUBLIC_PSK = base64.b64decode("izOH6cXN6mrJ5e26oRXNcg==")
PT_RAW_CUSTOM = 0x0F
REQ_GET_TELEMETRY_DATA = 0x03

# app -> companion commands (companion_radio MyMesh.cpp)
CMD_APP_START, CMD_SEND_TXT_MSG, CMD_SEND_CHANNEL_TXT_MSG, CMD_GET_CONTACTS, CMD_GET_DEVICE_TIME = 1, 2, 3, 4, 5
CMD_SET_DEVICE_TIME, CMD_SEND_SELF_ADVERT, CMD_SET_ADVERT_NAME, CMD_ADD_UPDATE_CONTACT = 6, 7, 8, 9
CMD_SYNC_NEXT_MESSAGE, CMD_SET_RADIO_PARAMS, CMD_SET_RADIO_TX_POWER, CMD_RESET_PATH = 10, 11, 12, 13
CMD_SET_ADVERT_LATLON, CMD_REMOVE_CONTACT, CMD_SHARE_CONTACT, CMD_EXPORT_CONTACT, CMD_IMPORT_CONTACT = 14, 15, 16, 17, 18
CMD_REBOOT, CMD_GET_BATT_AND_STORAGE, CMD_SET_TUNING_PARAMS, CMD_DEVICE_QUERY = 19, 20, 21, 22
CMD_EXPORT_PRIVATE_KEY, CMD_IMPORT_PRIVATE_KEY, CMD_SEND_RAW_DATA, CMD_SEND_LOGIN, CMD_SEND_STATUS_REQ = 23, 24, 25, 26, 27
CMD_HAS_CONNECTION, CMD_LOGOUT, CMD_GET_CONTACT_BY_KEY, CMD_GET_CHANNEL, CMD_SET_CHANNEL = 28, 29, 30, 31, 32
CMD_SIGN_START, CMD_SIGN_DATA, CMD_SIGN_FINISH, CMD_SEND_TRACE_PATH, CMD_SET_DEVICE_PIN = 33, 34, 35, 36, 37
CMD_SET_OTHER_PARAMS, CMD_SEND_TELEMETRY_REQ, CMD_GET_CUSTOM_VARS, CMD_SET_CUSTOM_VAR = 38, 39, 40, 41
CMD_GET_ADVERT_PATH, CMD_GET_TUNING_PARAMS = 42, 43
CMD_SEND_BINARY_REQ, CMD_FACTORY_RESET, CMD_SEND_PATH_DISCOVERY_REQ = 50, 51, 52
CMD_SET_FLOOD_SCOPE_KEY, CMD_SEND_CONTROL_DATA, CMD_GET_STATS, CMD_SEND_ANON_REQ = 54, 55, 56, 57
CMD_SET_AUTOADD_CONFIG, CMD_GET_AUTOADD_CONFIG, CMD_GET_ALLOWED_REPEAT_FREQ, CMD_SET_PATH_HASH_MODE = 58, 59, 60, 61
CMD_SEND_CHANNEL_DATA, CMD_SET_DEFAULT_FLOOD_SCOPE, CMD_GET_DEFAULT_FLOOD_SCOPE, CMD_SEND_RAW_PACKET = 62, 63, 64, 65
CMD_RUN_CLI_COMMAND = 66
VC_TX_CMDS = {CMD_SEND_TXT_MSG, CMD_SEND_CHANNEL_TXT_MSG, CMD_SEND_CHANNEL_DATA, CMD_SEND_SELF_ADVERT, CMD_SEND_LOGIN,
              CMD_SEND_ANON_REQ, CMD_SEND_STATUS_REQ, CMD_SEND_PATH_DISCOVERY_REQ, CMD_SEND_TELEMETRY_REQ,
              CMD_SEND_BINARY_REQ, CMD_SEND_TRACE_PATH, CMD_SEND_CONTROL_DATA}   # app commands that transmit
VC_TX_BURST = 10                      # ...at most this many at once,
VC_TX_EVERY_S = 3.0                   # then one more every this long (about 20 a minute)
VC_SAVE_EVERY_S = 30                  # an app's name / position changes reach the config file at most this often
VC_ADVERT_EVERY_S = 10                # and an advert at most this often (as the dashboard's button)

# companion -> app replies
RESP_OK, RESP_ERR, RESP_CONTACTS_START, RESP_CONTACT, RESP_END_OF_CONTACTS, RESP_SELF_INFO, RESP_SENT = 0, 1, 2, 3, 4, 5, 6
RESP_CONTACT_MSG_RECV, RESP_CHANNEL_MSG_RECV, RESP_CURR_TIME, RESP_NO_MORE_MESSAGES, RESP_EXPORT_CONTACT = 7, 8, 9, 10, 11
RESP_BATT_AND_STORAGE, RESP_DEVICE_INFO, RESP_PRIVATE_KEY, RESP_DISABLED = 12, 13, 14, 15
RESP_CONTACT_MSG_RECV_V3, RESP_CHANNEL_MSG_RECV_V3, RESP_CHANNEL_INFO, RESP_SIGN_START, RESP_SIGNATURE = 16, 17, 18, 19, 20
RESP_CUSTOM_VARS, RESP_ADVERT_PATH, RESP_TUNING_PARAMS, RESP_STATS, RESP_AUTOADD_CONFIG = 21, 22, 23, 24, 25
RESP_ALLOWED_REPEAT_FREQ, RESP_CHANNEL_DATA_RECV, RESP_DEFAULT_FLOOD_SCOPE, RESP_CLI_REPLY = 26, 27, 28, 29

# companion -> app pushes (sent at any time)
PUSH_ADVERT, PUSH_PATH_UPDATED, PUSH_SEND_CONFIRMED, PUSH_MSG_WAITING, PUSH_RAW_DATA = 0x80, 0x81, 0x82, 0x83, 0x84
PUSH_LOGIN_SUCCESS, PUSH_LOGIN_FAIL, PUSH_STATUS_RESPONSE, PUSH_LOG_RX_DATA, PUSH_TRACE_DATA = 0x85, 0x86, 0x87, 0x88, 0x89
PUSH_NEW_ADVERT, PUSH_TELEMETRY_RESPONSE, PUSH_BINARY_RESPONSE, PUSH_PATH_DISCOVERY_RESPONSE = 0x8A, 0x8B, 0x8C, 0x8D
PUSH_CONTROL_DATA, PUSH_CONTACT_DELETED, PUSH_CONTACTS_FULL = 0x8E, 0x8F, 0x90

ERR_UNSUPPORTED_CMD, ERR_NOT_FOUND, ERR_TABLE_FULL, ERR_BAD_STATE, ERR_FILE_IO, ERR_ILLEGAL_ARG = 1, 2, 3, 4, 5, 6

# settings an app may send that belong to the whole radio (or to hardware the companion doesn't have): acknowledged
# so the app is happy, never applied
VC_IGNORED = {CMD_SET_RADIO_PARAMS: "radio parameters", CMD_SET_RADIO_TX_POWER: "TX power",
              CMD_SET_TUNING_PARAMS: "tuning parameters", CMD_SET_DEVICE_PIN: "Bluetooth PIN",
              CMD_SET_PATH_HASH_MODE: "path hash mode", CMD_REBOOT: "reboot", CMD_FACTORY_RESET: "factory reset",
              CMD_IMPORT_PRIVATE_KEY: "private key import", CMD_SET_DEVICE_TIME: "clock",
              CMD_RUN_CLI_COMMAND: "CLI command"}


def snr4(snr):
    return struct.pack("b", max(-128, min(127, int(snr * 4))))


def channel_hash(secret16):
    return hashlib.sha256(secret16).digest()[0]


def utf8_cut(b, n):
    """At most n bytes of UTF-8, never ending mid-character."""
    b = b[:n]
    while b:
        try:
            b.decode()
            return b
        except UnicodeDecodeError:
            b = b[:-1]
    return b


def companion_changes(body):
    """Dashboard companion settings -> {config key: value}, validated. Raises ValueError with a readable message."""
    import ipaddress
    if not isinstance(body, dict):
        raise ValueError("bad request")
    ch = {}
    for j, k in (("enabled", "companion_enabled"), ("auto_advert", "companion_auto_advert"),
                 ("advert_flood", "companion_advert_flood")):
        if j in body:
            ch[k] = bool(body[j])
    if "private_key" in body:
        key = str(body["private_key"]).strip().lower()
        if len(key) not in (64, 128) or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("private key must be 64 or 128 hexadecimal characters")
        RepeaterIdentity(bytes.fromhex(key))                # never returned through dashboard state or logs
        ch["companion_key"] = key
    if "name" in body:
        name = str(body["name"]).strip()
        if not name or len(name.encode()) > 31:
            raise ValueError("name: 1 to 31 bytes")
        ch["companion_name"] = name
    if "port" in body:
        try:
            port = int(body["port"])
        except (TypeError, ValueError):
            raise ValueError("port: not a number")
        if not 1 <= port <= 65535:
            raise ValueError("port: 1 to 65535")
        ch["companion_port"] = port
    if "advert_min" in body:
        try:
            v = int(body["advert_min"])
        except (TypeError, ValueError):
            raise ValueError("advert interval: not a number")
        if not 1 <= v <= 10080:
            raise ValueError("advert interval: 1 to 10080 minutes")
        ch["companion_advert_interval_min"] = v
    if "allow" in body:
        allow = body["allow"]
        if isinstance(allow, str):
            allow = allow.replace(";", ",").split(",")
        allow = [str(a).strip() for a in allow if str(a).strip()]
        for a in allow:
            try:
                ipaddress.ip_network(a, strict=False)
            except ValueError:
                raise ValueError("allowed address %r: an IP address or network such as 192.168.1.0/24" % a)
        ch["companion_allow"] = allow
    return ch


class VCContact:
    __slots__ = ("pub", "type", "flags", "out_len", "out_path", "name", "adv_ts", "lat", "lon", "lastmod",
                 "sync_since", "advert", "secret")

    def __init__(self, pub):
        self.pub = pub
        self.type = self.flags = self.adv_ts = self.lat = self.lon = self.lastmod = self.sync_since = 0
        self.out_len = None                                 # None = no known route (flood)
        self.out_path = b""
        self.name = ""
        self.advert = b""                                   # last advert, raw (export / share)
        self.secret = None

    def frame(self, code):
        """writeContactRespFrame."""
        return bytes([code]) + self.pub + bytes([self.type, self.flags, 0xFF if self.out_len is None else self.out_len]) \
            + self.out_path[:MAX_PATH_SIZE].ljust(MAX_PATH_SIZE, b"\0") + utf8_cut(self.name.encode(), 31).ljust(32, b"\0") \
            + struct.pack("<IiiI", self.adv_ts & 0xFFFFFFFF, self.lat, self.lon, self.lastmod & 0xFFFFFFFF)


class CompanionStore:
    """companion.db: the virtual companion's contacts, channels, settings and the messages waiting for the app. Kept
    apart from room.db: made the first time the companion is enabled, and deleting it resets only the companion."""

    TABLES = {
        "contacts": ("pubkey BLOB PRIMARY KEY", "type INT", "flags INT", "out_len INT", "out_path BLOB", "name TEXT",
                     "adv_ts INT", "lat INT", "lon INT", "lastmod INT", "sync_since INT", "advert BLOB"),
        "channels": ("idx INT PRIMARY KEY", "name TEXT", "secret BLOB"),
        "prefs": ("k TEXT PRIMARY KEY", "v TEXT"),
        "queue": ("id INTEGER PRIMARY KEY AUTOINCREMENT", "frame BLOB"),
    }

    def __init__(self, path):
        self.path = path
        if not os.path.exists(path):
            os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))   # holds private messages: owner-only from the start
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        self.db = sqlite3.connect(path)
        for table, cols in self.TABLES.items():
            self.db.execute("CREATE TABLE IF NOT EXISTS %s (%s)" % (table, ", ".join(cols)))
        self.db.commit()

    def contacts(self):
        out = []
        for r in self.db.execute("SELECT pubkey, type, flags, out_len, out_path, name, adv_ts, lat, lon, lastmod, sync_since, "
                                 "advert FROM contacts ORDER BY rowid"):
            c = VCContact(bytes(r[0]))
            c.type, c.flags = r[1] or 0, r[2] or 0
            c.out_len = r[3] if r[3] is not None and r[3] >= 0 and path_valid(r[3]) else None
            c.out_path = bytes(r[4] or b"")
            c.name, c.adv_ts, c.lat, c.lon, c.lastmod, c.sync_since = r[5] or "", r[6] or 0, r[7] or 0, r[8] or 0, r[9] or 0, r[10] or 0
            c.advert = bytes(r[11] or b"")
            out.append(c)
        return out

    def save_contacts(self, cs):
        with self.db:
            self.db.executemany("INSERT OR REPLACE INTO contacts (pubkey, type, flags, out_len, out_path, name, adv_ts, lat, lon, "
                                "lastmod, sync_since, advert) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                                [(c.pub, c.type, c.flags, -1 if c.out_len is None else c.out_len, c.out_path, c.name, c.adv_ts,
                                  c.lat, c.lon, c.lastmod, c.sync_since, c.advert) for c in cs])

    def delete_contact(self, pub):
        with self.db:
            self.db.execute("DELETE FROM contacts WHERE pubkey=?", (pub,))

    def channels(self):
        return {r[0]: (r[1] or "", bytes(r[2] or bytes(16))) for r in self.db.execute("SELECT idx, name, secret FROM channels")}

    def save_channel(self, idx, name, secret):
        with self.db:
            if not name and not any(secret):
                self.db.execute("DELETE FROM channels WHERE idx=?", (idx,))
            else:
                self.db.execute("INSERT OR REPLACE INTO channels VALUES (?,?,?)", (idx, name, secret))

    def prefs(self):
        out = {}
        for k, v in self.db.execute("SELECT k, v FROM prefs"):
            try:
                out[k] = json.loads(v)
            except ValueError:
                pass
        return out

    def save_prefs(self, prefs):
        with self.db:
            self.db.executemany("INSERT OR REPLACE INTO prefs VALUES (?,?)", [(k, json.dumps(v)) for k, v in prefs.items()])

    def queued(self):
        return [(r[0], bytes(r[1])) for r in self.db.execute("SELECT id, frame FROM queue ORDER BY id")]

    def queue_add(self, frame):
        with self.db:
            return self.db.execute("INSERT INTO queue (frame) VALUES (?)", (frame,)).lastrowid

    def queue_remove(self, qid):
        with self.db:
            self.db.execute("DELETE FROM queue WHERE id=?", (qid,))

    def close(self):
        try:
            self.db.close()
        except sqlite3.Error:
            pass


VC_OUT_MAX_FRAMES = 2048              # replies queued for the app, unread, before it's disconnected...
VC_OUT_MAX_BYTES = 512 * 1024         # ...or this many bytes of them


class _CompanionOut:
    """Replies waiting for the companion's writer thread."""

    def __init__(self):
        self.q, self.size, self.cv = collections.deque(), 0, threading.Condition()


class CompanionLink:
    """The companion's TCP port, as WiFi companion firmware: one app at a time (a new connection replaces the old one),
    frames "<" + u16 length + payload in and ">" + u16 length + payload out. Accepting and reading run on their own
    threads and hand each command to the main loop as an event; replies are written from the main loop."""

    ids = iter(range(1, 1 << 62))                          # connection ids, unique across links (a port change)

    def __init__(self, bind, port, put, allowed):
        self.bind, self.port, self.put, self.allowed = bind, port, put, allowed
        self.lock = threading.Lock()
        self.client, self.peer, self.client_id, self.out = None, None, 0, None
        self.backlog = {}                                   # connection id -> commands handed to the main loop, not yet handled
        self.running = True
        fam = socket.AF_INET6 if ":" in bind else socket.AF_INET
        self.sock = socket.socket(fam, socket.SOCK_STREAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((bind, port))
            self.sock.listen(2)
        except OSError:
            self.sock.close()
            raise
        self.port = self.sock.getsockname()[1]              # (port 0 in tests: the one the OS picked)
        threading.Thread(target=self._accept, name="companion-accept", daemon=True).start()

    def connected(self):
        return self.client is not None

    def _accept(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
            except OSError:
                break
            ip = addr[0]
            if not self.allowed(ip):
                log.warning("virtual companion: refused a connection from %s (not in companion_allow)", ip)
                conn.close()
                continue
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, struct.pack("ll", 3, 0))  # a stalled app can't block the room
            except (OSError, struct.error):
                pass
            out = _CompanionOut()
            with self.lock:
                old = self.client
                cid = self.client_id = next(CompanionLink.ids)
                self.client, self.peer, self.out = conn, ip, out
            if old is not None:
                self._close(old)
            self.put(("vc_conn", cid, ip))
            threading.Thread(target=self._read, args=(conn, cid), name="companion-read", daemon=True).start()
            threading.Thread(target=self._write, args=(conn, out), name="companion-write", daemon=True).start()

    def _read(self, conn, cid):
        buf = b""
        try:
            while self.running:
                d = conn.recv(4096)
                if not d:
                    break
                buf += d
                while True:
                    i = buf.find(b"<")
                    if i < 0:
                        buf = b""
                        break
                    buf = buf[i:]
                    if len(buf) < 3:
                        break
                    n = struct.unpack_from("<H", buf, 1)[0]
                    if not 0 < n <= VC_MAX_FRAME:
                        buf = buf[1:]                       # not a frame start: resynchronise
                        continue
                    if len(buf) < 3 + n:
                        break
                    frame, buf = buf[3:3 + n], buf[3 + n:]
                    while self.backlog.get(cid, 0) > 64 and self.running and self.client is conn:
                        time.sleep(0.01)                    # an app flooding commands waits; the room doesn't
                    with self.lock:
                        self.backlog[cid] = self.backlog.get(cid, 0) + 1
                    self.put(("vc_cmd", cid, frame))
        except OSError:
            pass
        finally:
            with self.lock:
                if self.client is conn:
                    self.client, self.peer = None, None
                self.backlog.pop(cid, None)
            self._close(conn)
            self.put(("vc_disc", cid))

    def done(self, cid):
        """The main loop handled one of this connection's commands."""
        with self.lock:
            if self.backlog.get(cid):
                self.backlog[cid] -= 1

    @staticmethod
    def _close(conn):
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()

    def send(self, frame):
        """Queue a reply for the app (the main loop never waits on the socket: a writer thread sends it). An app that
        lets VC_OUT_MAX_BYTES / VC_OUT_MAX_FRAMES pile up unread is disconnected."""
        with self.lock:
            conn, out = self.client, self.out
        if conn is None:
            return False
        data = b">" + struct.pack("<H", len(frame)) + frame
        with out.cv:
            full = len(out.q) >= VC_OUT_MAX_FRAMES or out.size + len(data) > VC_OUT_MAX_BYTES
            if not full:
                out.q.append(data)
                out.size += len(data)
                out.cv.notify()
        if full:
            log.warning("virtual companion: disconnected %s, which wasn't reading its replies", self.peer)
            self._drop(conn)
            return False
        return True

    def _write(self, conn, out):
        try:
            while True:
                with out.cv:
                    while not out.q and self.client is conn and self.running:
                        out.cv.wait(1.0)
                    if self.client is not conn or not self.running:
                        return
                    data = out.q.popleft()
                    out.size -= len(data)
                conn.sendall(data)                          # (SO_SNDTIMEO: an app stalled 3 s is dropped)
        except OSError:
            self._drop(conn)

    def _drop(self, conn):
        with self.lock:
            if self.client is conn:
                self.client, self.peer = None, None
        self._close(conn)

    def stop(self):
        self.running = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)            # wakes the blocked accept() (close alone leaves it listening)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        with self.lock:
            conn, self.client, self.peer = self.client, None, None
        if conn is not None:
            self._close(conn)


class VirtualCompanion:
    """A MeshCore chat node (companion_radio firmware: MyMesh.cpp + BaseChatMesh.cpp) with its own key, sharing the
    room's radio, that phone apps drive over TCP. It doesn't repeat. The room and the virtual repeater are on the same
    radio, so traffic between them and the companion never goes on the air: what the room or repeater sends that is for
    the companion is handed to it, what the companion sends hears the room first, and anything that was only for the
    room isn't transmitted. Radio-wide settings from the app are acknowledged and ignored (VC_IGNORED)."""

    PREFS = dict(manual_add=0, autoadd_config=0, autoadd_max_hops=0, telem_base=0, telem_loc=0, telem_env=0,
                 advert_loc_policy=0, multi_acks=0, app_ver=3, scope_name="", scope_key="")

    def __init__(self, room, ident, store):
        self.room, self.id, self.pub, self.store = room, ident, ident.pub_key, store
        self.contacts = collections.OrderedDict((c.pub, c) for c in store.contacts())
        self.anon = {}                                      # transient contacts for requests to non-contacts (not kept)
        self.channels = store.channels()                    # idx -> (name, 16-byte secret)
        if not self.channels:
            self.channels[0] = ("Public", VC_PUBLIC_PSK)
            store.save_channel(0, "Public", VC_PUBLIC_PSK)
        self.prefs = dict(self.PREFS)
        self.prefs.update({k: v for k, v in store.prefs().items() if k in self.PREFS})
        self.queue = store.queued()                         # [(row id, frame)], oldest first
        self.seen = {}
        self.inbox, self.outbox, self.seq = [], [], 0      # heaps: packets to/from the room, due when the radio would send
        self.expected = collections.deque(maxlen=VC_ACK_TABLE)   # [ack, sent (monotonic), contact pub]
        self.acked = collections.deque(maxlen=VC_ACK_TABLE)      # (ack, monotonic) matched lately: its other copies
        self.pending = dict(login=None, status=None, telemetry=None, req=None, discovery=None)
        self.traces = {}                                    # tag -> expiry: our own traces (their results go to the app)
        self.connections = {}                               # server pub -> keep-alive state (logins with keep-alive)
        self.advert_paths = collections.OrderedDict()       # pub[:7] -> (recv ts, path_len, path)
        self.send_scope, self.send_unscoped = None, False
        self.sign_buf = None
        self.last_unique = 0
        self.link, self.link_error, self.link_addr = None, "", None
        self.dirty = set()
        self.next_flush = time.monotonic() + 15
        self.next_advert = time.monotonic() + 10
        self.ignored_logged = set()
        self.stats = dict(rx=0, internal_in=0, internal_out=0, msgs_in=0, msgs_out=0, frames=0, ignored=0)

    cfg = property(lambda s: s.room.cfg)

    # ---------------------------------------------------------------- app link

    def listen(self):
        """Open (or move) the TCP port. Only called while the companion is enabled: the port is closed otherwise."""
        want = (str(self.cfg.companion_bind or "0.0.0.0"), int(self.cfg.companion_port))
        if self.link is not None and self.link_addr == want:
            return
        if self.link is not None:
            self.link.stop()
            self.link = None
        put = getattr(self.room, "events_put", None) or (lambda ev: None)
        try:
            self.link = CompanionLink(want[0], want[1], put, self.allowed)
            self.link_addr, self.link_error = want, ""
            log.info("virtual companion: listening on %s:%d", want[0], self.link.port)
        except OSError as e:
            self.link_addr, self.link_error = None, str(e.strerror or e)
            log.error("virtual companion: can't open TCP port %d on %s: %s", want[1], want[0], self.link_error)

    def allowed(self, ip):
        import ipaddress
        nets = self.cfg.companion_allow or []
        if isinstance(nets, str):                           # (hand-edited config: "a, b")
            nets = [n.strip() for n in nets.split(",") if n.strip()]
        if not nets:
            return True
        try:
            a = ipaddress.ip_address(ip.split("%")[0])
            if getattr(a, "ipv4_mapped", None):
                a = a.ipv4_mapped
            return any(a in ipaddress.ip_network(str(n), strict=False) for n in nets)
        except ValueError:
            return False

    def close(self):
        if self.link is not None:
            self.link.stop()
            self.link = None
        if getattr(self, "cfg_dirty", False):
            self.cfg_dirty = False
            self.cfg.save()                                 # (a name / position the app set, not saved yet)
        self.flush()
        self.store.close()

    connected = property(lambda s: s.link is not None and s.link.connected())

    def write(self, frame):
        if self.link is not None:
            self.link.send(frame[:VC_MAX_FRAME])

    def ok(self):
        self.write(bytes([RESP_OK]))

    def err(self, code):
        self.write(bytes([RESP_ERR, code]))

    def app_event(self, ev):
        kind, cid = ev[0], ev[1]
        link = self.link
        if link is not None and kind == "vc_cmd":
            link.done(cid)
        if link is None or cid != link.client_id:
            return                                          # from a connection that has since been replaced
        if kind == "vc_conn":
            self.sign_buf = None
            log.info("virtual companion: app connected from %s", ev[2])
        elif kind == "vc_disc":
            log.info("virtual companion: app disconnected")
        elif kind == "vc_cmd":
            self.on_frame(ev[2])

    # ---------------------------------------------------------------- helpers

    def unique_time(self):
        self.last_unique = max(now_s(), self.last_unique + 1)
        return self.last_unique

    def secret(self, c):
        if c.secret is None:
            try:
                c.secret = self.id.shared_secret(c.pub)
            except ValueError:                              # not a usable public key: nothing decrypts with it
                c.secret = bytes(32)
        return c.secret

    def find(self, prefix):
        for tab in (self.contacts, self.anon):
            for pub, c in tab.items():
                if pub[:len(prefix)] == prefix:
                    return c
        return None

    def contact(self, pub):
        return self.contacts.get(pub) or self.anon.get(pub)

    def touch(self, c):
        if c.pub in self.contacts:
            self.dirty.add(c.pub)

    def save_prefs(self):
        self.store.save_prefs(self.prefs)

    def was_seen(self, pkt):
        return pkt.packet_hash() in self.seen

    def seen_mark(self, pkt):
        self.seen[pkt.packet_hash()] = None
        while len(self.seen) > 512:
            self.seen.pop(next(iter(self.seen)))

    def check_dup(self, pkt):
        if self.was_seen(pkt):
            return True
        self.seen_mark(pkt)
        return False

    def flush(self):
        if self.dirty:
            self.store.save_contacts([self.contacts[k] for k in self.dirty if k in self.contacts])
            self.dirty.clear()

    def position(self):
        if self.prefs["advert_loc_policy"] == 0:            # ADVERT_LOC_NONE (the app's "share position" setting)
            return 0.0, 0.0
        return float(self.cfg.companion_lat or 0), float(self.cfg.companion_lon or 0)

    def make_self_advert(self):
        lat, lon = self.position()
        return make_advert(self.id, ADV_TYPE_CHAT, self.cfg.companion_name, lat, lon)

    # ---------------------------------------------------------------- sending

    def scope_key(self):
        if self.send_unscoped:
            return None
        if self.send_scope:
            return self.send_scope
        return bytes.fromhex(self.prefs["scope_key"]) if self.prefs["scope_key"] else None

    def send_flood(self, pkt, delay=0.0, scope=None):
        key = self.scope_key() if scope is None else scope
        pkt.path_len, pkt.path = int(self.cfg.path_hash_mode or 0) << 6, b""
        if key:
            pkt.header = (pkt.header & ~0x03) | ROUTE_TRANSPORT_FLOOD
            pkt.transport_codes = (transport_code(key, pkt), 0)
        else:
            pkt.header = (pkt.header & ~0x03) | ROUTE_FLOOD
        self._out(pkt, 2 if pkt.ptype == PT_PATH else 3 if pkt.ptype == PT_ADVERT else 1, delay)

    def send_direct(self, pkt, path, plen, delay=0.0):
        if self.room.vr is not None and plen & 63:
            path, plen = self.room.vr.strip_first_hops(path, plen)   # our own repeater is this radio: skip it
        pkt.header = (pkt.header & ~0x03) | ROUTE_DIRECT
        pkt.path_len, pkt.path = plen, path[:path_bytes(plen)]
        self._out(pkt, 1 if pkt.ptype == PT_PATH else 0, delay)

    def send_zero_hop(self, pkt, delay=0.0):
        pkt.header = (pkt.header & ~0x03) | ROUTE_DIRECT
        pkt.path_len, pkt.path = 0, b""
        self._out(pkt, 0, delay)

    def send_to(self, c, pkt, delay=0.0):
        if c.out_len is None:
            self.send_flood(pkt, delay)
        else:
            self.send_direct(pkt, c.out_path, c.out_len, delay)

    def _out(self, pkt, prio, delay):
        self.seen_mark(pkt)
        self.seq += 1
        heapq.heappush(self.outbox, (time.monotonic() + delay, self.seq, pkt, prio))

    def deliver(self, pkt, delay=0.0):
        """Something the room or the virtual repeater is sending: this node hears it (internally), when it's sent."""
        self.seq += 1
        heapq.heappush(self.inbox, (time.monotonic() + delay, self.seq, pkt))

    def service(self):
        now = time.monotonic()
        if getattr(self, "cfg_dirty", False) and now - getattr(self, "cfg_saved", 0.0) >= VC_SAVE_EVERY_S:
            self.cfg_dirty, self.cfg_saved = False, now
            self.cfg.save()
        while self.inbox and self.inbox[0][0] <= now:
            pkt = heapq.heappop(self.inbox)[2]
            pkt.snr, pkt.rssi = VIRTUAL_LINK_SNR, 0
            self.on_rx(pkt)
        while self.outbox and self.outbox[0][0] <= now:
            _, _, pkt, prio = heapq.heappop(self.outbox)
            self.room.companion_tx(pkt, prio)

    def est_timeout(self, pkt):
        t = self.room.airtime_ms(pkt.raw_length())
        if pkt.is_flood:
            return int(500 + 16 * t)
        return int(500 + (t * 6 + 250) * ((pkt.path_len & 63) + 1))

    def sent_frame(self, pkt, tag):
        return bytes([RESP_SENT, 1 if pkt.is_flood else 0]) + tag + struct.pack("<I", self.est_timeout(pkt))

    def make_datagram(self, ptype, c, data):
        return Packet(ptype, bytes([c.pub[0], self.pub[0]]) + encrypt_then_mac(self.secret(c), data))

    def make_path_return(self, c, path, plen, extra_type=None, extra=b""):
        if path_bytes(plen) + len(extra) + 5 > MAX_PACKET_PAYLOAD - 2 - CIPHER_BLOCK_SIZE:
            return None
        data = bytes([plen]) + path[:path_bytes(plen)]
        data += bytes([extra_type]) + extra if extra else b"\xFF" + os.urandom(4)
        return Packet(PT_PATH, bytes([c.pub[0], self.pub[0]]) + encrypt_then_mac(self.secret(c), data))

    def send_advert(self, flood):
        pkt = self.make_self_advert()
        if flood:
            key = bytes.fromhex(self.prefs["scope_key"]) if self.prefs["scope_key"] else None
            self.send_flood(pkt, scope=key or b"")
        else:
            self.send_zero_hop(pkt)
        log.info("virtual companion: sent %s advert", "flood" if flood else "zero-hop")

    # ---------------------------------------------------------------- what the room hands over

    def expects_ack(self, ack):
        """An ACK for this node: one it waits for, or another copy of one it just got (a room acknowledges twice,
        multipart then plain: both are for this node, and neither belongs on the air)."""
        now = time.monotonic()
        return any(e[0] == ack for e in self.expected) or any(cn["ack"] == ack for cn in self.connections.values()) \
            or any(a == ack and now - t < VC_ACK_COPY_S for a, t in self.acked)

    def claims(self, pkt):
        """Is this packet, about to be sent by the room or the virtual repeater, for this node? Then it's handed over
        instead of going on the air. Decides without changing anything (the packet is processed when it's due)."""
        t, p = pkt.ptype, pkt.payload
        if t == PT_TRACE:
            return pkt.is_direct and len(p) >= 9 and p[:4] in self.traces \
                and (pkt.path_len << (p[8] & 3)) >= len(p) - 9
        if pkt.is_direct and pkt.hop_count > 0:
            return False
        if t == PT_ACK:
            return len(p) >= 4 and self.expects_ack(p[:4])
        if t == PT_MULTIPART:
            return len(p) >= 5 and (p[0] & 0x0F) == PT_ACK and self.expects_ack(p[1:5])
        if t in (PT_PATH, PT_REQ, PT_RESPONSE, PT_TXT_MSG):
            if len(p) <= 2 + CIPHER_MAC_SIZE or p[0] != self.pub[0]:
                return False
            return any(mac_then_decrypt(self.secret(c), p[2:]) is not None
                       for tab in (self.contacts, self.anon) for c in tab.values() if c.pub[0] == p[1])
        return False

    # ---------------------------------------------------------------- receive (Mesh::onRecvPacket, no forwarding)

    def on_rx(self, pkt, raw=None):
        """A packet heard on the radio (raw given) or handed over internally. True if it was for this node (then the
        virtual repeater doesn't relay it)."""
        try:
            if raw is not None:
                self.stats["rx"] += 1
                if self.connected and len(raw) + 3 <= VC_MAX_FRAME:
                    self.write(bytes([PUSH_LOG_RX_DATA]) + snr4(pkt.snr) + struct.pack("b", max(-128, min(127, int(pkt.rssi)))) + raw)
            else:
                self.stats["internal_in"] += 1
            return self._rx(pkt)
        except Exception:
            log.exception("virtual companion")
            return False

    def _rx(self, pkt):
        t, p = pkt.ptype, pkt.payload
        if pkt.is_direct and t == PT_TRACE:
            return self.rx_trace(pkt)
        if pkt.is_direct and t == PT_CONTROL and p[:1] and p[0] & 0x80:
            if pkt.hop_count == 0:
                self.write(bytes([PUSH_CONTROL_DATA]) + snr4(pkt.snr) + struct.pack("b", max(-128, min(127, int(pkt.rssi))))
                           + bytes([pkt.path_len]) + p)
            return False
        if pkt.is_direct and pkt.hop_count > 0:
            if t == PT_ACK and len(p) >= 4:
                self.process_ack(p[:4])                     # an ACK on its way past us (firmware does this too)
            return False
        if t == PT_ACK:
            return len(p) >= 4 and not self.check_dup(pkt) and self.process_ack(p[:4], pkt)
        if t == PT_MULTIPART:
            if len(p) >= 5 and (p[0] & 0x0F) == PT_ACK:
                tmp = Packet(PT_ACK, p[1:])
                tmp.header, tmp.path_len, tmp.path = pkt.header, pkt.path_len, pkt.path
                return not self.check_dup(tmp) and self.process_ack(p[1:5], tmp)
            return False
        if t in (PT_PATH, PT_REQ, PT_RESPONSE, PT_TXT_MSG):
            return self.rx_peer(pkt)
        if t in (PT_GRP_TXT, PT_GRP_DATA):
            self.rx_group(pkt)
        elif t == PT_ADVERT:
            self.rx_advert(pkt)
        elif t == PT_RAW_CUSTOM and pkt.is_direct and not self.check_dup(pkt):
            self.write(bytes([PUSH_RAW_DATA]) + snr4(pkt.snr) + struct.pack("b", max(-128, min(127, int(pkt.rssi)))) + b"\xFF" + p)
        return False

    def rx_trace(self, pkt):
        p = pkt.payload
        if len(p) < 9 or pkt.path_len >= MAX_PATH_SIZE:
            return False
        flags = p[8]
        sz = flags & 3
        hashes = p[9:]
        if (pkt.path_len << sz) < len(hashes) or p[:4] not in self.traces:
            return False                                    # not at its end yet, or not one of ours
        del self.traces[p[:4]]
        self.write(bytes([PUSH_TRACE_DATA, 0, len(hashes), flags]) + p[:8] + hashes + pkt.path[:len(hashes) >> sz] + snr4(pkt.snr))
        return True

    def rx_peer(self, pkt):
        p = pkt.payload
        if len(p) <= 2 + CIPHER_MAC_SIZE or self.check_dup(pkt) or p[0] != self.pub[0]:
            return False
        for c in [c for tab in (self.contacts, self.anon) for c in tab.values() if c.pub[0] == p[1]]:
            data = mac_then_decrypt(self.secret(c), p[2:])
            if data is None:
                continue
            self.mark_active(c)
            if pkt.ptype == PT_PATH:
                self.rx_path(pkt, c, data)
            else:
                self.rx_data(pkt, c, data)
            return True
        return False

    def rx_path(self, pkt, c, data):
        plen = data[0]
        if not path_valid(plen):
            return
        k = 1 + path_bytes(plen)
        path = bytes(data[1:k])
        extra_type = data[k] & 0x0F if k < len(data) else 0xFF
        extra = data[k + 1:]
        if extra_type == PT_RESPONSE and len(extra) > 4 and extra[:4] == self.pending["discovery"]:
            self.pending["discovery"] = None                # path discovery answered: report both ways, no reciprocal path
            if path_valid(pkt.path_len):
                self.write(bytes([PUSH_PATH_DISCOVERY_RESPONSE, 0]) + c.pub[:6] + bytes([plen]) + path
                           + bytes([pkt.path_len]) + pkt.path[:path_bytes(pkt.path_len)])
            return
        c.out_len, c.out_path = plen, path
        c.lastmod = now_s()
        self.touch(c)
        self.write(bytes([PUSH_PATH_UPDATED]) + c.pub)
        if extra_type == PT_ACK and len(extra) >= 4:
            self.process_ack(extra[:4])
        elif extra_type == PT_RESPONSE and extra:
            self.on_response(c, extra)
        if pkt.is_flood:                                    # reciprocal path, sent direct on the path we were given
            pr = self.make_path_return(c, pkt.path, pkt.path_len)
            if pr:
                self.send_direct(pr, path, plen, 0.5)

    def rx_data(self, pkt, c, data):
        t = pkt.ptype
        if t == PT_TXT_MSG and len(data) > 5:
            ts = struct.unpack_from("<I", data, 0)[0]
            flags = data[4] >> 2
            text = data[5:].split(b"\0", 1)[0]
            if flags == TXT_TYPE_PLAIN:
                c.lastmod = now_s()
                self.touch(c)
                self.queue_msg(c, TXT_TYPE_PLAIN, pkt, ts, b"", text)
                tail = data[5 + len(text) + 1:5 + len(text) + 2] or b"\0"
                self.reply_ack(pkt, c, sha256(data[:5 + len(text)], c.pub)[:4] + tail + os.urandom(1))
            elif flags == TXT_TYPE_CLI_DATA:
                self.queue_msg(c, TXT_TYPE_CLI_DATA, pkt, ts, b"", text)
                if pkt.is_flood:
                    pr = self.make_path_return(c, pkt.path, pkt.path_len)
                    if pr:
                        self.send_flood(pr)
            elif flags == TXT_TYPE_SIGNED_PLAIN and len(data) > 9:
                if ts > c.sync_since:
                    c.sync_since = ts                       # room posts: where to resume after the next login
                c.lastmod = now_s()
                self.touch(c)
                text = data[9:].split(b"\0", 1)[0]
                self.queue_msg(c, TXT_TYPE_SIGNED_PLAIN, pkt, ts, data[5:9], text)
                self.reply_ack(pkt, c, sha256(data[:9 + len(text)], self.pub)[:4])
        elif t == PT_REQ and len(data) > 4:
            reply = self.on_request(c, data[:4], data[4:])
            if reply:
                if pkt.is_flood:
                    pr = self.make_path_return(c, pkt.path, pkt.path_len, PT_RESPONSE, reply)
                    if pr:
                        self.send_flood(pr, SERVER_RESPONSE_DELAY)
                else:
                    self.send_to(c, self.make_datagram(PT_RESPONSE, c, reply), SERVER_RESPONSE_DELAY)
        elif t == PT_RESPONSE and data:
            self.on_response(c, data)
            if pkt.is_flood and c.out_len is not None:
                self.return_path_retry(c, pkt)

    def return_path_retry(self, c, pkt):
        """They still flood though we have a route: they may have missed our path return, so send it again."""
        pr = self.make_path_return(c, pkt.path, pkt.path_len)
        if pr:
            self.send_direct(pr, c.out_path, c.out_len, 3.0)

    def reply_ack(self, pkt, c, ack):
        if pkt.is_flood:                                    # tell them the path to us, carrying the ACK
            pr = self.make_path_return(c, pkt.path, pkt.path_len, PT_ACK, ack)
            if pr:
                self.send_flood(pr, TXT_ACK_DELAY)
        elif c.out_len is None:
            self.send_flood(Packet(PT_ACK, ack), TXT_ACK_DELAY)
        else:
            d = TXT_ACK_DELAY
            if self.prefs["multi_acks"]:
                self.send_direct(Packet(PT_MULTIPART, bytes([(1 << 4) | PT_ACK]) + ack), c.out_path, c.out_len, d)
                d += 0.3
            self.send_direct(Packet(PT_ACK, ack), c.out_path, c.out_len, d)

    def on_request(self, c, tag, req):
        """Requests to us: telemetry only, as allowed by the app's telemetry settings (per-contact flags or all)."""
        if req[0] != REQ_GET_TELEMETRY_DATA:
            return None
        cp = c.flags >> 1
        perm = 0
        for mode, bit in ((self.prefs["telem_base"], 1), (self.prefs["telem_loc"], 2)):
            if mode == 2:
                perm |= bit
            elif mode == 1:
                perm |= cp & bit
        if len(req) > 1:
            perm &= ~req[1]                                 # the requester's inverse mask
        if not perm & 1:
            return None
        lpp = struct.pack(">BBH", 1, 116, int(self.room.batt_mv / 10))   # channel 1, voltage, 0.01 V
        lat, lon = float(self.cfg.companion_lat or 0), float(self.cfg.companion_lon or 0)
        if perm & 2 and (lat or lon):
            lpp += bytes([1, 136]) + int(lat * 1e4).to_bytes(3, "big", signed=True) \
                + int(lon * 1e4).to_bytes(3, "big", signed=True) + bytes(3)
        return tag + lpp

    def on_response(self, c, data):
        tag = data[:4]
        pl = self.pending
        if pl["login"] is not None and c.pub[:4] == pl["login"]:
            pl["login"] = None
            if data[4:6] == b"OK":                          # legacy repeater login
                f = bytes([PUSH_LOGIN_SUCCESS, 0]) + c.pub[:6]
            elif len(data) > 4 and data[4] == RESP_SERVER_LOGIN_OK:
                d = data.ljust(13, b"\0")
                if d[5]:
                    self.connections[c.pub] = dict(ka=d[5] * 16, next=time.monotonic() + d[5] * 16, ack=None, last=now_s())
                f = bytes([PUSH_LOGIN_SUCCESS, d[6]]) + c.pub[:6] + tag + bytes([d[7], d[12]])
            else:
                f = bytes([PUSH_LOGIN_FAIL, 0]) + c.pub[:6]
        elif len(data) > 4 and pl["status"] is not None and c.pub[:4] == pl["status"]:
            pl["status"] = None
            f = bytes([PUSH_STATUS_RESPONSE, 0]) + c.pub[:6] + data[4:]
        elif len(data) > 4 and tag == pl["telemetry"]:
            pl["telemetry"] = None
            f = bytes([PUSH_TELEMETRY_RESPONSE, 0]) + c.pub[:6] + data[4:]
        elif len(data) > 4 and tag == pl["req"]:
            pl["req"] = None
            f = bytes([PUSH_BINARY_RESPONSE, 0]) + tag + data[4:]
        else:
            return
        self.write(f)

    def process_ack(self, ack, pkt=None):
        for e in self.expected:
            if e[0] == ack:
                self.write(bytes([PUSH_SEND_CONFIRMED]) + ack + struct.pack("<I", int((time.monotonic() - e[1]) * 1000)))
                e[0] = None                                 # the same ACK can arrive more than once
                self.acked.append((ack, time.monotonic()))
                c = self.contacts.get(e[2])
                if pkt is not None and pkt.is_flood and c is not None and c.out_len is not None:
                    self.return_path_retry(c, pkt)
                return True
        for cn in self.connections.values():
            if cn["ack"] is not None and cn["ack"] == ack:
                cn["ack"], cn["last"], cn["next"] = None, now_s(), time.monotonic() + cn["ka"]
                return True
        return False

    def mark_active(self, c):
        cn = self.connections.get(c.pub)
        if cn is not None:
            cn["last"], cn["next"] = now_s(), time.monotonic() + cn["ka"]

    def rx_group(self, pkt):
        p = pkt.payload
        if len(p) <= 3 or self.check_dup(pkt):
            return
        for idx in sorted(self.channels):
            name, key = self.channels[idx]
            if not any(key) or channel_hash(key) != p[0]:
                continue
            data = mac_then_decrypt(key + bytes(16), p[1:])
            if data is None:
                continue
            plen = pkt.path_len if pkt.is_flood else 0xFF
            if pkt.ptype == PT_GRP_TXT:
                if len(data) < 5 or data[4] >> 2:
                    return
                text = data[5:].split(b"\0", 1)[0]
                f = bytes([RESP_CHANNEL_MSG_RECV_V3]) + snr4(pkt.snr) + bytes([0, 0, idx, plen, TXT_TYPE_PLAIN]) + data[:4] + text
            else:
                if len(data) < 3 or data[2] > len(data) - 3 or data[2] > VC_MAX_FRAME - 9:
                    return
                f = bytes([RESP_CHANNEL_DATA_RECV]) + snr4(pkt.snr) + bytes([0, 0, idx, plen]) + data[:3] + data[3:3 + data[2]]
            self.enqueue(f)
            return

    def rx_advert(self, pkt):
        p = pkt.payload
        if len(p) < PUB_KEY_SIZE + 4 + SIGNATURE_SIZE or p[:32] == self.pub or self.check_dup(pkt):
            return
        a = RoomServer.parse_advert(pkt)
        if a is None or not a["name"]:
            return
        pub = a["pub"]
        c = self.contacts.get(pub)
        if c is not None and a["ts"] <= c.adv_ts:
            return                                          # replayed
        self.anon.pop(pub, None)
        if path_valid(pkt.path_len):
            k7 = pub[:7]
            self.advert_paths.pop(k7, None)
            self.advert_paths[k7] = (now_s(), pkt.path_len, pkt.path[:path_bytes(pkt.path_len)])
            while len(self.advert_paths) > VC_ADVERT_PATHS:
                self.advert_paths.popitem(last=False)
        saved = Packet()                                    # kept for export / share: flood route, no transport codes
        saved.header = (pkt.header & ~0x03) | ROUTE_FLOOD
        saved.path_len, saved.path, saved.payload = pkt.path_len, pkt.path, pkt.payload
        if c is None:
            new = VCContact(pub)
            self.fill_from_advert(new, a, saved)
            if not self.auto_add(a["type"]) or (self.prefs["autoadd_max_hops"] and pkt.hop_count >= self.prefs["autoadd_max_hops"]):
                self.write(new.frame(PUSH_NEW_ADVERT))      # the app may add it
                return
            if not self.add_contact(new):
                self.write(new.frame(PUSH_NEW_ADVERT))
                self.write(bytes([PUSH_CONTACTS_FULL]))
                return
            c = new
        else:
            self.fill_from_advert(c, a, saved)
        self.touch(c)
        self.write(bytes([PUSH_ADVERT]) + pub)

    @staticmethod
    def fill_from_advert(c, a, saved):
        c.name = a["name"]
        c.type = a["type"]
        if a["lat"] is not None:
            c.lat, c.lon = int(round(a["lat"] * 1e6)), int(round(a["lon"] * 1e6))
        c.adv_ts = a["ts"]
        c.lastmod = now_s()
        c.advert = saved.encode()

    def auto_add(self, atype):
        if not self.prefs["manual_add"] & 1:
            return True
        bit = {ADV_TYPE_CHAT: 2, ADV_TYPE_REPEATER: 4, ADV_TYPE_ROOM: 8, ADV_TYPE_SENSOR: 16}.get(atype)
        return bool(bit and self.prefs["autoadd_config"] & bit)

    def add_contact(self, c):
        if len(self.contacts) >= VC_MAX_CONTACTS:
            if not self.prefs["autoadd_config"] & 1:
                return False
            olds = [x for x in self.contacts.values() if not x.flags & 1]
            if not olds:
                return False
            old = min(olds, key=lambda x: x.lastmod)        # overwrite the oldest non-favourite
            self.remove_contact(old.pub)
            self.write(bytes([PUSH_CONTACT_DELETED]) + old.pub)
        self.contacts[c.pub] = c
        self.touch(c)
        return True

    def remove_contact(self, pub):
        self.contacts.pop(pub, None)
        self.dirty.discard(pub)
        self.connections.pop(pub, None)
        self.store.delete_contact(pub)

    # ---------------------------------------------------------------- messages for the app

    def queue_msg(self, c, txt_type, pkt, ts, extra, text):
        self.stats["msgs_in"] += 1
        plen = pkt.path_len if pkt.is_flood else 0xFF
        self.enqueue(bytes([RESP_CONTACT_MSG_RECV_V3]) + snr4(pkt.snr) + bytes([0, 0]) + c.pub[:6]
                     + bytes([plen, txt_type]) + struct.pack("<I", ts) + extra + text)

    def enqueue(self, frame):
        """Kept (in companion.db) until the app fetches it. Stored in the v3 layout; older apps get it converted."""
        frame = frame[:VC_MAX_FRAME]
        if len(self.queue) >= VC_QUEUE_MAX:
            drop = next((e for e in self.queue if e[1][0] in (RESP_CHANNEL_MSG_RECV_V3, RESP_CHANNEL_DATA_RECV)), self.queue[0])
            self.queue.remove(drop)                         # full: the oldest channel message goes first
            self.store.queue_remove(drop[0])
        self.queue.append((self.store.queue_add(frame), frame))
        if self.connected:
            self.write(bytes([PUSH_MSG_WAITING]))

    # ---------------------------------------------------------------- periodic

    def periodic(self):
        now = time.monotonic()
        c = self.cfg
        iv = float(c.companion_advert_interval_min or 0)
        if c.companion_auto_advert and iv > 0 and now >= self.next_advert:
            self.send_advert(bool(c.companion_advert_flood))
            self.next_advert = now + iv * 60
        elif not c.companion_auto_advert:
            self.next_advert = now + 10                     # turned on: first advert soon after
        for pub, cn in list(self.connections.items()):      # keep-alives to servers that asked for them (checkConnections)
            if now_s() >= cn["last"] + cn["ka"] * 5 // 2:
                del self.connections[pub]
                continue
            ct = self.contacts.get(pub)
            if now < cn["next"] or ct is None or ct.out_len is None:
                continue
            data = struct.pack("<I", self.unique_time()) + bytes([REQ_KEEP_ALIVE]) + struct.pack("<I", ct.sync_since)
            cn["ack"] = sha256(data, self.pub)[:4]
            self.send_direct(self.make_datagram(PT_REQ, ct, data), ct.out_path, ct.out_len)
            cn["next"] = now + cn["ka"]
        for tag in [t for t, exp in self.traces.items() if exp < now]:
            del self.traces[tag]
        if now >= self.next_flush:
            self.flush()
            self.next_flush = now + 15

    def state(self):
        link = self.link
        return dict(listening=link is not None, error=self.link_error, client=link is not None and link.connected(),
                    listen_port=link.port if link is not None else None,
                    contacts=len(self.contacts), channels=sum(1 for n, k in self.channels.values() if any(k)),
                    queued=len(self.queue), **self.stats)

    # ---------------------------------------------------------------- app commands (MyMesh::handleCmdFrame)

    def on_frame(self, f):
        self.stats["frames"] += 1
        if not f:
            return
        cmd = f[0]
        if cmd in VC_IGNORED:
            self.stats["ignored"] += 1
            if cmd not in self.ignored_logged:
                self.ignored_logged.add(cmd)
                log.info("virtual companion: the app sent a %s change - acknowledged and ignored (pyMeshRoom manages "
                         "the radio)", VC_IGNORED[cmd])
            if cmd == CMD_RUN_CLI_COMMAND:
                return self.write(bytes([RESP_CLI_REPLY]) + b"OK")
            return self.ok()
        h = self.HANDLERS.get(cmd)
        if h is None:
            return self.err(ERR_UNSUPPORTED_CMD)
        if cmd in VC_TX_CMDS and not self.tx_allowed(cmd):
            self.stats["tx_limited"] = self.stats.get("tx_limited", 0) + 1
            return self.err(ERR_TABLE_FULL)                 # (the app shows the send as failed)
        try:
            h(self, f)
        except (IndexError, struct.error, ValueError):
            self.err(ERR_ILLEGAL_ARG)

    def tx_allowed(self, cmd):
        """The app's transmissions: a token bucket (VC_TX_BURST, one more every VC_TX_EVERY_S), and adverts at most
        every VC_ADVERT_EVERY_S, so an app (or anyone on the port) can't make the radio flood the mesh. What the
        companion sends by itself (ACKs, path returns, auto adverts) isn't counted."""
        now = time.monotonic()
        tokens, last = getattr(self, "tx_bucket", (VC_TX_BURST, now))
        tokens = min(VC_TX_BURST, tokens + (now - last) / VC_TX_EVERY_S)
        if cmd == CMD_SEND_SELF_ADVERT:
            if now - getattr(self, "last_app_advert", -1e9) < VC_ADVERT_EVERY_S:
                self.tx_bucket = (tokens, now)
                return False
            self.last_app_advert = now
        if tokens < 1:
            self.tx_bucket = (tokens, now)
            return False
        self.tx_bucket = (tokens - 1, now)
        return True

    def c_device_query(self, f):
        if len(f) < 2:
            return self.err(ERR_UNSUPPORTED_CMD)
        if self.prefs["app_ver"] != f[1]:
            self.prefs["app_ver"] = f[1]
            self.save_prefs()
        self.write(bytes([RESP_DEVICE_INFO, VC_FIRMWARE_VER_CODE, VC_MAX_CONTACTS // 2, VC_MAX_CHANNELS]) + struct.pack("<I", 0)
                   + b"pyMeshRoom".ljust(12, b"\0") + b"pyMeshRoom virtual companion".ljust(40, b"\0")
                   + FIRMWARE_VERSION.encode()[:19].ljust(20, b"\0") + bytes([0, int(self.cfg.path_hash_mode or 0)]))

    def c_app_start(self, f):
        if len(f) < 8:
            return self.err(ERR_UNSUPPORTED_CMD)
        r = self.room
        freq, bw, sf, cr = r.radio if r.radio else r.wanted_radio()
        txp = r.cfg.radio_tx_power_dbm if r.cfg.radio_tx_power_dbm is not None else 22
        pr = self.prefs
        lat, lon = float(self.cfg.companion_lat or 0), float(self.cfg.companion_lon or 0)
        self.write(bytes([RESP_SELF_INFO, ADV_TYPE_CHAT, int(txp) & 0xFF, 22]) + self.pub
                   + struct.pack("<ii", int(lat * 1e6), int(lon * 1e6))
                   + bytes([pr["multi_acks"], pr["advert_loc_policy"], (pr["telem_env"] << 4) | (pr["telem_loc"] << 2) | pr["telem_base"],
                            pr["manual_add"]])
                   + struct.pack("<IIBB", freq // 1000, bw, sf, cr) + utf8_cut(str(self.cfg.companion_name).encode(), 31))

    def c_send_txt_msg(self, f):
        if len(f) < 14:
            return self.err(ERR_UNSUPPORTED_CMD)
        txt_type, attempt, ts = f[1], f[2], f[3:7]
        c = self.find(f[7:13])
        if c is None or txt_type not in (TXT_TYPE_PLAIN, TXT_TYPE_CLI_DATA):
            return self.err(ERR_NOT_FOUND if c is None else ERR_UNSUPPORTED_CMD)
        text = f[13:].split(b"\0", 1)[0]
        if len(text) > VC_MAX_TEXT_LEN or (attempt > 3 and len(text) > VC_MAX_TEXT_LEN - 2):
            return self.err(ERR_TABLE_FULL)
        if txt_type == TXT_TYPE_CLI_DATA:                   # the node's clock, not the app's (replay protection)
            data = struct.pack("<I", self.unique_time()) + bytes([(attempt & 3) | (TXT_TYPE_CLI_DATA << 2)]) + text
            ack = bytes(4)
        else:
            data = ts + bytes([attempt & 3]) + text
            ack = sha256(data, self.pub)[:4]
            if attempt > 3:
                data += b"\0" + bytes([attempt])            # the attempt number, hidden after the text
        pkt = self.make_datagram(PT_TXT_MSG, c, data)
        self.send_to(c, pkt)
        if txt_type == TXT_TYPE_PLAIN:
            self.expected.append([ack, time.monotonic(), c.pub])
        self.stats["msgs_out"] += 1
        self.write(self.sent_frame(pkt, ack))

    def c_send_channel_txt_msg(self, f):
        if len(f) < 7 or f[1] != TXT_TYPE_PLAIN:
            return self.err(ERR_UNSUPPORTED_CMD)
        ch = self.channels.get(f[2])
        if ch is None or not any(ch[1]):
            return self.err(ERR_NOT_FOUND)
        prefix = (str(self.cfg.companion_name) + ": ").encode()
        text = f[7:].split(b"\0", 1)[0][:max(0, VC_MAX_TEXT_LEN - len(prefix))]
        key = ch[1]
        self.send_flood(Packet(PT_GRP_TXT, bytes([channel_hash(key)]) + encrypt_then_mac(key + bytes(16), f[3:7] + b"\0" + prefix + text)))
        self.stats["msgs_out"] += 1
        self.ok()

    def c_send_channel_data(self, f):
        if len(f) < 4:
            return self.err(ERR_ILLEGAL_ARG)
        idx, plen, i = f[1], f[2], 3
        if plen != 0xFF and not path_valid(plen):
            return self.err(ERR_ILLEGAL_ARG)
        path = b""
        if plen != 0xFF:
            path = f[i:i + path_bytes(plen)]
            i += path_bytes(plen)
        dtype = f[i:i + 2]
        payload = f[i + 2:]
        ch = self.channels.get(idx)
        if ch is None or not any(ch[1]):
            return self.err(ERR_NOT_FOUND)
        if len(dtype) < 2 or dtype == b"\0\0" or len(payload) > VC_MAX_FRAME - 9:
            return self.err(ERR_ILLEGAL_ARG)
        key = ch[1]
        pkt = Packet(PT_GRP_DATA, bytes([channel_hash(key)]) + encrypt_then_mac(key + bytes(16), dtype + bytes([len(payload)]) + payload))
        if plen == 0xFF:
            self.send_flood(pkt)
        else:
            self.send_direct(pkt, path, plen)
        self.ok()

    def c_get_contacts(self, f):
        since = struct.unpack_from("<I", f, 1)[0] if len(f) >= 5 else 0
        self.write(bytes([RESP_CONTACTS_START]) + struct.pack("<I", len(self.contacts)))
        latest = 0
        for c in list(self.contacts.values()):
            if c.lastmod > since:
                self.write(c.frame(RESP_CONTACT))
                latest = max(latest, c.lastmod)
        self.write(bytes([RESP_END_OF_CONTACTS]) + struct.pack("<I", latest))

    def c_set_advert_name(self, f):
        if len(f) < 2:
            return self.err(ERR_UNSUPPORTED_CMD)
        name = utf8_cut(f[1:].split(b"\0", 1)[0], 31).decode(errors="ignore").strip()
        if not name:
            return self.err(ERR_ILLEGAL_ARG)
        if name != self.cfg.companion_name:
            self.cfg.set("companion_name", name, save=False)
            self.cfg_dirty = True                           # (saved by service(), at most every VC_SAVE_EVERY_S)
        self.ok()

    def c_set_advert_latlon(self, f):
        if len(f) < 9:
            return self.err(ERR_UNSUPPORTED_CMD)
        lat, lon = struct.unpack_from("<ii", f, 1)
        if not (-90e6 <= lat <= 90e6 and -180e6 <= lon <= 180e6):
            return self.err(ERR_ILLEGAL_ARG)
        if (lat / 1e6, lon / 1e6) != (self.cfg.companion_lat, self.cfg.companion_lon):
            self.cfg.set("companion_lat", lat / 1e6, save=False)
            self.cfg.set("companion_lon", lon / 1e6, save=False)
            self.cfg_dirty = True
        self.ok()

    def c_get_device_time(self, f):
        self.write(bytes([RESP_CURR_TIME]) + struct.pack("<I", now_s()))

    def c_send_self_advert(self, f):
        self.send_advert(len(f) >= 2 and f[1] == 1)
        self.ok()

    def c_reset_path(self, f):
        c = self.contacts.get(f[1:33]) if len(f) >= 33 else None
        if c is None:
            return self.err(ERR_NOT_FOUND)
        c.out_len, c.out_path = None, b""
        self.touch(c)
        self.ok()

    def c_add_update_contact(self, f):
        if len(f) < 36:
            return self.err(ERR_UNSUPPORTED_CMD)
        pub = bytes(f[1:33])
        d = f.ljust(148, b"\0")
        c = self.contacts.get(pub)
        new = c is None
        if new:
            c = self.anon.pop(pub, None) or VCContact(pub)
            c.sync_since = 0
        c.type, c.flags = d[33], d[34]
        plen = d[35]
        c.out_len = None if plen == 0xFF or not path_valid(plen) else plen
        c.out_path = bytes(d[36:36 + path_bytes(plen)]) if c.out_len is not None else b""
        c.name = d[100:132].split(b"\0", 1)[0].decode(errors="replace")
        c.adv_ts = struct.unpack_from("<I", d, 132)[0]
        if len(f) >= 144:
            c.lat, c.lon = struct.unpack_from("<ii", d, 136)
        c.lastmod = struct.unpack_from("<I", d, 144)[0] if len(f) >= 148 else now_s()
        if new and not self.add_contact(c):
            return self.err(ERR_TABLE_FULL)
        self.touch(c)
        self.ok()

    def c_remove_contact(self, f):
        pub = bytes(f[1:33])
        if pub not in self.contacts:
            return self.err(ERR_NOT_FOUND)
        self.remove_contact(pub)
        self.ok()

    def c_share_contact(self, f):
        c = self.contacts.get(bytes(f[1:33]))
        if c is None:
            return self.err(ERR_NOT_FOUND)
        pkt = Packet.parse(c.advert) if c.advert else None
        if pkt is None:
            return self.err(ERR_TABLE_FULL)
        pkt.header = (pkt.header & ~0x03) | ROUTE_TRANSPORT_DIRECT
        pkt.transport_codes = (0, 0)                        # { 0, 0 }: "send this nowhere" (repeaters don't relay it)
        pkt.path_len, pkt.path = 0, b""
        self._out(pkt, 0, 0.0)
        self.ok()

    def c_get_contact_by_key(self, f):
        c = self.contacts.get(bytes(f[1:33]))
        if c is None:
            return self.err(ERR_NOT_FOUND)
        self.write(c.frame(RESP_CONTACT))

    def c_export_contact(self, f):
        if len(f) < 1 + PUB_KEY_SIZE:
            pkt = self.make_self_advert()
            pkt.header = (pkt.header & ~0x03) | ROUTE_FLOOD
            return self.write(bytes([RESP_EXPORT_CONTACT]) + pkt.encode())
        c = self.contacts.get(bytes(f[1:33]))
        if c is None or not c.advert:
            return self.err(ERR_NOT_FOUND)
        self.write(bytes([RESP_EXPORT_CONTACT]) + c.advert)

    def c_import_contact(self, f):
        pkt = Packet.parse(bytes(f[1:])) if len(f) > 2 + 32 + 64 else None
        if pkt is None or pkt.ptype != PT_ADVERT:
            return self.err(ERR_ILLEGAL_ARG)
        pkt.header = (pkt.header & ~0x03) | ROUTE_FLOOD    # as if received flood-mode
        self.seen.pop(pkt.packet_hash(), None)
        self.rx_advert(pkt)
        self.ok()

    def c_sync_next_message(self, f):
        if not self.queue:
            return self.write(bytes([RESP_NO_MORE_MESSAGES]))
        qid, frame = self.queue.pop(0)
        self.store.queue_remove(qid)
        if self.prefs["app_ver"] < 3 and frame[0] in (RESP_CONTACT_MSG_RECV_V3, RESP_CHANNEL_MSG_RECV_V3):
            frame = bytes([RESP_CONTACT_MSG_RECV if frame[0] == RESP_CONTACT_MSG_RECV_V3 else RESP_CHANNEL_MSG_RECV]) + frame[4:]
        self.write(frame)

    def c_get_tuning_params(self, f):
        self.write(bytes([RESP_TUNING_PARAMS]) + struct.pack("<II", 0, 1000))

    def c_set_other_params(self, f):
        if len(f) < 2:
            return self.err(ERR_ILLEGAL_ARG)
        pr = self.prefs
        pr["manual_add"] = f[1]
        if len(f) >= 3:
            pr["telem_base"], pr["telem_loc"], pr["telem_env"] = f[2] & 3, (f[2] >> 2) & 3, (f[2] >> 4) & 3
        if len(f) >= 4:
            pr["advert_loc_policy"] = f[3]
        if len(f) >= 5:
            pr["multi_acks"] = f[4]
        self.save_prefs()
        self.ok()

    def c_get_batt_and_storage(self, f):
        try:
            used = os.path.getsize(self.store.path) // 1024
            import shutil
            total = (shutil.disk_usage(os.path.dirname(os.path.abspath(self.store.path))).free // 1024) + used
        except OSError:
            used = total = 0
        self.write(bytes([RESP_BATT_AND_STORAGE]) + struct.pack("<HII", self.room.batt_mv & 0xFFFF, min(used, 0xFFFFFFFF),
                                                                 min(total, 0xFFFFFFFF)))

    def c_export_private_key(self, f):
        self.write(bytes([RESP_DISABLED]))                  # as default firmware: the key never leaves the server

    def _request(self, c, data, flood=False):
        pkt = self.make_datagram(PT_REQ, c, data)
        if flood:
            self.send_flood(pkt)
        else:
            self.send_to(c, pkt)
        return pkt

    def c_send_login(self, f):
        if len(f) < 1 + PUB_KEY_SIZE:
            return self.err(ERR_UNSUPPORTED_CMD)
        c = self.contacts.get(bytes(f[1:33]))
        if c is None:
            return self.err(ERR_NOT_FOUND)
        pw = f[33:].split(b"\0", 1)[0][:15]
        data = struct.pack("<I", self.unique_time()) + (struct.pack("<I", c.sync_since) if c.type == ADV_TYPE_ROOM else b"") + pw
        pkt = Packet(PT_ANON_REQ, bytes([c.pub[0]]) + self.pub + encrypt_then_mac(self.secret(c), data))
        self.send_to(c, pkt)
        self.pending = dict.fromkeys(self.pending)
        self.pending["login"] = c.pub[:4]
        self.write(self.sent_frame(pkt, c.pub[:4]))

    def c_send_anon_req(self, f):
        if len(f) <= 1 + PUB_KEY_SIZE:
            return self.err(ERR_UNSUPPORTED_CMD)
        pub = bytes(f[1:33])
        c = self.contact(pub)
        if c is None:                                       # firmware v13: requests to non-contacts, zero-hop direct
            c = self.anon[pub] = VCContact(pub)
            c.out_len, c.lastmod = 0, now_s()
            while len(self.anon) > 8:
                self.anon.pop(next(iter(self.anon)))
        tag = struct.pack("<I", self.unique_time())
        pkt = Packet(PT_ANON_REQ, bytes([c.pub[0]]) + self.pub + encrypt_then_mac(self.secret(c), tag + f[33:]))
        self.send_to(c, pkt)
        self.pending = dict.fromkeys(self.pending)
        self.pending["req"] = tag
        self.write(self.sent_frame(pkt, tag))

    def c_send_status_req(self, f):
        c = self.contacts.get(bytes(f[1:33])) if len(f) >= 33 else None
        if c is None:
            return self.err(ERR_NOT_FOUND)
        tag = struct.pack("<I", self.unique_time())
        pkt = self._request(c, tag + bytes([REQ_GET_STATUS]) + bytes(4) + os.urandom(4))
        self.pending = dict.fromkeys(self.pending)
        self.pending["status"] = c.pub[:4]                  # (legacy matching, as firmware)
        self.write(self.sent_frame(pkt, tag))

    def c_send_path_discovery_req(self, f):
        if len(f) < 2 + PUB_KEY_SIZE or f[1] != 0:
            return self.err(ERR_UNSUPPORTED_CMD)
        c = self.contacts.get(bytes(f[2:34]))
        if c is None:
            return self.err(ERR_NOT_FOUND)
        tag = struct.pack("<I", self.unique_time())         # a flooded request for base telemetry
        pkt = self._request(c, tag + bytes([REQ_GET_TELEMETRY_DATA, 0xFE, 0, 0, 0]) + os.urandom(4), flood=True)
        self.pending = dict.fromkeys(self.pending)
        self.pending["discovery"] = tag
        self.write(self.sent_frame(pkt, tag))

    def c_send_telemetry_req(self, f):
        if len(f) == 4:                                     # our own telemetry
            lpp = struct.pack(">BBH", 1, 116, int(self.room.batt_mv / 10))
            return self.write(bytes([PUSH_TELEMETRY_RESPONSE, 0]) + self.pub[:6] + lpp)
        c = self.contacts.get(bytes(f[4:36])) if len(f) >= 4 + PUB_KEY_SIZE else None
        if c is None:
            return self.err(ERR_NOT_FOUND)
        tag = struct.pack("<I", self.unique_time())
        pkt = self._request(c, tag + bytes([REQ_GET_TELEMETRY_DATA]) + bytes(4) + os.urandom(4))
        self.pending = dict.fromkeys(self.pending)
        self.pending["telemetry"] = tag
        self.write(self.sent_frame(pkt, tag))

    def c_send_binary_req(self, f):
        if len(f) < 2 + PUB_KEY_SIZE:
            return self.err(ERR_UNSUPPORTED_CMD)
        c = self.contacts.get(bytes(f[1:33]))
        if c is None:
            return self.err(ERR_NOT_FOUND)
        if len(f) - 33 > MAX_PACKET_PAYLOAD - 16:
            return self.err(ERR_TABLE_FULL)
        tag = struct.pack("<I", self.unique_time())
        pkt = self._request(c, tag + bytes(f[33:]))
        self.pending = dict.fromkeys(self.pending)
        self.pending["req"] = tag
        self.write(self.sent_frame(pkt, tag))

    def c_has_connection(self, f):
        if bytes(f[1:33]) in self.connections:
            return self.ok()
        self.err(ERR_NOT_FOUND)

    def c_logout(self, f):
        self.connections.pop(bytes(f[1:33]), None)
        self.ok()

    def c_get_channel(self, f):
        if len(f) < 2 or f[1] >= VC_MAX_CHANNELS:
            return self.err(ERR_NOT_FOUND)
        name, key = self.channels.get(f[1], ("", bytes(16)))
        self.write(bytes([RESP_CHANNEL_INFO, f[1]]) + utf8_cut(name.encode(), 31).ljust(32, b"\0") + key)

    def c_set_channel(self, f):
        if len(f) >= 2 + 32 + 32:
            return self.err(ERR_UNSUPPORTED_CMD)            # 256-bit channel keys: not supported (as firmware)
        if len(f) < 2 + 32 + 16:
            return self.err(ERR_UNSUPPORTED_CMD)
        idx = f[1]
        if idx >= VC_MAX_CHANNELS:
            return self.err(ERR_NOT_FOUND)
        name = utf8_cut(f[2:34].split(b"\0", 1)[0], 31).decode(errors="replace")
        key = bytes(f[34:50])
        if name or any(key):
            self.channels[idx] = (name, key)
        else:
            self.channels.pop(idx, None)
        self.store.save_channel(idx, name, key)
        self.ok()

    def c_sign_start(self, f):
        self.sign_buf = bytearray()
        self.write(bytes([RESP_SIGN_START, 0]) + struct.pack("<I", VC_MAX_SIGN))

    def c_sign_data(self, f):
        if self.sign_buf is None:
            return self.err(ERR_BAD_STATE)
        if len(self.sign_buf) + len(f) - 1 > VC_MAX_SIGN:
            return self.err(ERR_TABLE_FULL)
        self.sign_buf += f[1:]
        self.ok()

    def c_sign_finish(self, f):
        if self.sign_buf is None:
            return self.err(ERR_BAD_STATE)
        data = bytes(self.sign_buf)
        self.sign_buf = None
        if data[:PUB_KEY_SIZE] == self.pub or data.startswith(WEB_LOGIN_LABEL.encode()):
            # an advert is signed over our key + time + app data, and a MeshCore Web login starts with its label: a
            # signature over either would let whoever asked impersonate this node (until the key is changed)
            log.warning("virtual companion: refused to sign an advert or a web login for %s", self.link.peer
                        if getattr(self, "link", None) else "the app")
            return self.err(ERR_ILLEGAL_ARG)
        sig = self.id.sign(data)
        self.write(bytes([RESP_SIGNATURE]) + sig)

    def c_send_trace_path(self, f):
        n = len(f) - 10
        if n <= 0 or n >= MAX_PACKET_PAYLOAD - 5:
            return self.err(ERR_UNSUPPORTED_CMD)
        flags = f[9]
        sz = flags & 3
        if sz == 3 or (n >> sz) > MAX_PATH_SIZE or n % (1 << sz):
            return self.err(ERR_ILLEGAL_ARG)
        tag = bytes(f[1:5])
        pkt = Packet(PT_TRACE, bytes(f[1:10]) + bytes(f[10:]))   # the route rides in the payload; path_len counts SNRs
        pkt.header = (pkt.header & ~0x03) | ROUTE_DIRECT
        self.traces[tag] = time.monotonic() + 120
        self._out(pkt, 5, 0.0)
        t = self.room.airtime_ms(pkt.raw_length())
        self.write(bytes([RESP_SENT, 0]) + tag + struct.pack("<I", int(500 + (t * 6 + 250) * ((n >> sz) + 1))))

    def c_get_custom_vars(self, f):
        self.write(bytes([RESP_CUSTOM_VARS]))

    def c_set_custom_var(self, f):
        self.err(ERR_ILLEGAL_ARG)

    def c_get_advert_path(self, f):
        if len(f) < PUB_KEY_SIZE + 2:
            return self.err(ERR_UNSUPPORTED_CMD)
        e = self.advert_paths.get(bytes(f[2:9]))
        if e is None:
            return self.err(ERR_NOT_FOUND)
        self.write(bytes([RESP_ADVERT_PATH]) + struct.pack("<I", e[0]) + bytes([e[1]]) + e[2])

    def c_get_stats(self, f):
        if len(f) < 2:
            return self.err(ERR_ILLEGAL_ARG)
        r, s = self.room, self.room.stats
        if f[1] == 0:
            out = struct.pack("<HIHB", r.batt_mv & 0xFFFF, int(time.monotonic() - r.boot), 0, min(len(r.txq), 255))
        elif f[1] == 1:
            out = struct.pack("<hbbII", int(r.noise_floor), max(-128, min(127, int(r.last_rssi))),
                              max(-128, min(127, int(r.last_snr * 4))), s["airtime_ms"] // 1000, r.rx_airtime_ms // 1000)
        elif f[1] == 2:
            out = struct.pack("<7I", *(s[k] & 0xFFFFFFFF for k in ("recv", "sent", "sent_flood", "sent_direct",
                                                                   "recv_flood", "recv_direct", "errors")))
        else:
            return self.err(ERR_ILLEGAL_ARG)
        self.write(bytes([RESP_STATS, f[1]]) + out)

    def c_set_flood_scope_key(self, f):
        if len(f) < 2 or f[1] not in (0, 1):
            return self.err(ERR_UNSUPPORTED_CMD)
        if f[1] == 1:
            self.send_unscoped = True
        else:
            self.send_scope = bytes(f[2:18]) if len(f) >= 18 else None
            self.send_unscoped = False
        self.ok()

    def c_set_default_flood_scope(self, f):
        if len(f) >= 1 + 31 + 16:
            name = f[1:32].split(b"\0", 1)[0]
            if not 0 < len(name) < 31:
                return self.err(ERR_ILLEGAL_ARG)
            self.prefs["scope_name"], self.prefs["scope_key"] = name.decode(errors="replace"), bytes(f[32:48]).hex()
        else:
            self.prefs["scope_name"], self.prefs["scope_key"] = "", ""
        self.save_prefs()
        self.ok()

    def c_get_default_flood_scope(self, f):
        if self.prefs["scope_name"]:
            return self.write(bytes([RESP_DEFAULT_FLOOD_SCOPE]) + self.prefs["scope_name"].encode()[:30].ljust(31, b"\0")
                              + bytes.fromhex(self.prefs["scope_key"]))
        self.write(bytes([RESP_DEFAULT_FLOOD_SCOPE]))

    def c_send_control_data(self, f):
        if len(f) < 2 or not f[1] & 0x80:
            return self.err(ERR_UNSUPPORTED_CMD)
        self.send_zero_hop(Packet(PT_CONTROL, bytes(f[1:])))
        self.ok()

    def c_set_autoadd_config(self, f):
        if len(f) < 2:
            return self.err(ERR_ILLEGAL_ARG)
        self.prefs["autoadd_config"] = f[1]
        if len(f) >= 3:
            self.prefs["autoadd_max_hops"] = min(f[2], 64)
        self.save_prefs()
        self.ok()

    def c_get_autoadd_config(self, f):
        self.write(bytes([RESP_AUTOADD_CONFIG, self.prefs["autoadd_config"], self.prefs["autoadd_max_hops"]]))

    def c_get_allowed_repeat_freq(self, f):
        self.write(bytes([RESP_ALLOWED_REPEAT_FREQ]))       # none: the companion never repeats

    HANDLERS = {
        CMD_DEVICE_QUERY: c_device_query, CMD_APP_START: c_app_start, CMD_SEND_TXT_MSG: c_send_txt_msg,
        CMD_SEND_CHANNEL_TXT_MSG: c_send_channel_txt_msg, CMD_SEND_CHANNEL_DATA: c_send_channel_data,
        CMD_GET_CONTACTS: c_get_contacts, CMD_SET_ADVERT_NAME: c_set_advert_name, CMD_SET_ADVERT_LATLON: c_set_advert_latlon,
        CMD_GET_DEVICE_TIME: c_get_device_time, CMD_SEND_SELF_ADVERT: c_send_self_advert, CMD_RESET_PATH: c_reset_path,
        CMD_ADD_UPDATE_CONTACT: c_add_update_contact, CMD_REMOVE_CONTACT: c_remove_contact, CMD_SHARE_CONTACT: c_share_contact,
        CMD_GET_CONTACT_BY_KEY: c_get_contact_by_key, CMD_EXPORT_CONTACT: c_export_contact, CMD_IMPORT_CONTACT: c_import_contact,
        CMD_SYNC_NEXT_MESSAGE: c_sync_next_message, CMD_GET_TUNING_PARAMS: c_get_tuning_params,
        CMD_SET_OTHER_PARAMS: c_set_other_params, CMD_GET_BATT_AND_STORAGE: c_get_batt_and_storage,
        CMD_EXPORT_PRIVATE_KEY: c_export_private_key, CMD_SEND_LOGIN: c_send_login, CMD_SEND_ANON_REQ: c_send_anon_req,
        CMD_SEND_STATUS_REQ: c_send_status_req, CMD_SEND_PATH_DISCOVERY_REQ: c_send_path_discovery_req,
        CMD_SEND_TELEMETRY_REQ: c_send_telemetry_req, CMD_SEND_BINARY_REQ: c_send_binary_req,
        CMD_HAS_CONNECTION: c_has_connection, CMD_LOGOUT: c_logout, CMD_GET_CHANNEL: c_get_channel,
        CMD_SET_CHANNEL: c_set_channel, CMD_SIGN_START: c_sign_start, CMD_SIGN_DATA: c_sign_data,
        CMD_SIGN_FINISH: c_sign_finish, CMD_SEND_TRACE_PATH: c_send_trace_path, CMD_GET_CUSTOM_VARS: c_get_custom_vars,
        CMD_SET_CUSTOM_VAR: c_set_custom_var, CMD_GET_ADVERT_PATH: c_get_advert_path, CMD_GET_STATS: c_get_stats,
        CMD_SET_FLOOD_SCOPE_KEY: c_set_flood_scope_key, CMD_SET_DEFAULT_FLOOD_SCOPE: c_set_default_flood_scope,
        CMD_GET_DEFAULT_FLOOD_SCOPE: c_get_default_flood_scope, CMD_SEND_CONTROL_DATA: c_send_control_data,
        CMD_SET_AUTOADD_CONFIG: c_set_autoadd_config, CMD_GET_AUTOADD_CONFIG: c_get_autoadd_config,
        CMD_GET_ALLOWED_REPEAT_FREQ: c_get_allowed_repeat_freq,
    }

# ============================================================================
# Tenant rooms: more rooms on the same radio, each with its own key, members, posts, passwords and web page
# ============================================================================

TENANT_MAX = 100
TENANT_DIR = "tenants"
# settings a tenant room keeps for itself (in its own database); everything else comes from the main config, and a
# tenant can't change it (no radio, timing or service settings: nothing that affects anyone outside the tenant)
TENANT_KEYS = {"name", "path", "private_key", "lat", "lon", "admin_password", "room_password", "allow_read_only",
               "web_password_hash", "welcome_new_members", "welcome_message", "welcome_advert_hint", "kick_message",
               "ban_message", "advert_interval_min", "flood_advert_interval_h", "max_posts", "catchup_max"}
TENANT_DEFAULTS = {"lat": 0.0, "lon": 0.0, "admin_password": "", "room_password": "", "allow_read_only": False,
                   "web_password_hash": "", "advert_interval_min": 60, "flood_advert_interval_h": 24}
TENANT_RESERVED_PATHS = {"api", "static", "icons", "index.html", "favicon.ico", "robots.txt", "tenants", "meshcore-web"}


def hash_web_password(pw):
    salt = os.urandom(16)
    n = 100000
    return "pbkdf2_sha256$%d$%s$%s" % (n, salt.hex(), hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, n).hex())


WEB_PAGE_SESSION_S = 30 * 86400        # a MeshCore Web page session (page password) lasts this long


def same_text(a, b):
    """a == b, in constant time (passwords)."""
    return hmac.compare_digest(str(a).encode(), str(b).encode())


ROOM_LOGIN_FAILS = 5                  # wrong room / admin passwords from one key within ROOM_LOGIN_FAIL_WINDOW_S...
ROOM_LOGIN_FAIL_WINDOW_S = 600        # ...and its logins go unanswered until the oldest is this old


def web_page_session(stored, now=None):
    """A MeshCore Web page session (the mr_web cookie): its expiry, signed with the stored page password hash (a secret:
    salted, and only in the config). Nothing is kept, so it outlives a restart; a new password ends every one."""
    exp = int((now or time.time()) + WEB_PAGE_SESSION_S)
    return "%d.%s" % (exp, hmac.new(str(stored).encode(), b"mr_web %d" % exp, hashlib.sha256).hexdigest())


def web_page_session_ok(token, stored):
    exp, _, mac = str(token).partition(".")
    if not stored or not exp.isdigit() or int(exp) < time.time():
        return False
    return hmac.compare_digest(mac, hmac.new(str(stored).encode(), b"mr_web %d" % int(exp), hashlib.sha256).hexdigest())


def check_web_password(pw, stored):
    try:
        algo, n, salt, h = str(stored).split("$")
        if algo != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac("sha256", str(pw).encode(), bytes.fromhex(salt), int(n)).hex()
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, h)


def welcome_changes(body, room_name, cur):
    """Welcome DM settings from a dashboard -> {setting: value}, validated against the room's name and current
    settings (cur: an object with the welcome_* settings). Raises ValueError."""
    if not isinstance(body, dict):
        raise ValueError("invalid JSON")
    updates = {}
    if "welcome_new_members" in body:
        if not isinstance(body["welcome_new_members"], bool):
            raise ValueError("welcome_new_members must be true or false")
        updates["welcome_new_members"] = body["welcome_new_members"]
    for key in ("welcome_message", "welcome_advert_hint"):
        if key in body:
            if not isinstance(body[key], str):
                raise ValueError("%s must be text" % key)
            updates[key] = body[key]
    if not updates:
        raise ValueError("no welcome settings supplied")
    enabled = updates.get("welcome_new_members", bool(cur.welcome_new_members))
    message = updates.get("welcome_message", str(cur.welcome_message))
    hint = updates.get("welcome_advert_hint", str(cur.welcome_advert_hint))
    if enabled and message:
        rendered = message.replace("{room}", str(room_name))
        if hint:
            rendered += " " + hint.replace("{room}", str(room_name))
        if len(rendered.encode()) > MAX_POST_TEXT_LEN:
            raise ValueError("welcome DM is too long after {room} is replaced (maximum %d UTF-8 bytes)" % MAX_POST_TEXT_LEN)
    return updates


def tenant_location(body):
    """A tenant room's advertised position from the dashboard: (lat, lon), both blank = none (0, 0). Raises ValueError."""
    def num(k, lim):
        v = body.get(k)
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        try:
            f = float(v)
        except (TypeError, ValueError):
            raise ValueError("%s: a number" % k)
        if not -lim <= f <= lim or f != f:
            raise ValueError("%s: -%d to %d" % (k, lim, lim))
        return round(f, 6)
    lat, lon = num("lat", 90), num("lon", 180)
    if (lat is None) != (lon is None):
        raise ValueError("location: give both latitude and longitude, or neither")
    return (lat or 0.0, lon or 0.0)


def tenant_spec(body, taken_paths=(), taken_keys=()):
    """Dashboard 'create tenant room' form -> validated spec. The web password is hashed here (it never reaches the
    main loop or the database in the clear). Raises ValueError with a readable message."""
    if not isinstance(body, dict):
        raise ValueError("bad request")
    name = str(body.get("name", "")).strip()
    if not name or len(name.encode()) > 31:
        raise ValueError("room name: 1 to 31 bytes")
    path = str(body.get("path", "")).strip().strip("/").lower()
    if not 1 <= len(path) <= 32 or not all(c in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in path):
        raise ValueError("room path: 1 to 32 lowercase letters, digits, - or _")
    if path in TENANT_RESERVED_PATHS or path in taken_paths:
        raise ValueError("room path %r is already in use" % path)
    key = str(body.get("private_key", "") or "").strip().lower()
    if key:
        if len(key) not in (64, 128) or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("private key must be 64 or 128 hexadecimal characters (or empty for a random one)")
        pub = RepeaterIdentity(bytes.fromhex(key)).pub_key
        if pub[0] in (0x00, 0xFF):
            raise ValueError("that key's public key starts with %02X, which MeshCore reserves" % pub[0])
        if pub in taken_keys:
            raise ValueError("that key is already used by this server")
    out = dict(name=name, path=path, private_key=key)
    for j in ("room_password", "admin_password"):
        v = str(body.get(j, "") or "")
        if len(v.encode()) > 15:
            raise ValueError("%s: at most 15 bytes (MeshCore's limit)" % j.replace("_", " "))
        out[j] = v
    if out["admin_password"] and out["admin_password"] == out["room_password"]:
        raise ValueError("the admin password must differ from the join password")
    wp = str(body.get("web_password", "") or "")
    if len(wp) < 6:
        raise ValueError("web UI password: at least 6 characters")
    out["web_password_hash"] = hash_web_password(wp)
    out["lat"], out["lon"] = tenant_location(body)
    return out


class TenantConfig:
    """A tenant room's settings: its own (TENANT_KEYS, kept in its database) over the main config's. set() refuses
    anything outside TENANT_KEYS, so nothing a tenant does (RF CLI included) can change the main room or the radio."""

    def __init__(self, base, store):
        self.__dict__["base"], self.__dict__["store"] = base, store
        data = {}
        for k, v in store.read("SELECT k, v FROM settings"):
            try:
                data[k] = json.loads(v)
            except ValueError:
                pass
        self.__dict__["data"] = data

    def __getattr__(self, k):
        d = self.__dict__["data"]
        if k in d:
            return d[k]
        if k in TENANT_DEFAULTS:
            return TENANT_DEFAULTS[k]
        return getattr(self.__dict__["base"], k)

    def __setattr__(self, k, v):
        self.set(k, v)

    def set(self, k, v):
        if k not in TENANT_KEYS:
            raise ValueError("%s is a server setting: a tenant room can't change it" % k.replace("_", "."))
        self.__dict__["data"][k] = v
        self.__dict__["store"].execmany([("INSERT OR REPLACE INTO settings (k, v) VALUES (?,?)", [(k, json.dumps(v))])])


def _shared(name, writable=False):
    """A TenantRoom attribute that is the main room's (the map, the radio's readings, the virtual repeater...).
    Writes are ignored unless writable (RoomServer.__init__ assigns defaults that must not reach the main room)."""
    def get(self):
        return getattr(self.host, name)

    def put(self, v):
        if writable:
            setattr(self.host, name, v)
    return property(get, put)


class TenantRoom(RoomServer):
    """A room on the main room's radio: same room logic, its own key, members, posts, bans, passwords and settings
    (tenants/{public key}.db). It shares the main room's map and routes to repeaters, and its transmissions go through
    the main room (internal hand-over to the other nodes on this radio, then the one transmit queue). It never does
    mesh-level work: no topology learning, discovery, traces, map building or radio housekeeping."""

    TENANT = True
    SHARED = ("radio", "noise_floor", "nf_min", "nf_max", "last_rssi", "last_snr", "batt_mv", "mcu_temp_c", "temp_supported",
              "rroutes", "mrpts", "edges", "repeaters", "heard", "obs_edges", "probes", "neighbours", "names", "disk_names",
              "vr", "vc", "observer", "feed", "txq", "tx_busy_until", "last_rx_mono", "rx_airtime_ms", "web_map",
              "map_version", "minutes", "sys_samples", "mem_total_mb")
    RADIO_STATS = ("recv", "sent", "airtime_ms", "recv_flood", "recv_direct", "sent_flood", "sent_direct", "errors",
                   "flood_dups", "direct_dups", "traces")

    def __init__(self, host, store, cfg=None):
        self.host = host
        cfg = cfg or TenantConfig(host.cfg, store)
        ident = RepeaterIdentity(bytes.fromhex(str(cfg.private_key)))
        super().__init__(cfg, host.modem, ident, store)
        self.events_put = host.events_put
        self.web_last_request = 0.0
        self.web_state = {}
        now = time.monotonic()
        self.next_zero_advert = now + random.uniform(10, 300)    # (spread out: many rooms restarting together)
        self.next_flood_advert = now + random.uniform(60, 1800)

    path = property(lambda s: s.cfg.path)
    key = property(lambda s: hexs(s.id.pub_key))

    # ---------------------------------------------------------------- mesh-level work belongs to the main room
    def repeater_apply(self):
        pass

    def observe_flood_path(self, pkt):
        pass

    def observe_trace(self, pkt):
        pass

    def on_control(self, pkt):
        pass

    def maybe_trace(self):
        pass

    def send_discovery(self):
        pass

    def learn_name(self, pub, ts, name):
        pass                                                # (the main room keeps the shared name cache)

    def radio_stats(self):
        """This room's counters, with the radio's own (packets heard and sent, airtime) from the main room."""
        s = dict(self.stats)
        for k in self.RADIO_STATS:
            s[k] = self.host.stats.get(k, 0)
        return s

    def hour_stats(self):
        return self.host.hour_stats()

    def sys_stats(self):
        return self.host.sys_stats()

    # ---------------------------------------------------------------- radio: through the main room
    def queue_tx(self, pkt, prio, delay=0.0, deferrable=False, relay=False, src=None):
        self.seen_mark(pkt)
        self.host.bus_send(self, pkt, prio, delay, deferrable)

    def wants(self, pkt):
        """Could this packet concern this room? (Cheap filter: the main room offers every packet to every tenant.)"""
        t, p = pkt.ptype, pkt.payload
        if t in (PT_PATH, PT_REQ, PT_RESPONSE, PT_TXT_MSG, PT_ANON_REQ):
            return bool(p) and p[0] == self.self_hash
        if t in (PT_ACK, PT_MULTIPART):
            return bool(self.notices) or any(m.pending_ack is not None or m.ack_map
                                             for m in self.members.values())
        if t == PT_ADVERT:
            return p[:32] in self.members
        if t == PT_TRACE:
            return pkt.is_direct and len(p) >= 9 and self.id.pub_key[:1 << (p[8] & 3)] in p[9:]
        return False

    def on_advert(self, pkt):
        """A member's advert: they're on the air (the main room does names, positions and the map)."""
        m = self.members.get(pkt.payload[:32])
        if m is None or self.check_dup(pkt) or self.parse_advert(pkt) is None:
            return
        if pkt.is_flood:
            self.member_flood(m, pkt)
        self.heard_from(m)
        if (m.given_up or m.push_failures > 0 or m.stuck_since) and m.pending_ack is None:
            self.member_active(m, pkt)
            if m.last_activity == 0:
                m.last_activity = now_s()
            self.mark_dirty()

    def dashboard_advert(self, flood):
        self.send_advert(flood)
        log.info("tenant room %r: %s advert sent from its page", self.cfg.name, "flood" if flood else "zero-hop")

    def handle_cli(self, cmd):
        """The room CLI, without anything that reaches outside this room (the radio, timing, discovery, restarts)."""
        c = cmd.strip()
        if c in ("reboot", "restart", "discover") or c.startswith(("set path.hash", "set push.")):
            return "Err - not available in a tenant room"
        return super().handle_cli(c)

    def run_once(self):
        if self.notices:
            self.service_notices()
        self.periodic()

    def periodic(self):
        now = time.monotonic()
        c = self.cfg
        if c.advert_interval_min and now >= self.next_zero_advert:
            self.send_advert(False)
            self.next_zero_advert = now + float(c.advert_interval_min) * 60
        if c.flood_advert_interval_h and now >= self.next_flood_advert:
            self.send_advert(True)
            self.next_flood_advert = now + float(c.flood_advert_interval_h) * 3600
        if now >= self.next_aging:
            for m in self.members.values():
                self.prune_routes(m)
            self.drop_private(None, older_than=now_s() - 7 * 86400)
            self.next_aging = now + 3600
        self.pace_ease()
        if self.dirty and now >= self.next_flush:
            self.flush()
            self.next_flush = now + 30
        if now - self.web_last_request < 20 and now >= self.next_web:
            self.publish_web_state()
            self.next_web = now + 1

    def publish_web_state(self):
        super().publish_web_state()
        st = dict(self.web_state)
        st["stats"] = dict(st["stats"], **{k: self.host.stats.get(k, 0) for k in self.RADIO_STATS})
        st["room"] = dict(st["room"], tenant=True, path=self.cfg.path)
        st["mqtt"], st["repeater"], st["companion"] = {}, {}, {}
        self.web_state = st

    def admin_row(self):
        return dict(name=self.cfg.name, path=self.cfg.path, key=self.key, id=hexs(self.id.pub_key[:2]),
                    lat=float(self.cfg.lat or 0.0), lon=float(self.cfg.lon or 0.0),
                    members=sum(1 for m in self.members.values() if not m.given_up),
                    suspended=sum(1 for m in self.members.values() if m.given_up),
                    posts=sum(1 for p in self.posts if p[3] is None))

    def close(self):
        self.flush()
        self.store.close()


for _n in TenantRoom.SHARED:
    setattr(TenantRoom, _n, _shared(_n))
TenantRoom._rpt_idx = _shared("_rpt_idx", writable=True)          # (the repeater name index follows the shared map)
TenantRoom._label_memo = _shared("_label_memo", writable=True)
del _n

# ============================================================================
# Observer feed (MQTT augmentation): read-only, its own thread, filters before anything reaches the main loop
# ============================================================================

class MQTTError(Exception):
    pass


class MiniMQTT:
    """MQTT 3.1.1 subscriber over TCP or WebSockets, optional TLS. Read-only by design: CONNECT, SUBSCRIBE,
    receive PUBLISH, keepalive pings. No publishing. Uses only the Python standard library."""

    CONNACK = {1: "unacceptable protocol version", 2: "client id rejected", 3: "server unavailable",
               4: "bad username or password", 5: "not authorized"}

    def __init__(self, host, port, client_id, username=None, password=None, websockets=True, ws_path="/mqtt",
                 tls=True, verify=True, keepalive=60, timeout=15):
        self.host, self.port, self.client_id = host, port, client_id
        self.username, self.password = username, password
        self.websockets, self.ws_path, self.tls, self.verify = websockets, ws_path, tls, verify
        self.keepalive, self.timeout = keepalive, timeout
        self.sock = None
        self.buf = b""                                      # decoded MQTT byte stream (after WebSocket framing)
        self.wsbuf = b""
        self.pid = 0
        self.wlock = threading.Lock()
        self.last_tx = 0.0

    # --- transport ---
    def _open(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.tls:
            ctx = ssl.create_default_context()
            if not self.verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=self.host)
        self.sock = raw
        if self.websockets:
            key = base64.b64encode(os.urandom(16)).decode()
            req = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: mqtt\r\n\r\n"
                   % (self.ws_path, self.host, self.port, key))
            self.sock.sendall(req.encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise MQTTError("connection closed during the WebSocket handshake")
                resp += chunk
            head, _, rest = resp.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            if " 101 " not in lines[0] + " ":
                raise MQTTError("WebSocket upgrade refused: %s (wrong --ws-path?)" % lines[0])
            want = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            hdrs = {l.split(":", 1)[0].strip().lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
            if hdrs.get("sec-websocket-accept") != want:
                raise MQTTError("bad WebSocket handshake response")
            self.wsbuf = rest

    def _send(self, data):
        with self.wlock:
            if self.websockets:                             # one masked binary frame per MQTT packet (client frames must be masked)
                n = len(data)
                hdr = bytearray([0x82])
                if n < 126:
                    hdr.append(0x80 | n)
                elif n < 65536:
                    hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
                else:
                    hdr += bytes([0x80 | 127]) + struct.pack(">Q", n)
                mask = os.urandom(4)
                data = bytes(hdr) + mask + bytes(b ^ mask[i & 3] for i, b in enumerate(data))
            self.sock.sendall(data)
            self.last_tx = time.monotonic()

    def _recv_raw(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise MQTTError("connection closed by the broker")
        return chunk

    def _fill(self):
        """Read more bytes into the MQTT stream (unwrapping WebSocket frames: fragmented, ping, close)."""
        if not self.websockets:
            self.buf += self._recv_raw()
            return
        while True:
            b = self.wsbuf
            if len(b) >= 2:
                op, ln, i = b[0] & 0x0F, b[1] & 0x7F, 2
                masked = b[1] & 0x80
                if ln == 126 and len(b) >= 4:
                    ln, i = struct.unpack(">H", b[2:4])[0], 4
                elif ln == 127 and len(b) >= 10:
                    ln, i = struct.unpack(">Q", b[2:10])[0], 10
                elif ln >= 126:
                    ln = None
                if ln is not None:
                    if masked:
                        i += 4
                    if len(b) >= i + ln:
                        payload = b[i:i + ln]
                        if masked:
                            m = b[i - 4:i]
                            payload = bytes(x ^ m[k & 3] for k, x in enumerate(payload))
                        self.wsbuf = b[i + ln:]
                        if op in (0x0, 0x2):                # binary data (or a continuation of it)
                            self.buf += payload
                            return
                        if op == 0x8:
                            raise MQTTError("WebSocket closed by the broker")
                        if op == 0x9:                       # ping -> pong
                            with self.wlock:
                                mask = os.urandom(4)
                                self.sock.sendall(bytes([0x8A, 0x80 | len(payload)]) + mask +
                                                  bytes(x ^ mask[k & 3] for k, x in enumerate(payload)))
                        continue                            # pong / text / other control frames: ignore
            self.wsbuf += self._recv_raw()

    def _packet(self):
        """Next MQTT packet -> (type, flags, body)."""
        while True:
            b = self.buf
            if len(b) >= 2:
                mult, rl, i = 1, 0, 1
                ok = False
                while i < len(b) and i <= 4:
                    rl += (b[i] & 0x7F) * mult
                    mult *= 128
                    i += 1
                    if not b[i - 1] & 0x80:
                        ok = True
                        break
                if ok and len(b) >= i + rl:
                    self.buf = b[i + rl:]
                    return b[0] >> 4, b[0] & 0x0F, b[i:i + rl]
            self._fill()

    @staticmethod
    def _str(s):
        e = s.encode()
        return struct.pack(">H", len(e)) + e

    @staticmethod
    def _rl(n):
        out = bytearray()
        while True:
            d, n = n % 128, n // 128
            out.append(d | (0x80 if n else 0))
            if not n:
                return bytes(out)

    # --- MQTT ---
    def connect(self):
        self._open()
        flags = 0x02                                        # clean session
        payload = self._str(self.client_id)
        if self.username is not None:
            flags |= 0x80
            payload += self._str(self.username)
            if self.password is not None:
                flags |= 0x40
                payload += self._str(self.password)
        var = self._str("MQTT") + bytes([4, flags]) + struct.pack(">H", self.keepalive)
        body = var + payload
        self._send(bytes([0x10]) + self._rl(len(body)) + body)
        t, _, b = self._packet()
        if t != 2 or len(b) < 2:
            raise MQTTError("unexpected reply to CONNECT")
        if b[1] != 0:
            raise MQTTError("CONNECT REFUSED: %s" % self.CONNACK.get(b[1], "code %d" % b[1]))

    def subscribe(self, topic):
        self.pid = (self.pid % 65535) + 1
        body = struct.pack(">H", self.pid) + self._str(topic) + bytes([0])
        self._send(bytes([0x82]) + self._rl(len(body)) + body)
        return self.pid

    def loop(self, on_message, on_suback, stop):
        """Receive until stop is set or the connection drops. Sends keepalive pings on its own."""
        self.sock.settimeout(1.0)
        while not stop.is_set():
            if time.monotonic() - self.last_tx > self.keepalive * 0.5:
                self._send(bytes([0xC0, 0x00]))             # PINGREQ
            try:
                t, fl, b = self._packet()
            except socket.timeout:
                continue
            if t == 3:                                      # PUBLISH
                tl = struct.unpack(">H", b[:2])[0]
                topic = b[2:2 + tl].decode("utf-8", "replace")
                i = 2 + tl
                qos = (fl >> 1) & 3
                if qos:
                    pid = b[i:i + 2]; i += 2
                    self._send(bytes([0x40, 0x02]) + pid)   # PUBACK (we subscribe at QoS 0, but be polite)
                on_message(topic, b[i:], bool(fl & 1))
            elif t == 9:                                    # SUBACK
                on_suback(struct.unpack(">H", b[:2])[0], list(b[2:]))
            # PINGRESP (13) and anything else: nothing to do

    def close(self):
        try:
            self._send(bytes([0xE0, 0x00]))                 # DISCONNECT
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass



TOPIC_REGION_RE = re.compile(r"^meshcore/([A-Za-z0-9]+)/(\+/packets|#)$")


def topic_regions(topics):
    """The region codes a set of topic filters stands for (upper case), or None when they aren't plain
    per-region filters (e.g. meshcore/# or a custom filter), in which case nothing is filtered by region."""
    found = [TOPIC_REGION_RE.match(str(t).strip()) for t in (topics or [])]
    if not found or not all(found):
        return None
    return frozenset(m.group(1).upper() for m in found)


class ObserverFeed:
    """Listens to the observer network over MQTT (LetsMesh format: meshcore/<region>/<observer>/packets, JSON with
    the raw packet in hex). Keeps only ACKs and packets addressed to the room (destination byte), drops duplicates
    (the same packet from many observers), and hands those to the main loop. Never publishes; never required."""

    def __init__(self, room, events):
        self.room, self.events = room, events
        self.stop_ev = threading.Event()
        self.connected = False
        self.error = ""
        self.lock = threading.Lock()
        self.seen = collections.OrderedDict()                # packet hash -> time (dedupe across observers)
        self.bad = 0                                         # malformed messages skipped
        self.connects = 0
        self.recent = collections.deque()                    # (time, relevant) for the rate shown in the header
        self.diag = collections.Counter({                    # received and intentionally ignored MQTT observations
            "received": 0, "accepted": 0, "retained": 0, "non_packet_topic": 0,
            "malformed": 0, "self_origin": 0, "duplicate": 0, "other_region": 0})
        self.subscriptions = {}                               # topic -> pending/granted/denied, set by broker SUBACK
        self.subscription_error = ""
        self.ingress = queue.Queue(maxsize=max(10, int(room.cfg.mqtt_queue_max)))
        self.dropped = 0
        self.thread = threading.Thread(target=self.worker, name="mqtt", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_ev.set()

    def depth(self):
        return self.ingress.qsize()

    def pop(self):
        try:
            return self.ingress.get_nowait()
        except queue.Empty:
            return None

    def rates(self):
        now = time.monotonic()
        with self.lock:
            while self.recent and now - self.recent[0][0] > 60:
                self.recent.popleft()
            n = len(self.recent)
            rel = sum(1 for _, r in self.recent if r)
        span = 60.0
        return round(n / span, 1), round(rel / span, 2)

    def subscription_state(self):
        """A copy suitable for the public status API; it contains no credentials."""
        with self.lock:
            return {topic: dict(status) for topic, status in self.subscriptions.items()}

    def record_suback(self, topic_by_pid, pid, codes):
        """Record a broker acknowledgement for a requested subscription.

        A TCP/WebSocket connection alone does not prove that the broker accepted a
        topic filter. MQTT 3.1.1 uses 0, 1 or 2 for a granted QoS and 0x80 for a
        refused filter.
        """
        topic = topic_by_pid.get(pid)
        if topic is None:
            return
        granted = bool(codes) and all(code in (0, 1, 2) for code in codes)
        with self.lock:
            self.subscriptions[topic] = {"state": "granted" if granted else "denied",
                                         "codes": list(codes)}
            denied = [t for t, status in self.subscriptions.items() if status.get("state") == "denied"]
            self.subscription_error = ("subscription denied: " + ", ".join(denied)) if denied else ""

    def worker(self):
        cfg = self.room.cfg
        delay = 2
        cid = "meshroom-" + os.urandom(4).hex()
        while not self.stop_ev.is_set():
            c = MiniMQTT(cfg.mqtt_host, int(cfg.mqtt_port), cid, cfg.mqtt_username or None, cfg.mqtt_password or None,
                         websockets=(cfg.mqtt_transport == "websockets"), ws_path=cfg.mqtt_ws_path,
                         tls=bool(cfg.mqtt_tls), verify=bool(cfg.mqtt_tls_verify))
            try:
                c.connect()
                topics = list(cfg.mqtt_topics or ["meshcore/#"])
                with self.lock:
                    self.subscriptions = {tp: {"state": "pending", "codes": []} for tp in topics}
                    self.subscription_error = ""
                topic_by_pid = {c.subscribe(tp): tp for tp in topics}
                self.connected, self.error, delay = True, "", 2
                self.connects += 1
                log.info("MQTT: connected to %s", cfg.mqtt_host)
                c.loop(self.on_message, lambda pid, codes: self.record_suback(topic_by_pid, pid, codes), self.stop_ev)
            except MQTTError as e:
                self.error = str(e)
                if "REFUSED" in str(e):
                    self.error += " (token may have expired)"
                    delay = max(delay, 300)                 # bad credentials: don't hammer the broker
                log.warning("MQTT: %s", self.error)
            except (OSError, ssl.SSLError) as e:
                self.error = "connection failed: %s" % e
                log.warning("MQTT: %s", self.error)
            except Exception as e:                          # never let the feed die quietly: log, then retry
                self.error = "unexpected error: %r" % e
                log.exception("MQTT: unexpected error (will retry)")
            finally:
                self.connected = False
                c.close() if c.sock else None
            if self.stop_ev.wait(delay):
                break
            delay = min(delay * 2, 300)

    def on_message(self, topic, payload, retain):
        try:
            self._on_message(topic, payload, retain)
        except Exception as e:                              # a malformed message from some observer: skip it, keep the connection
            self.bad += 1
            if self.bad <= 5 or self.bad % 100 == 0:
                log.warning("MQTT: skipped a malformed message on %s (%r) [%d so far]", topic, e, self.bad)

    def _on_message(self, topic, payload, retain):
        self.diag["received"] += 1
        if retain or not topic.endswith("/packets"):
            self.diag["retained" if retain else "non_packet_topic"] += 1
            return                                          # retained = an old packet replayed; status messages: not needed
        regions = topic_regions(getattr(self.room.cfg, "mqtt_topics", None))
        if regions is not None:
            parts = topic.split("/")
            if len(parts) < 2 or parts[1].upper() not in regions:
                self.diag["other_region"] += 1
                return                                      # only the regions asked for, even if a broker sends more
        try:
            obj = json.loads(payload)
            raw = bytes.fromhex(obj["raw"])
        except (ValueError, KeyError, TypeError, AttributeError):
            self.diag["malformed"] += 1
            return
        if len(raw) < 2:
            self.diag["malformed"] += 1
            return                                          # empty / truncated packet
        now = time.monotonic()
        cfg = self.room.cfg
        pkt = Packet.parse(raw)
        try:
            origin = bytes.fromhex(obj.get("origin_id") or "")[:32]
        except (ValueError, TypeError):
            origin = b""
        if origin == self.room.id.pub_key:
            self.diag["self_origin"] += 1
            return                                          # never ingest this room's own published observation
        try:
            snr = float(obj.get("SNR"))
        except (ValueError, TypeError):
            snr = None
        pkey = obj.get("hash") or hashlib.sha256(raw).hexdigest()[:16]
        out = []                                            # (dedupe key, event)
        if pkt is not None:
            t, pl = pkt.ptype, pkt.payload
            if t == PT_ACK and len(pl) >= 4:
                out.append((pkey, ("ack", pl[:4])))
            elif t == PT_MULTIPART and len(pl) >= 5 and (pl[0] & 0x0F) == PT_ACK:
                out.append((pkey, ("ack", pl[1:5])))
            elif t in (PT_TXT_MSG, PT_PATH) and len(pl) >= 2 and pl[0] == self.room.self_hash:
                out.append((pkey, ("pkt", raw)))
            elif t == PT_ADVERT and (cfg.mqtt_advert_ingest or cfg.mqtt_activity):
                first = pkt.path[:pkt.hash_size] if pkt.hop_count else origin[:2]
                out.append(((pkey, first), ("advert", raw, origin)))    # each first hop = another "near" sighting
            elif t == PT_GRP_TXT and cfg.mqtt_activity and pl and pl[0] in self.room.channel_hashes():
                out.append((pkey, ("grp", raw)))
            if cfg.mqtt_topo_ingest and ((pkt.is_flood and pkt.hash_size >= 2 and pkt.hop_count) or (t == PT_TRACE and pkt.is_direct)):
                out.append(((pkey, origin[:4]), ("topo", raw, origin, snr)))   # every observer's copy adds its own last link
            if cfg.web_backlog_mqtt and int(cfg.web_backlog_days or 0) > 0 and t in BACKLOG_TYPES and len(pl) >= 2:
                out.append((("bk", pkey), ("backlog", raw, snr)))         # for MeshCore Web's catch-up (kept once)
        with self.lock:
            self.recent.append((now, bool(out)))
            keep = []
            for key, ev in out:
                if key in self.seen:
                    self.diag["duplicate"] += 1
                    continue                                # another observer's copy of the same thing
                self.seen[key] = now
                keep.append(ev)
            self.diag["accepted"] += len(keep)
            while len(self.seen) > 4000:
                self.seen.popitem(last=False)
        for ev in keep:
            try:
                self.ingress.put_nowait(("obs",) + ev)    # preserve FIFO; drop only the arriving event under load
            except queue.Full:
                self.dropped += 1


# ============================================================================
# KaaS: KISS radio as an API service. Websocket clients (bots, integrations) get every packet this radio hears and
# sends, and may send raw packets of their own; they do all MeshCore crypto themselves. See docs/api.md.
# ============================================================================

KAAS_PATH = "/api/v1/kaas"
WEB_PATH = "/api/v1/web"
KAAS_TOKEN_PREFIX = "kaas_"
KAAS_TICKET_PREFIX = "kt_"
KAAS_TICKET_S = 30                    # a websocket ticket (for browsers, which can't send Authorization) lasts this long
KAAS_TICKET_LOG_S = 300               # what became of a ticket, kept this long for /api/v1/web/ticket to tell its browser
KAAS_MAX_TICKETS = 1024               # tickets waiting to be used, across all keys
KAAS_TICKETS_PER_KEY = 4              # ...and per key, so no one key can take them all
KAAS_MAX_KEYS = 50
KAAS_MAX_CLIENTS = 16
KAAS_QUEUE_MAX = 512                  # messages waiting for a slow client; past that the oldest are dropped (and counted)
KAAS_MAX_MESSAGE = 4096               # largest message a client may send
KAAS_QUERY_LIMITS = {"nodes": 4, "route": 30}   # queries a minute per key (nodes; near/routes/route)
NODES_DAYS_WEB = 31                    # a web session's "nodes" reaches back at most this many days
LINK_GRAPH_TTL_S = 30                  # route questions reuse the repeater link graph this long
KAAS_MAX_INFLIGHT = 4                 # a client's sends waiting for the main loop
ROUTE_HOP_COST = 0.95                 # each hop of a suggested route scores this much less
KAAS_MAX_ROUTES = 5                   # route suggestions per request
KAAS_PING_S = 30                      # websocket ping this often; nothing heard for 3 of these closes the connection
KAAS_STATS = ("rx", "tx", "err")      # per key: packets streamed to it, packets it sent (accepted), errors it got
KAAS_STATS_SAVE_S = 300
KAAS_PRIO = 9                         # (and they go out after everything of the room's, the repeater's and pushes)
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WEB_CHALLENGE_PREFIX = "wc_"
WEB_CHALLENGE_S = 60                  # a web login's challenge must be signed and sent back within this long
WEB_MAX_USED_CHALLENGES = 20000       # logins in the last minute (each a signed challenge) remembered, so none is reused
WEB_LOGIN_LABEL = "meshcore-web login v1"   # signed first, so a login signature is never a valid packet signature
WEB_USERS_MAX = 1000                  # web users remembered for the dashboard (the least recently active go first)
WEB_ID_PREFIX = "w:"                  # a web session's id in the per-key stats: "w:" + its public key
BACKLOG_TYPES = (PT_GRP_TXT, PT_TXT_MSG)  # what web users catch up on: channel messages and DMs (and room posts)
BACKLOG_RECENT = 20000                # packet hash -> seq kept in memory, so later copies of a packet get its number
BACKLOG_BATCH = 200                   # packets per replay message
BACKLOG_FLUSH_S = 1.0                 # new backlog rows are written at most this often (one transaction)
BACKLOG_PRUNE_S = 3600
# what a web session may send, and the identity each must carry (adverts, logins: the full key; DMs etc.: its hash)
WEB_SEND_TYPES = (PT_ADVERT, PT_GRP_TXT, PT_TXT_MSG, PT_ACK, PT_PATH, PT_ANON_REQ, PT_REQ, PT_RESPONSE, PT_MULTIPART)


def web_login_message(host, challenge, pub_hex):
    """What a web login signs: the label, the server's host as the browser named it, the challenge, the key."""
    return ("%s\n%s\n%s\n%s" % (WEB_LOGIN_LABEL, host, challenge, pub_hex)).encode()


def web_packet_check(pkt, pub):
    """None if a web session holding pub may send pkt, else why not."""
    t, p = pkt.ptype, pkt.payload
    if t not in WEB_SEND_TYPES:
        return "web sessions can't send %s packets" % (PT_NAMES[t] if t < len(PT_NAMES) else t)
    if t == PT_ADVERT and p[:PUB_KEY_SIZE] != pub:
        return "an advert must be for your own key"
    if t == PT_ANON_REQ and p[1:1 + PUB_KEY_SIZE] != pub:
        return "a login must be from your own key"
    if t in (PT_TXT_MSG, PT_REQ, PT_RESPONSE, PT_PATH) and (len(p) < 2 or p[1] != pub[0]):
        return "a message must be from your own key"
    if pkt.is_flood and pkt.path_len & 63:
        return "a flood starts with no hops: the repeaters add them"
    return None


def kaas_token_hash(token):
    """Only this is stored: a key is 256 random bits, so a plain SHA-256 can't be reversed or guessed."""
    return hashlib.sha256(token.encode()).hexdigest()


def kaas_key_spec(body, now=None):
    """A new API key's settings from the dashboard -> dict(receive, send, description, expires), or ValueError."""
    if not isinstance(body, dict):
        raise ValueError("bad request")
    receive, send = body.get("receive"), body.get("send")
    if not isinstance(receive, bool) or not isinstance(send, bool):
        raise ValueError("receive and send must be true or false")
    if not (receive or send):
        raise ValueError("choose Receive, Send or both")
    desc = body.get("description", "")
    if not isinstance(desc, str) or len(desc.strip()) > 80:
        raise ValueError("description: text, at most 80 characters")
    exp = body.get("expires")
    if exp is not None:
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            raise ValueError("expires: a time in seconds since 1970, or null for never")
        if exp <= (now or time.time()):
            raise ValueError("that expiry date has already passed")
        exp = int(exp)
    return dict(receive=receive, send=send, description=desc.strip(), expires=exp)


def ws_accept(key):
    return base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()


def ws_frame(opcode, data=b"", mask=False):
    """One whole websocket frame. Servers send unmasked frames, clients masked ones."""
    n = len(data)
    head = bytearray([0x80 | opcode])
    mbit = 0x80 if mask else 0
    if n < 126:
        head.append(mbit | n)
    elif n < 65536:
        head.append(mbit | 126)
        head += struct.pack(">H", n)
    else:
        head.append(mbit | 127)
        head += struct.pack(">Q", n)
    if mask:
        k = os.urandom(4)
        head += k
        data = bytes(b ^ k[i & 3] for i, b in enumerate(data))
    return bytes(head) + data


def _ws_exact(rf, n):
    b = rf.read(n) if n else b""
    if len(b) < n:
        raise EOFError
    return b


def ws_read(rf, max_len, masked=True, on_control=None):
    """The next message: (opcode, payload), fragments joined. Control frames (close, ping, pong) come back on their
    own, or go to on_control when they arrive between a message's fragments. EOFError when the connection ends,
    ValueError for a protocol error."""
    parts, first = [], None
    while True:
        h = _ws_exact(rf, 2)
        fin, op, n = h[0] & 0x80, h[0] & 0x0F, h[1] & 0x7F
        if bool(h[1] & 0x80) != masked:
            raise ValueError("client frames must be masked" if masked else "server frames must not be masked")
        if n == 126:
            n = struct.unpack(">H", _ws_exact(rf, 2))[0]
        elif n == 127:
            n = struct.unpack(">Q", _ws_exact(rf, 8))[0]
        if sum(len(p) for p in parts) + n > max_len:
            raise ValueError("message too big")
        k = _ws_exact(rf, 4) if masked else None
        data = _ws_exact(rf, n)
        if k:
            data = bytes(b ^ k[i & 3] for i, b in enumerate(data))
        if op >= 8:
            if not fin or n > 125:
                raise ValueError("bad control frame")
            if parts and on_control is not None and op != 8:
                on_control(op, data)
                continue
            return op, data
        if op == 0:
            if first is None:
                raise ValueError("unexpected continuation frame")
        elif first is not None:
            raise ValueError("expected a continuation frame")
        else:
            first = op
        parts.append(data)
        if fin:
            return first, b"".join(parts)


def kaas_endpoint(x):
    """One end of a route request: ("key", bytes), ("repeater", 2-3 bytes) or ("name", str); None if it's none."""
    if not isinstance(x, str):
        return None
    x = x.strip()
    try:
        b = bytes.fromhex(x)
    except ValueError:
        b = None
    if b is not None and 8 <= len(b) <= 32:
        return "key", b
    if b is not None and 2 <= len(b) <= 3 and not x.startswith("@"):
        return "repeater", b
    n = kaas_mention_name(x)
    return None if n is None else ("name", n)


def kaas_mention_name(x):
    """A node name from a near request: "platinum" or the mention form "@[platinum]". None if it can't be a name."""
    if not isinstance(x, str):
        return None
    x = x.strip()
    m = re.fullmatch(r"@\[(.*)\]", x, re.S)
    if m:
        x = m.group(1).strip()
    return x if 1 <= len(x.encode()) <= 32 else None


class KaasConn:
    """One websocket client. Its HTTP thread reads; its own writer thread drains a bounded outbox, so a slow client
    never holds up the radio (past KAAS_QUEUE_MAX waiting, the oldest are dropped and the client is told how many)."""

    def __init__(self, hub, sock, rfile, key, peer):
        self.hub, self.sock, self.rfile, self.peer = hub, sock, rfile, peer
        self.ip = peer                                      # the client's address (behind a proxy: the one it forwarded for)
        self.key_id, self.can_receive, self.can_send = key["id"], bool(key.get("receive")), bool(key.get("send"))
        self.web = key.get("web")                           # a web login: its public key (hex); None for an API key
        self.rooms = set()                                  # rooms on this server it follows (web logins: "room")
        self.out = collections.deque()
        self.cv = threading.Condition()
        self.wlock = threading.Lock()
        self.closed, self.close_frame, self.dropped, self.inflight = False, None, 0, 0
        self.last_rx = time.monotonic()
        self.since = now_s()

    def put(self, text):
        with self.cv:
            if self.closed:
                return
            if len(self.out) >= KAAS_QUEUE_MAX:
                self.out.popleft()
                self.dropped += 1
            self.out.append(text)
            self.cv.notify()

    def send_json(self, obj):
        t = obj.get("type")
        if t == "error" or (t == "send_result" and obj.get("status") == "dropped"):
            self.hub.count(self.key_id, "err")
        elif t == "send_result" and obj.get("status") in ("queued", "local"):
            self.hub.count(self.key_id, "tx")
        self.put(json.dumps(obj, separators=(",", ":")))

    def close(self, code=1000, reason=""):
        with self.cv:
            if self.closed:
                return
            self.closed, self.close_frame = True, (code, reason)
            self.cv.notify()

    def _raw(self, frame):
        with self.wlock:
            self.sock.sendall(frame)

    def _control(self, op, data):
        if op == 9:
            self._raw(ws_frame(10, data))                   # ping -> pong
        elif op == 8:
            code = struct.unpack(">H", data[:2])[0] if len(data) >= 2 else 1000
            self.close(code if code in (1000, 1001) else 1000)

    def run(self):
        """In the HTTP thread that upgraded: start the writer, then read until the connection ends."""
        tokens, t_tok = float(KAAS_MSG_BURST), time.monotonic()
        writer = threading.Thread(target=self._writer, name="kaas-w", daemon=True)
        try:
            writer.start()
            while not self.closed:
                op, data = ws_read(self.rfile, KAAS_MAX_MESSAGE, on_control=self._control)
                self.last_rx = time.monotonic()
                if op >= 8:
                    self._control(op, data)
                    continue
                if op != 1:
                    self.send_json({"type": "error", "error": "send JSON text messages"})
                    continue
                try:
                    msg = json.loads(data)
                except ValueError:
                    msg = None
                if not isinstance(msg, dict):
                    self.send_json({"type": "error", "error": "not a JSON object"})
                    continue
                now = time.monotonic()                      # (a token bucket: KAAS_MSG_RATE a second, KAAS_MSG_BURST deep)
                tokens, t_tok = min(KAAS_MSG_BURST, tokens + (now - t_tok) * KAAS_MSG_RATE) - 1, now
                if tokens < -KAAS_MSG_BURST:
                    self.close(1008, "too many messages")
                    break
                if tokens < 0:
                    self.send_json({"type": "error", "id": msg.get("id") if isinstance(msg.get("id"), (str, int)) else None,
                                    "error": "too many messages: at most %d a second" % KAAS_MSG_RATE})
                    continue
                self.hub.on_message(self, msg)
        except ValueError as e:
            self.close(1002, str(e)[:100])
        except (EOFError, OSError):
            pass
        finally:
            self.close()
            self.hub.drop(self)                             # (the writer drops it too: whichever ends first frees the slot)
            if writer.is_alive() and writer is not threading.current_thread():
                writer.join(2.0)                            # (its close frame goes out before the socket is closed)

    def _writer(self):
        last_ping = time.monotonic()
        try:
            while True:
                with self.cv:
                    if not self.out and not self.closed and not self.dropped:
                        self.cv.wait(max(0.0, last_ping + KAAS_PING_S - time.monotonic()))
                    batch, dropped, closed = list(self.out), self.dropped, self.closed
                    self.out.clear()
                    self.dropped = 0
                if dropped:
                    self._raw(ws_frame(1, json.dumps({"type": "dropped", "count": dropped}).encode()))
                for text in batch:
                    self._raw(ws_frame(1, text.encode()))
                if closed:
                    code, reason = self.close_frame
                    self._raw(ws_frame(8, struct.pack(">H", code) + reason.encode()[:120]))
                    break
                now = time.monotonic()
                if now - self.last_rx > 3 * KAAS_PING_S:
                    break                                   # gone quiet: not even pongs
                if now - last_ping >= KAAS_PING_S:
                    self._raw(ws_frame(9, b"kaas"))
                    last_ping = now
        except OSError:
            pass
        finally:
            with self.cv:
                self.closed = True
            self.hub.drop(self)
            try:
                self.sock.shutdown(socket.SHUT_RDWR)        # also ends the reader's blocking read
            except OSError:
                pass


class KaasHub:
    """The radio as an API: keys (from the config, hashed), connected clients, the packet stream and clients' sends.
    publish/send/sent/periodic/event run in the main loop; find/add/drop/on_message/key_rows in web threads."""

    def __init__(self, room):
        self.room = room
        self.lock = threading.Lock()
        self.conns = []                     # (replaced, never mutated: the main loop reads it without the lock)
        self.last_used = {}                 # key id -> time (this run; the config keeps the last connect)
        self.last_send = {}                 # key id -> deque of monotonic times of its rate-limited sends in the window
        self.stats = dict(rx=0, tx=0, sent=0, local=0, dropped=0)
        self.next_check = 0.0
        self.tickets = {}                   # ticket -> (web login's pub hex, monotonic expiry): one websocket, once
        self.ticket_log = {}                # ticket -> (what became of it, monotonic expiry): see ticket_outcome
        self.qtimes = {}                    # (key id, "nodes" | "route") -> deque of monotonic times: query budget
        self.refused_hosts = {}             # host -> (logins refused, last): names web logins were signed for, not ours
        self.challenge_key = os.urandom(32)  # signs web login challenges (stateless: no pool to exhaust)
        self.used_challenges = {}           # challenge -> expiry (time.time): signed ones, so each works once
        self.wusers = {}                    # web user (pub hex) -> {"name", "first", "last"}: shown on the dashboard
        self.wusers_path = os.path.join(room.cfg.data_dir, "web_users.json")
        self.wusers_dirty = False
        # the backlog: channel messages and DMs, numbered (seq), so web users catch up on what they missed
        self.bk_lock = threading.Lock()
        self.bk_seq = 0
        self.bk_recent = collections.OrderedDict()  # packet hash -> seq
        self.bk_pending = []                # rows not written yet (a replay reads them too)
        self.bk_next_flush, self.bk_next_prune = 0.0, 0.0
        self.bk_store = getattr(room, "store", None)
        if self.bk_store is not None:
            try:
                self.bk_seq = int(self.bk_store.read("SELECT MAX(seq) FROM backlog")[0][0] or 0)
                self.bk_store.execmany([("CREATE INDEX IF NOT EXISTS backlog_ts ON backlog (ts)", None)])
            except Exception as e:
                log.warning("MeshCore Web backlog not available: %s", e)
                self.bk_store = None
        self.slock = threading.Lock()
        self.kstats = {}                    # key id -> {"total": [rx, tx, err], "hours": {hour: [rx, tx, err]}}
        self.kstats_path = os.path.join(room.cfg.data_dir, "kaas_stats.json")
        self.kstats_dirty, self.next_save = False, time.monotonic() + KAAS_STATS_SAVE_S
        try:
            with open(self.kstats_path) as f:
                for kid, st in json.load(f).items():
                    self.kstats[kid] = {"total": [int(x) for x in st["total"]][:3],
                                        "hours": {int(h): [int(x) for x in v][:3] for h, v in st["hours"].items()}}
        except FileNotFoundError:
            pass
        except (ValueError, KeyError, TypeError, AttributeError, OSError) as e:
            log.warning("KaaS stats in %s not read: %s", self.kstats_path, e)
        try:
            with open(self.wusers_path) as f:
                self.wusers = {k: dict(name=str(v.get("name", ""))[:32], first=int(v["first"]), last=int(v["last"]),
                                       seq=int(v.get("seq") or 0), floor=int(v.get("floor") or 0))
                               for k, v in json.load(f).items()}
        except FileNotFoundError:
            pass
        except (ValueError, KeyError, TypeError, AttributeError, OSError) as e:
            log.warning("web users in %s not read: %s", self.wusers_path, e)

    # ---------------------------------------------------------------- per-key stats

    def count(self, kid, field, n=1):
        """Any thread. Hourly buckets for the last 24 h, plus a running total."""
        i, hour = KAAS_STATS.index(field), int(time.time() // 3600)
        with self.slock:
            st = self.kstats.setdefault(kid, {"total": [0, 0, 0], "hours": {}})
            st["total"][i] += n
            st["hours"].setdefault(hour, [0, 0, 0])[i] += n
            self.kstats_dirty = True

    def key_stats(self, kid):
        """{"rx": [last 24 h, total], "tx": [...], "err": [...]}"""
        since = int(time.time() // 3600) - 23
        with self.slock:
            st = self.kstats.get(kid) or {"total": [0, 0, 0], "hours": {}}
            day = [sum(v[i] for h, v in st["hours"].items() if h >= since) for i in range(3)]
            return {f: [day[i], st["total"][i]] for i, f in enumerate(KAAS_STATS)}

    def save_stats(self):
        self.save_web_users()
        since = int(time.time() // 3600) - 23
        with self.slock:
            if not self.kstats_dirty:
                return
            for st in self.kstats.values():
                for h in [h for h in st["hours"] if h < since]:
                    del st["hours"][h]
            for kid in [k for k in self.kstats if k.startswith(WEB_ID_PREFIX) and k[len(WEB_ID_PREFIX):] not in self.wusers]:
                del self.kstats[kid]                        # (a web key the users list let go: self-made keys are free)
            data = json.dumps(self.kstats)
            self.kstats_dirty = False
        tmp = self.kstats_path + ".tmp"
        try:
            with open(tmp, "w") as f:
                f.write(data)
            os.replace(tmp, self.kstats_path)
        except OSError as e:
            log.warning("KaaS stats not saved: %s", e)

    # ---------------------------------------------------------------- keys

    def keys(self):
        return [k for k in (self.room.cfg.kaas_keys or []) if isinstance(k, dict) and k.get("id")]

    def key_by_id(self, kid):
        return next((k for k in self.keys() if k["id"] == kid), None)

    def find(self, token):
        if not token.startswith(KAAS_TOKEN_PREFIX) or len(token) > 128:
            return None
        h = kaas_token_hash(token)
        found = None
        for k in self.keys():
            if hmac.compare_digest(str(k.get("hash", "")), h):
                found = k
        return found

    def new_ticket(self, key):
        """A one-time ticket for a web login, or None when too many are waiting. Browsers can't put Authorization on a
        websocket, so they log in by signing (/api/v1/web/login) and open the websocket with ?ticket=. Any thread."""
        import secrets
        ticket = KAAS_TICKET_PREFIX + secrets.token_urlsafe(24)
        now = time.monotonic()
        with self.lock:
            self._prune_tickets(now)
            if len(self.tickets) >= KAAS_MAX_TICKETS or \
                    sum(1 for e in self.tickets.values() if e[0] == key["web"]) >= KAAS_TICKETS_PER_KEY:
                return None
            self.tickets[ticket] = (key["web"], now + KAAS_TICKET_S)
        return ticket

    def _prune_tickets(self, now):
        for t in [t for t, e in self.tickets.items() if e[1] <= now]:
            del self.tickets[t]
            self.ticket_log[t] = ("unused", now + KAAS_TICKET_LOG_S)       # (it never reached us)
        for t in [t for t, e in self.ticket_log.items() if e[1] <= now]:
            del self.ticket_log[t]
        while len(self.ticket_log) > 4 * KAAS_MAX_TICKETS:
            del self.ticket_log[next(iter(self.ticket_log))]

    def redeem(self, ticket):
        """(the key a ticket was made for, None) or (None, why not: "expired", "unknown", "refused"). A ticket works
        once."""
        with self.lock:
            e = self.tickets.pop(ticket, None)
        if e is None:
            return None, "unknown"
        if e[1] <= time.monotonic():
            return None, "expired"
        key = self.web_key(e[0])
        return (key, None) if key else (None, "refused")

    def ticket_outcome(self, ticket, outcome):
        """What became of a ticket's websocket: "connected", or why it was refused ("no_upgrade", "bad_version",
        "busy", "full", "expired", "refused"). The browser only sees that its websocket didn't open; this tells it
        why (/api/v1/web/ticket)."""
        if not str(ticket).startswith(KAAS_TICKET_PREFIX):
            return
        with self.lock:
            self.tickets.pop(ticket, None)
            self.ticket_log[ticket] = (outcome, time.monotonic() + KAAS_TICKET_LOG_S)

    def ticket_status(self, ticket):
        """POST /api/v1/web/ticket: "waiting" (made, but its websocket hasn't reached us: a proxy or the browser
        stopped it), "unused" (the same, and it has expired), an outcome from ticket_outcome, or "unknown"."""
        with self.lock:
            self._prune_tickets(time.monotonic())
            if ticket in self.tickets:
                return "waiting"
            e = self.ticket_log.get(ticket)
        return e[0] if e else "unknown"

    # ---------------------------------------------------------------- web logins (any thread unless noted)

    def web_banned(self, pub_hex):
        return any(isinstance(b, dict) and b.get("pub") == pub_hex for b in (self.room.cfg.web_banned or []))

    def web_ip_banned(self, ip):
        return any(isinstance(b, dict) and b.get("ip") == ip for b in (self.room.cfg.web_banned_ips or []))

    def web_can_send(self, pub_hex):
        """Heard advertising on this radio (or by an observer, when trusted), or let in by the admin."""
        if pub_hex in (self.room.cfg.web_approved or []):
            return True
        return self.room.heard_on_rf(bytes.fromhex(pub_hex)) is not None      # (on this radio: an MQTT report won't do)

    def web_key(self, pub_hex):
        """A web login as a key: receive always, send once heard or allowed. None while logins are off, or banned."""
        if not self.room.cfg.web_login or self.web_banned(pub_hex):
            return None
        return dict(id=WEB_ID_PREFIX + pub_hex, receive=True, send=self.web_can_send(pub_hex), expires=None, web=pub_hex)

    def new_challenge(self):
        """A web login challenge: its expiry and a nonce, signed with this run's key. Nothing is stored until a login
        uses it, so asking for challenges can't use them up."""
        body = struct.pack(">Q", int(time.time()) + WEB_CHALLENGE_S) + os.urandom(12)
        mac = hmac.new(self.challenge_key, body, hashlib.sha256).digest()[:16]
        return WEB_CHALLENGE_PREFIX + base64.urlsafe_b64encode(body + mac).rstrip(b"=").decode()

    def challenge_expiry(self, ch):
        """A challenge's expiry (time.time) if this server made it and it's still good, else None."""
        try:
            raw = base64.urlsafe_b64decode(str(ch)[len(WEB_CHALLENGE_PREFIX):] + "==")
        except (ValueError, TypeError):
            return None
        if not str(ch).startswith(WEB_CHALLENGE_PREFIX) or len(raw) != 36:
            return None
        if not hmac.compare_digest(raw[20:], hmac.new(self.challenge_key, raw[:20], hashlib.sha256).digest()[:16]):
            return None
        exp = struct.unpack(">Q", raw[:8])[0]
        return exp if exp > time.time() else None

    def web_login(self, body, hosts, ip="?"):
        """POST /api/v1/web/login: {"pub", "signature", "challenge", "host", "name"}, the signature over
        web_login_message(host, challenge, pub). -> (HTTP status, answer): a ticket, and whether this key may send."""
        if not self.room.cfg.web_login:
            return 403, {"error": "web logins are off on this server"}
        body = body if isinstance(body, dict) else {}
        pub, sig, ch, host = (str(body.get(k, "")).strip() for k in ("pub", "signature", "challenge", "host"))
        pub = pub.lower()
        try:
            pb, sb = bytes.fromhex(pub), bytes.fromhex(sig)
        except ValueError:
            pb = sb = b""
        if len(pb) != PUB_KEY_SIZE or len(sb) != SIGNATURE_SIZE:
            return 400, {"error": "pub: a 32-byte public key in hex; signature: 64 bytes in hex"}
        exp = self.challenge_expiry(ch)
        if exp is None:
            return 401, {"error": "unknown or expired challenge: ask for a new one"}
        if host.lower() not in hosts:
            self.web_refused_host(host.lower())
            return 401, {"error": "the login was signed for %s, which isn't one of this server's names (its admin can "
                                  "allow it on the Web users card)" % host[:100]}
        if not ed25519_verify(pb, sb, web_login_message(host, ch, pub)):
            return 401, {"error": "the signature doesn't match the key"}
        now = time.time()
        with self.lock:                                     # (a challenge works once)
            if ch in self.used_challenges:
                return 401, {"error": "that challenge was used already: ask for a new one"}
            for c in [c for c, e in self.used_challenges.items() if e <= now]:
                del self.used_challenges[c]
            if len(self.used_challenges) >= WEB_MAX_USED_CHALLENGES:
                return 503, {"error": "too many logins at once: try again shortly"}
            self.used_challenges[ch] = exp
        if pb in self.room.own_node_keys():
            return 403, {"error": "that key belongs to a node on this server"}
        if self.web_banned(pub):
            return 403, {"error": "this key is banned from this server"}
        name = "".join(c for c in str(body.get("name", "")) if ord(c) >= 0x20)[:32].strip()
        cap = int(self.room.cfg.web_max_clients or 0)
        if sum(1 for c in self.conns if c.web and not c.closed) >= cap:
            log.warning("web login (%s) from %s refused: all %d web sessions are in use", pub[:8], ip, cap)
            return 503, {"error": "all of this server's web sessions are in use (%d): try again later" % cap, "full": True}
        self.web_seen(pub, name, ip)
        key = self.web_key(pub)
        ticket = self.new_ticket(key) if key else None
        if ticket is None:
            return 503, {"error": "too many logins at once: try again shortly"}
        return 200, {"ticket": ticket, "expires_in": KAAS_TICKET_S, "send": key["send"],
                     "state": "allowed" if key["send"] else "pending"}

    def web_refused_host(self, host):
        """A web login signed for a name not in web_hosts: kept (the last few) for the Web users card to offer."""
        if not re.fullmatch(r"[a-z0-9.\-:\[\]]{1,100}", host):
            return
        with self.slock:
            n = self.refused_hosts.pop(host, (0, 0))[0]
            self.refused_hosts[host] = (n + 1, now_s())
            while len(self.refused_hosts) > 10:
                del self.refused_hosts[next(iter(self.refused_hosts))]

    def web_seen(self, pub_hex, name=None, ip=None):
        """A web user logged in, or is still connected: the dashboard's list (the least recently active go first)."""
        now = now_s()
        with self.slock:
            u = self.wusers.get(pub_hex)
            if u is None:
                if len(self.wusers) >= WEB_USERS_MAX:
                    keep = set(self.room.cfg.web_approved or [])
                    cands = [k for k in self.wusers if k not in keep] or list(self.wusers)
                    del self.wusers[min(cands, key=lambda k: self.wusers[k]["last"])]
                u = self.wusers[pub_hex] = dict(name="", first=now, last=now, seq=self.bk_seq, floor=0)
            if name:
                u["name"] = name
            if ip and ip != "?":
                u["ip"] = ip                                # (the last address they logged in from)
            u["last"] = now
            self.wusers_dirty = True

    def save_web_users(self):
        with self.slock:
            if not self.wusers_dirty:
                return
            data = json.dumps(self.wusers)
            self.wusers_dirty = False
        tmp = self.wusers_path + ".tmp"
        try:
            with open(tmp, "w") as f:
                f.write(data)
            os.replace(tmp, self.wusers_path)
        except OSError as e:
            log.warning("web users not saved: %s", e)

    def web_rows(self):
        """The dashboard's Web users card: most recently active first, the connected ones on top."""
        conns = list(self.conns)
        approved = set(self.room.cfg.web_approved or [])
        with self.slock:
            users = {k: dict(v) for k, v in self.wusers.items()}
        rows = []
        per_ip = collections.Counter(u.get("ip") for u in users.values() if u.get("ip"))
        for pub, u in users.items():
            n = self.room.nodes.get(bytes.fromhex(pub)) or {}
            connected = sum(1 for c in conns if c.web == pub)
            rows.append(dict(pub=pub, name=u["name"], advert_name=n.get("name") or None, first=u["first"], last=u["last"],
                             heard_rf=n.get("rf"), heard_obs=n.get("obs"), approved=pub in approved,
                             send=self.web_can_send(pub), banned=self.web_banned(pub), connected=connected,
                             ip=u.get("ip"), ip_shared=max(0, per_ip[u.get("ip")] - 1) if u.get("ip") else 0,
                             ip_banned=bool(u.get("ip")) and self.web_ip_banned(u.get("ip")),
                             stats=self.key_stats(WEB_ID_PREFIX + pub)))
        rows.sort(key=lambda r: (-min(r["connected"], 1), -r["last"]))
        for r in rows:                                      # backlog packets since they were last connected
            r["missed"] = 0 if r["connected"] else max(0, self.bk_seq - users[r["pub"]].get("seq", self.bk_seq))
        return rows

    @staticmethod
    def valid(k, now=None):
        return k is not None and (not k.get("expires") or k["expires"] > (now or time.time()))

    def new_key(self, spec):
        """(token, entry): the token goes back to the dashboard once; the config keeps only its hash."""
        import secrets
        token = KAAS_TOKEN_PREFIX + secrets.token_urlsafe(32)
        entry = dict(id=secrets.token_hex(4), hash=kaas_token_hash(token), created=now_s(), last_used=None, **spec)
        return token, entry

    def key_rows(self):
        conns = list(self.conns)
        return [dict(id=k["id"], description=k.get("description", ""),
                     receive=bool(k.get("receive")), send=bool(k.get("send")), expires=k.get("expires"),
                     created=k.get("created"), expired=not self.valid(k),
                     last_used=max(self.last_used.get(k["id"]) or 0, k.get("last_used") or 0) or None,
                     connected=sum(1 for c in conns if c.key_id == k["id"]), stats=self.key_stats(k["id"]))
                for k in self.keys()]

    def event(self, ev):
        """kaas_key_add / kaas_key_del / kaas_used / kaas_tx, in the main loop."""
        kind, cfg = ev[0], self.room.cfg
        if kind == "kaas_tx":
            self.send(*ev[1:])
            return
        if kind == "kaas_query":
            self.query(*ev[1:])
            return
        if kind == "kaas_web_admin":
            self.web_admin(*ev[1:])
            return
        if kind == "kaas_room":
            self.room_request(*ev[1:])
            return
        if kind == "kaas_key_add":
            cfg.set("kaas_keys", self.keys() + [ev[1]])
        elif kind == "kaas_key_del":
            cfg.set("kaas_keys", [k for k in self.keys() if k["id"] != ev[1]])
            for c in self.conns:
                if c.key_id == ev[1]:
                    c.close(4001, "key revoked")
            with self.slock:
                if self.kstats.pop(ev[1], None) is not None:
                    self.kstats_dirty = True
        elif kind == "kaas_used":
            cfg.set("kaas_keys", [dict(k, last_used=ev[2]) if k["id"] == ev[1] else k for k in self.keys()])
        self.room.web_dirty = True

    def web_admin(self, action, pub_hex, name=""):
        """The dashboard's Web users card, in the main loop: allow / unallow sending, kick, ban, unban, forget;
        or ("settings", {"web_login": bool, ...})."""
        cfg = self.room.cfg
        if action == "settings":
            for k, v in pub_hex.items():
                cfg.set(k, v)
        elif action == "allow":
            cfg.set("web_approved", [p for p in (cfg.web_approved or []) if p != pub_hex] + [pub_hex])
        elif action == "unallow":
            cfg.set("web_approved", [p for p in (cfg.web_approved or []) if p != pub_hex])
        elif action == "ban":
            with self.slock:
                name = name or (self.wusers.get(pub_hex) or {}).get("name", "")
            cfg.set("web_banned", [b for b in (cfg.web_banned or []) if isinstance(b, dict) and b.get("pub") != pub_hex] +
                    [dict(pub=pub_hex, name=name, ts=now_s())])
            cfg.set("web_approved", [p for p in (cfg.web_approved or []) if p != pub_hex])
        elif action == "unban":
            cfg.set("web_banned", [b for b in (cfg.web_banned or []) if isinstance(b, dict) and b.get("pub") != pub_hex])
        elif action == "ban_ip":                            # (pub_hex is the address here)
            cfg.set("web_banned_ips", [b for b in (cfg.web_banned_ips or []) if isinstance(b, dict) and b.get("ip") != pub_hex] +
                    [dict(ip=pub_hex, name=name, ts=now_s())])
            for c in list(self.conns):
                if c.web and getattr(c, "ip", None) == pub_hex:
                    c.close(4003, "this address is banned from this server")
        elif action == "unban_ip":
            cfg.set("web_banned_ips", [b for b in (cfg.web_banned_ips or []) if isinstance(b, dict) and b.get("ip") != pub_hex])
        elif action == "purge":                             # their backlog: as if they'd caught up just now
            with self.slock:
                u = self.wusers.get(pub_hex)
                if u is not None:
                    u["floor"] = u["seq"] = self.bk_seq
                    self.wusers_dirty = True
        elif action == "delete":                            # forget them: their record, counts, and "allow send"
            with self.slock:
                if self.wusers.pop(pub_hex, None) is not None:
                    self.wusers_dirty = True
                if self.kstats.pop(WEB_ID_PREFIX + pub_hex, None) is not None:
                    self.kstats_dirty = True
            cfg.set("web_approved", [p for p in (cfg.web_approved or []) if p != pub_hex])
        for c in self.conns:
            if c.web and (c.web == pub_hex or action == "settings"):
                if action in ("kick", "delete"):
                    c.close(4005, "disconnected by the admin")
                elif action == "ban":
                    c.close(4003, "this key is banned from this server")
        self.next_check = 0.0                               # settings, allow/unallow: applied by the next periodic check
        self.room.web_dirty = True

    # ---------------------------------------------------------------- clients

    def add(self, conn):
        with self.lock:
            web = sum(1 for c in self.conns if c.web)
            if (web >= int(self.room.cfg.web_max_clients or 0)) if conn.web else (len(self.conns) - web >= KAAS_MAX_CLIENTS):
                return False
            self.conns = self.conns + [conn]
        self.last_used[conn.key_id] = now_s()
        return True

    def drop(self, conn):
        with self.lock:
            self.conns = [c for c in self.conns if c is not conn]

    def web_sessions_from(self, ip):
        return sum(1 for c in self.conns if c.web and c.ip == ip and not c.closed)

    def close_all(self):
        for c in self.conns:
            c.close(1001, "server shutting down")
        self.save_stats()

    def hello(self, key):
        room = self.room
        radio = dict(zip(("freq_hz", "bw_hz", "sf", "cr"), room.radio)) if room.radio else None
        return {"type": "hello", "api": 1, "server": FIRMWARE_VERSION,
                "key": dict({"id": key["id"], "receive": bool(key.get("receive")), "send": bool(key.get("send")),
                             "expires": key.get("expires")},
                            **({"web": True, "pub": key["web"], "state": "allowed" if key.get("send") else "pending",
                                "pending_message": str(room.cfg.web_unknown_key_message or "")}
                               if key.get("web") else {})),
                "send_burst": int(room.cfg.kaas_send_burst), "send_window_s": float(room.cfg.kaas_send_window_s),
                "airtime_pct": room.air.rates()[1]["web" if key.get("web") else "kaas"] * 100.0,   # (its class's
                                                                                   # guaranteed share; more when quiet)
                "radio": radio,
                "giphy_key": (room.cfg.web_giphy_key or None) if key.get("web") else None,   # (Giphy keys are for browsers)
                "motd": (str(room.cfg.web_motd).strip() or None) if key.get("web") and room.cfg.web_motd_enabled else None,
                "nodes": {"room": None,                     # (the host isn't a room: every room is in tenants)
                          "tenants": [hexs(t.id.pub_key) for t in list(room.tenants.values())],
                          "repeater": hexs(room.vr.pub) if room.vr is not None else None,
                          "companion": hexs(room.vc.pub) if room.vc is not None else None},
                "names": {hexs(t.id.pub_key): t.cfg.name for t in list(room.tenants.values())}}

    def on_message(self, conn, msg):
        """A client's message (its reader thread). Sends go to the main loop; at most KAAS_MAX_INFLIGHT wait there."""
        t, rid = msg.get("type"), msg.get("id")
        if rid is not None and not (isinstance(rid, (str, int)) and not isinstance(rid, bool) and len(str(rid)) <= 64):
            rid = None
        if t == "ping":
            return conn.send_json({"type": "pong", "id": rid})
        if t in ("near", "routes", "route", "nodes", "paths"):
            return self.ask(conn, t, msg, rid)
        if t == "replay":
            return self.replay(conn, msg, rid)
        if t in ("room", "room_post"):
            return self.room_ask(conn, t, msg, rid)
        if t != "send":
            return conn.send_json({"type": "error", "id": rid,
                                   "error": "unknown message type: use send, near, routes, route, paths, nodes or ping"})

        def drop(reason):
            self.stats["dropped"] += 1
            conn.send_json({"type": "send_result", "id": rid, "status": "dropped", "reason": reason})
        if not conn.can_send:
            return drop("your key hasn't been heard on this radio yet: the admin can let it send" if conn.web
                        else "this key can't send")
        try:
            raw = bytes.fromhex(str(msg.get("raw", "")))
        except ValueError:
            return drop("raw must be the packet in hex")
        with conn.cv:
            if conn.inflight >= KAAS_MAX_INFLIGHT:
                busy = True
            else:
                busy = False
                conn.inflight += 1
        if busy:
            return drop("too many sends waiting: wait for their results")
        self.room.events_put(("kaas_tx", conn, raw, rid))

    # ---------------------------------------------------------------- the backlog (MeshCore Web's catch-up)

    def backlog_add(self, raw, src, snr=None):
        """A packet heard ("rf": by this radio, or sent by it) or reported by an observer ("mqtt"), in the main loop.
        Channel messages and DMs are kept, once each whatever the source, numbered in order. -> its seq and whether
        it's new, or (None, False) when it isn't kept."""
        cfg = self.room.cfg
        if self.bk_store is None or int(cfg.web_backlog_days or 0) <= 0:
            return None, False
        pkt = Packet.parse(raw)
        if pkt is None or pkt.ptype not in BACKLOG_TYPES or len(pkt.payload) < 2:
            return None, False
        h = pkt.packet_hash()
        with self.bk_lock:
            seq = self.bk_recent.get(h)
            if seq is not None:
                return seq, False                           # another copy: through another repeater, or MQTT and RF
            self.bk_seq += 1
            seq = self.bk_recent[h] = self.bk_seq
            while len(self.bk_recent) > BACKLOG_RECENT:
                self.bk_recent.popitem(last=False)
            p = pkt.payload
            self.bk_pending.append((seq, h, now_s(), bytes(raw), src, snr, pkt.ptype,
                                    p[0] if pkt.ptype == PT_GRP_TXT else None, p[0] if pkt.ptype == PT_TXT_MSG else None))
        return seq, True

    def backlog_info(self):
        """For the dashboard (a web thread): the settings, and how much is kept."""
        cfg = self.room.cfg
        info = {"days": int(cfg.web_backlog_days or 0), "mqtt": bool(cfg.web_backlog_mqtt), "count": 0, "oldest": None,
                "seq": self.bk_seq}
        if self.bk_store is not None:
            try:
                n, oldest = self.bk_store.read("SELECT COUNT(*), MIN(ts) FROM backlog")[0]
                info.update(count=int(n or 0) + len(self.bk_pending), oldest=oldest)
            except Exception:
                pass
        return info

    def backlog_mqtt(self, raw, snr):
        """A channel message or DM an MQTT observer reported: kept, and to web users at once (they'd see it on their
        next catch-up otherwise). Read only, like a catch-up: the radio didn't hear it."""
        if not self.room.cfg.web_backlog_mqtt:
            return
        seq, new = self.backlog_add(raw, "mqtt", snr)
        if not new:
            return
        conns = [c for c in self.conns if c.web and c.can_receive]
        if conns:
            text = json.dumps({"type": "packet", "dir": "mqtt", "ts": round(time.time(), 3), "raw": bytes(raw).hex(),
                               "seq": seq}, separators=(",", ":"))
            for c in conns:
                c.put(text)
                self.count(c.key_id, "rx")

    def backlog_periodic(self):
        """Main loop: write new rows (one transaction a second at most), and prune past web_backlog_days."""
        if self.bk_store is None:
            return
        now = time.monotonic()
        if self.bk_pending and now >= self.bk_next_flush:
            self.bk_next_flush = now + BACKLOG_FLUSH_S
            with self.bk_lock:
                rows, self.bk_pending = self.bk_pending, []
            self.bk_store.execmany([("INSERT OR IGNORE INTO backlog (seq, hash, ts, raw, src, snr, ptype, ch, dst) "
                                     "VALUES (?,?,?,?,?,?,?,?,?)", rows)])
        if now >= self.bk_next_prune:
            self.bk_next_prune = now + BACKLOG_PRUNE_S
            days = int(self.room.cfg.web_backlog_days or 0)
            self.bk_store.execmany([("DELETE FROM backlog WHERE ts < ?", [(now_s() - days * 86400,)])])

    def replay(self, conn, msg, rid):
        """A web user's catch-up: {"type": "replay", "since": seq or null, "channels": [channel hash bytes], "me": its key's
        hash byte}. The channel messages and DMs kept after `since` (and after the admin's purge) that could be for it,
        in batches; then replay_done with the seq it's up to. No `since` (a first visit): nothing, just that seq."""
        def err(e):
            conn.send_json({"type": "error", "id": rid, "error": e})
        if not conn.web:
            return err("catching up is for web logins only")
        since, chans, me = msg.get("since"), msg.get("channels") or [], msg.get("me")
        ok_byte = lambda x: isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= 255
        if since is not None and (isinstance(since, bool) or not isinstance(since, int) or since < 0):
            return err("since: a seq from a packet, or null")
        if not isinstance(chans, list) or len(chans) > 256 or not all(ok_byte(x) for x in chans) or not ok_byte(me):
            return err("channels: channel hash bytes; me: your key's first byte")
        if getattr(conn, "replaying", False):
            return err("a catch-up is already running")
        conn.replaying = True
        threading.Thread(target=self._replay, args=(conn, rid, since, sorted(set(chans)), me), name="kaas-replay",
                         daemon=True).start()

    def _replay(self, conn, rid, since, chans, me):
        try:
            with self.slock:
                u = dict(self.wusers.get(conn.web) or {})
            top = self.bk_seq
            if since is None or self.bk_store is None:
                conn.send_json({"type": "replay_done", "id": rid, "last": top, "count": 0})
                return
            since = max(since, int(u.get("floor") or 0))
            want = lambda ptype, ch, dst: (ptype == PT_GRP_TXT and ch in chans) or (ptype == PT_TXT_MSG and dst == me)
            marks = ",".join("?" * len(chans)) or "NULL"
            sql = ("SELECT seq, raw, ts, src, snr FROM backlog WHERE seq > ? AND seq <= ? AND ((ptype = %d AND ch IN (%s)) OR "
                   "(ptype = %d AND dst = ?)) ORDER BY seq LIMIT %d" % (PT_GRP_TXT, marks, PT_TXT_MSG, BACKLOG_BATCH))
            sent, last = 0, since
            while not conn.closed:
                rows = self.bk_store.read(sql, (last, top, *chans, me))
                if not rows:
                    with self.bk_lock:                      # (and what's not written yet)
                        rows = [(r[0], r[3], r[2], r[4], r[5]) for r in self.bk_pending
                                if last < r[0] <= top and want(r[6], r[7], r[8])][:BACKLOG_BATCH]
                    if not rows:
                        break
                pkts = [{"seq": q, "raw": bytes(raw).hex(), "ts": ts, "dir": "mqtt" if src == "mqtt" else "rx",
                         "snr": snr} for q, raw, ts, src, snr in rows]
                while len(conn.out) > 32 and not conn.closed:
                    time.sleep(0.05)                        # let the client keep up: its outbox is bounded
                conn.send_json({"type": "replay_batch", "id": rid, "packets": pkts})
                sent += len(pkts)
                last = rows[-1][0]
                self.count(conn.key_id, "rx", len(pkts))
            conn.send_json({"type": "replay_done", "id": rid, "last": top, "count": sent})
            with self.slock:
                if conn.web in self.wusers:
                    self.wusers[conn.web]["seq"] = max(self.wusers[conn.web].get("seq", 0), top)
                    self.wusers_dirty = True
        except Exception as e:
            log.warning("catch-up for %s failed: %s", conn.web[:8], e)
            conn.send_json({"type": "error", "id": rid, "error": "the catch-up failed"})
        finally:
            conn.replaying = False

    def query_allowed(self, conn, t):
        """A key's query budget, across its connections: KAAS_QUERY_LIMITS per minute (the main loop answers them)."""
        kind = "nodes" if t == "nodes" else "route"
        limit = KAAS_QUERY_LIMITS[kind]
        now = time.monotonic()
        with self.lock:
            q = self.qtimes.setdefault((conn.key_id, kind), collections.deque())
            while q and now - q[0] >= 60:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self.qtimes) > 4096:                     # (keys gone quiet)
                for k in [k for k, v in self.qtimes.items() if not v or now - v[-1] >= 60]:
                    del self.qtimes[k]
        return True

    def ask(self, conn, t, msg, rid):
        """A route question: checked here, answered by the main loop (it owns the map). Shares the in-flight cap."""
        def err(e):
            conn.send_json({"type": "error", "id": rid, "error": e})
        def over_budget():
            if self.query_allowed(conn, t):
                return False
            kind = "nodes" if t == "nodes" else "route"
            err("too many %s requests: at most %d a minute" % (kind, KAAS_QUERY_LIMITS[kind]))
            return True
        if t == "nodes":
            days = msg.get("days", 7)
            top = NODES_DAYS_WEB if conn.web else 365
            if isinstance(days, bool) or not isinstance(days, (int, float)) or not 0 < days <= top:
                return err("days: more than 0, at most %d" % top)
            if over_budget():
                return
            with conn.cv:
                if conn.inflight >= KAAS_MAX_INFLIGHT:
                    return err("too many requests waiting: wait for their answers")
                conn.inflight += 1
            return self.room.events_put(("kaas_query", conn, t, float(days), NODES_ANSWER_MAX, rid))
        if t == "paths":
            try:
                node = bytes.fromhex(str(msg.get("node", "")))
            except ValueError:
                node = b""
            limit = msg.get("limit", 4)
            if len(node) != PUB_KEY_SIZE:
                return err("node: its public key in hex (64 characters)")
            if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 8:
                return err("limit: 1 to 8")
            if over_budget():
                return
            with conn.cv:
                if conn.inflight >= KAAS_MAX_INFLIGHT:
                    return err("too many requests waiting: wait for their answers")
                conn.inflight += 1
            return self.room.events_put(("kaas_query", conn, t, node, limit, rid))
        try:
            key = bytes.fromhex(str(msg.get("node" if t == "near" else "repeater", "")))
        except ValueError:
            key = b""
        if t == "near" and "name" in msg and "node" not in msg:
            key = kaas_mention_name(msg["name"])
            if key is None:
                return err("name: the node's advertised name, or a mention like @[name]")
        elif t == "near" and not 8 <= len(key) <= 32:
            return err("node: its public key in hex (at least the first 8 bytes), or name: its advertised name")
        if t == "routes" and not 2 <= len(key) <= 32:
            return err("repeater: its public key in hex (at least the first 2 bytes)")
        if t == "route":
            key = (kaas_endpoint(msg.get("from")), kaas_endpoint(msg.get("to")))
            for end, spec in zip(("from", "to"), key):
                if spec is None:
                    return err(end + ": a node's public key in hex (at least 8 bytes), its name or @[name], "
                               "or a repeater's 2-byte id in hex")
        limit = msg.get("limit", 4 if t == "near" else 3)
        top = KAAS_MAX_ROUTES if t == "route" else 10
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= top:
            return err("limit: 1 to %d" % top)
        if over_budget():
            return
        with conn.cv:
            if conn.inflight >= KAAS_MAX_INFLIGHT:
                return err("too many requests waiting: wait for their answers")
            conn.inflight += 1
        self.room.events_put(("kaas_query", conn, t, key, limit, rid))

    # ---------------------------------------------------------------- this server's rooms, for web logins

    def room_ask(self, conn, t, msg, rid):
        """A web login's "room" (read a room on this server: its posts, then each new one as it's stored) or
        "room_post" (post to it). Straight to the room, not over the air: the member's sync point and routes, which
        their radio companion relies on, are left alone. Checked here, done in the main loop."""
        def err(e):
            conn.send_json({"type": "error", "id": rid, "error": e})
        if not conn.web:
            return err("rooms on this server: for web logins only (an API key logs in over the air)")
        try:
            pub = bytes.fromhex(str(msg.get("room", "")))
        except ValueError:
            pub = b""
        if len(pub) != PUB_KEY_SIZE:
            return err("room: the room's public key in hex")
        if not conn.can_send:                               # (rooms too: nothing for a key not yet allowed)
            return err("your key hasn't been heard on this radio yet: the admin can let it send")
        if t == "room":
            since, pw = msg.get("since", 0), msg.get("password", "")
            if isinstance(since, bool) or not isinstance(since, int) or since < 0 or not isinstance(pw, str):
                return err("since: a timestamp (0 for the latest posts); password: text")
            arg = (since, pw[:15])
        else:
            text = msg.get("text")
            if not isinstance(text, str) or not text.strip() or len(text.strip().encode()) > MAX_POST_TEXT_LEN:
                return err("text: 1 to %d bytes" % MAX_POST_TEXT_LEN)
            arg = text.strip()
        with conn.cv:
            if conn.inflight >= KAAS_MAX_INFLIGHT:
                return err("too many requests waiting: wait for their answers")
            conn.inflight += 1
        self.room.events_put(("kaas_room", conn, t, pub, arg, rid))

    def local_room(self, pub):
        return self.room.tenants.get(pub)

    def room_request(self, conn, t, pub, arg, rid):
        """In the main loop. room: (since, password) -> the posts this member may see after since (all of the newest
        catchup_max when 0), and from now on each new one as "room_post". room_post: text -> stored as their post."""
        with conn.cv:
            conn.inflight = max(0, conn.inflight - 1)
        r, me = self.local_room(pub), bytes.fromhex(conn.web)

        def err(e, **kw):
            conn.send_json(dict({"type": "error", "id": rid, "error": e}, **kw))
        if r is None:
            return err("not a room on this server", local=False)
        if me in r.bans:
            return err("you're banned from this room")
        m = r.members.get(me)
        if t == "room":
            since, pw = arg
            if m is None or (pw and m.role == PERM_GUEST):  # (a member is known by their key: no password needed)
                if r.login_blocked(me):
                    return err("too many wrong passwords: try again later", refused=True)
                if r.cfg.admin_password and same_text(pw, r.cfg.admin_password):
                    perm = PERM_ADMIN
                elif same_text(pw, r.cfg.room_password):
                    perm = PERM_READ_WRITE
                elif r.cfg.allow_read_only:
                    perm = PERM_GUEST
                else:
                    r.login_failed(me)
                    return err("the room refused the login (a wrong password?)", refused=True)
                if m is None:
                    m = r.put_member(me)
                    m.secret = r.id.shared_secret(me)
                    public = [p for p in r.posts if p[3] is None]          # what a new member's radio would get
                    m.sync_since = public[-r.cfg.catchup_max - 1][0] if 0 < r.cfg.catchup_max < len(public) else 0
                m.perms = (m.perms & ~3) | perm
                r.mark_dirty()
            # (last_activity is left alone: it's what makes the room push over the air. A member who joined here has
            # none until their radio logs in, so the room never pushes to a radio that isn't there.)
            seen = [p for p in r.posts if p[0] > since and (p[3] is None or p[3] == me)]
            if since == 0:
                seen = seen[-max(1, int(r.cfg.catchup_max or 50)):]
            conn.rooms.add(pub)
            conn.send_json({"type": "room_result", "id": rid, "room": pub.hex(), "name": r.cfg.name,
                            "admin": m.is_admin, "perms": m.perms, "can_post": m.role != PERM_GUEST,
                            "posts": [self.room_post_json(r, p) for p in seen[-ROOM_ANSWER_MAX:]]})
            return
        if m is None or m.role == PERM_GUEST:
            return err("log in to the room with its password to post", refused=m is None)
        if r.is_manual_resend(m, arg):
            return conn.send_json({"type": "room_post_result", "id": rid, "status": "duplicate"})
        r.store_post(me, arg)
        conn.send_json({"type": "room_post_result", "id": rid, "status": "posted", "ts": r.posts[-1][0]})

    def room_post_json(self, r, p):
        ts, author, text, to = p
        return {"ts": ts, "author": author.hex(), "name": r.chat_label(author), "text": text, "private": to is not None}

    def room_post_added(self, r, p):
        """A post was just stored in room r (main loop): to the web sessions following it that may see it."""
        pub = r.id.pub_key
        for c in self.conns:
            if c.web and pub in c.rooms and not c.closed and (p[3] is None or p[3].hex() == c.web) \
                    and bytes.fromhex(c.web) not in r.bans:
                c.send_json(dict(self.room_post_json(r, p), type="room_post", room=pub.hex()))

    # ---------------------------------------------------------------- the main loop's side

    def query(self, conn, t, key, limit, rid):
        """near: the repeaters that hear a node (its first hop into the mesh), with each one's share.
        routes: the room's best known routes to a repeater (from this radio), ready to use as a direct path."""
        with conn.cv:
            conn.inflight -= 1
        r = self.room
        if getattr(r, "_rpt_idx", None) is None:
            r.build_rpt_index()

        def name(h):
            hit = r.rpt_lookup(h)
            return hit[1]["name"] if hit and hit[1].get("name") else None
        if t == "nodes":
            return self.nodes_answer(conn, key, limit, rid)
        if t == "near" and isinstance(key, str):
            k8 = r.node_by_name(key)
            if k8 is None:
                conn.send_json({"type": "error", "id": rid, "error": "no node named %s has been heard" % key})
                return
            key = k8
        if t == "route":
            return self.route(conn, key, limit, rid, name)
        if t == "paths":
            return self.paths_answer(conn, key, limit, rid, name)
        if t == "near":
            rows = r.locations(key[:8])[:limit]
            nm = r.names.get(key[:8])
            # heard with no hops: by this radio itself, so name its virtual repeater (what relays for it), else the room
            here = ({"id": r.vr.pub[:2].hex(), "name": r.cfg.repeater_name} if r.vr is not None else
                    {"id": r.id.pub_key[:2].hex(), "name": r.cfg.name})
            conn.send_json({"type": "near_result", "id": rid, "node": key.hex(), "name": nm[1] if nm else None,
                            "repeaters": [dict(here, direct=True, share=round(share, 3)) if h == b"" else
                                          {"id": h.hex(), "name": name(h), "share": round(share, 3)}
                                          for h, share in rows]})
            return
        target = key[:2]
        rows = []
        for rr, conf in r.top_rpt_routes(target, limit):
            sz = (rr.plen >> 6) + 1
            hops = [rr.path[i * sz:(i + 1) * sz] for i in range(rr.plen & 63)]
            rows.append({"path_len": rr.plen, "path": rr.path.hex(), "hops": [h.hex() for h in hops],
                         "names": [name(h) for h in hops], "confidence": round(conf, 3)})
        conn.send_json({"type": "routes_result", "id": rid, "repeater": target.hex(), "name": name(target), "routes": rows})

    def nodes_answer(self, conn, days, limit, rid):
        """nodes: everyone this server knows of, heard in the last `days`, newest first, for contact lists and maps. The
        node directory (adverts heard here or by an MQTT observer), plus what the room already kept: the repeater map
        and neighbours, room members (main and tenant rooms), the virtual companion's contacts, and the name cache.
        The name cache holds only the first 8 bytes of a key: those come as "partial", with that much of the key."""
        r = self.room
        since = now_s() - days * 86400
        types = {ADV_TYPE_CHAT: "chat", ADV_TYPE_REPEATER: "repeater", ADV_TYPE_ROOM: "room", ADV_TYPE_SENSOR: "sensor"}
        found = {}                                          # pub -> row; a later source only fills in what's missing

        def add(pub, kind, name, last, lat=None, lon=None, rf=None, obs=None):
            pub = bytes(pub)
            if len(pub) != PUB_KEY_SIZE or pub in self.own_keys():
                return
            row = found.get(pub)
            if row is None:
                row = found[pub] = {"pub": pub.hex(), "type": kind, "name": "", "lat": None, "lon": None,
                                    "last_heard": 0, "rf": rf, "obs": obs}
            row["name"] = row["name"] or name or ""
            if row["lat"] is None and lat is not None and (lat or lon):
                row["lat"], row["lon"] = lat, lon
            row["last_heard"] = max(row["last_heard"], int(last or 0))

        for pub, n in list(r.nodes.items()):
            add(pub, types.get(n["type"], n["type"]), n["name"], max(n["rf"] or 0, n["obs"] or 0), n["lat"], n["lon"],
                n["rf"], n["obs"])
        for pub, x in list(r.repeaters.items()):
            add(pub, "repeater", x.get("name"), x.get("last_advert"), x.get("lat"), x.get("lon"))
        for pub, x in list(r.neighbours.items()):
            add(pub, "repeater", x.get("name"), x.get("heard"))
        for room in [r] + list(r.tenants.values()):
            for pub, m in list(room.members.items()):
                nm = r.names.get(pub[:8])
                add(pub, "chat", nm[1] if nm else "", max(m.last_heard or 0, m.last_activity or 0))
        if r.vc is not None:
            for pub, c in list(r.vc.contacts.items()):
                add(pub, types.get(c.type, "chat"), c.name, c.lastmod or c.adv_ts,
                    c.lat / 1e6 if c.lat else None, c.lon / 1e6 if c.lon else None)
        prefixes = {pub[:8] for pub in found}
        partial = [{"pub": k8.hex(), "partial": True, "type": "chat", "name": name, "lat": None, "lon": None,
                    "last_heard": int(ts or 0), "rf": None, "obs": None}
                   for k8, (ts, name) in list(r.names.items()) if k8 not in prefixes and name]
        rows = [x for x in list(found.values()) + partial if x["last_heard"] >= since]
        rows.sort(key=lambda x: -x["last_heard"])
        conn.send_json({"type": "nodes_result", "id": rid, "nodes": rows[:limit]})

    def route(self, conn, ends, limit, rid, name):
        """route: suggested repeater chains from one node (or repeater) to another, through the links the room
        has seen, best first and scored."""
        r = self.room
        sides = []
        for spec in ends:
            kind, v = spec
            if kind == "repeater":
                sides.append(({"repeater": v.hex(), "name": name(v)}, {v[:2]: 1.0}))
                continue
            k8 = r.node_by_name(v) if kind == "name" else v[:8]
            if k8 is None:
                return conn.send_json({"type": "error", "id": rid, "error": "no node named %s has been heard" % v})
            nm = r.names.get(k8)
            locs = dict(r.locations(k8))
            if not locs:
                return conn.send_json({"type": "error", "id": rid, "error": "no recent location for %s: it hasn't "
                                       "flood-adverted lately" % (nm[1] if nm else k8.hex())})
            sides.append(({"node": k8.hex(), "name": nm[1] if nm else None}, locs))
        rows = []
        for hops, score in r.suggest_routes(sides[0][1], sides[1][1], limit):
            rows.append({"path_len": 0x40 | len(hops), "path": b"".join(hops).hex(), "hops": [h.hex() for h in hops],
                         "names": [name(h) for h in hops], "score": round(score, 3)})
        conn.send_json({"type": "route_result", "id": rid, "from": sides[0][0], "to": sides[1][0], "routes": rows})

    def paths_answer(self, conn, pub, limit, rid, name):
        """paths: direct paths from this radio to a node, best first, as the room plans its own pushes: routes measured
        by delivering to it (when it's a member here), routes built from the repeaters that hear it and this radio's
        best route to each, and shortcuts. Each is ready to put on a packet (path_len, path)."""
        r = self.room
        found = {}
        rooms = [x for x in [r] + list(r.tenants.values()) if pub in x.members]
        for room, m in [(x, x.members[pub]) for x in rooms] or [(r, types.SimpleNamespace(pub=pub, routes=[]))]:
            for c in room.candidates(m):
                if c["plen"] is None:
                    continue
                k = (c["plen"], bytes(c["path"]))
                old = found.get(k)
                if old is None or c["score"] > old["score"] or (c["proven"] is not None and old["proven"] is None):
                    found[k] = c
        rows = []
        for c in sorted(found.values(), key=lambda c: (-round(c["score"], 2), c["plen"] & 63))[:limit]:
            sz, n = (c["plen"] >> 6) + 1, c["plen"] & 63
            hops = [bytes(c["path"])[i * sz:(i + 1) * sz] for i in range(n)]
            rows.append({"path_len": c["plen"], "path": bytes(c["path"]).hex(), "hops": [h.hex() for h in hops],
                         "names": [name(h) for h in hops], "score": round(c["score"], 3),
                         "source": "measured" if c["proven"] is not None else "shortcut" if c["built"] == "shortcut"
                         else "direct" if n == 0 else "map"})
        nm = r.names.get(pub[:8])
        conn.send_json({"type": "paths_result", "id": rid, "node": pub.hex(), "name": nm[1] if nm else None,
                        "paths": rows})

    def own_keys(self):
        r = self.room
        keys = {r.id.pub_key} | {t.id.pub_key for t in r.tenants.values()}
        if r.vr is not None:
            keys.add(r.vr.pub)
        if r.vc is not None:
            keys.add(r.vc.pub)
        return keys

    def publish(self, direction, raw, snr=None, rssi=None):
        """A packet this radio heard ("rx") or sent ("tx"): to every client that may receive. Channel messages and DMs
        are kept for MeshCore Web's catch-up, and carry their number (seq)."""
        raw = bytes(raw)
        seq, _ = self.backlog_add(raw, "rf", snr)
        conns = [c for c in self.conns if c.can_receive]
        if not conns:
            return
        msg = {"type": "packet", "dir": direction, "ts": round(time.time(), 3), "raw": raw.hex()}
        if seq is not None:
            msg["seq"] = seq
        pkt = Packet.parse(raw)
        if pkt is not None:
            msg.update(ptype=PT_NAMES[pkt.ptype] if pkt.ptype < len(PT_NAMES) else pkt.ptype,
                       route="flood" if pkt.is_flood else "direct", hops=pkt.hop_count, hash=pkt.packet_hash().hex())
        if direction == "rx":
            msg.update(snr=snr, rssi=rssi)
        self.stats[direction] += 1
        text = json.dumps(msg, separators=(",", ":"))
        for c in conns:
            c.put(text)
            self.count(c.key_id, "rx")

    def send(self, conn, raw, rid):
        """A client's packet: checked, rate-limited, offered to the nodes on this radio, then queued for the air at the
        lowest priority. ACKs and path returns (which usually carry an ACK) skip the per-key rate limit, since a bot must
        answer what it's sent. Airtime comes out of the web users' or API clients' share (see Airtime)."""
        with conn.cv:
            conn.inflight -= 1

        def result(status, **kw):
            if status == "dropped":
                self.stats["dropped"] += 1
            conn.send_json(dict(type="send_result", id=rid, status=status, **kw))
        if conn.closed:
            return
        if conn.web:
            k = self.web_key(conn.web)
            if k is None or not k["send"]:
                return result("dropped", reason="this key may not send (anymore)")
        else:
            k = self.key_by_id(conn.key_id)
            if not self.valid(k) or not k.get("send"):
                return result("dropped", reason="key revoked or expired")
        pkt = Packet.parse(raw)
        if pkt is None or pkt.encode() != raw:
            return result("dropped", reason="not a valid MeshCore packet")
        if conn.web:
            why = web_packet_check(pkt, bytes.fromhex(conn.web))
            if why:
                return result("dropped", reason=why)
        own = self.own_keys()
        if (pkt.ptype == PT_ADVERT and pkt.payload[:PUB_KEY_SIZE] in own) or \
                (pkt.ptype == PT_ANON_REQ and pkt.payload[1:1 + PUB_KEY_SIZE] in own):
            return result("dropped", reason="that packet speaks for a node on this radio")
        now = time.monotonic()
        exempt = pkt.ptype in (PT_ACK, PT_PATH)
        burst, window = int(self.room.cfg.kaas_send_burst or 1), float(self.room.cfg.kaas_send_window_s or 0)
        recent = self.last_send.setdefault(conn.key_id, collections.deque())
        while recent and recent[0] <= now - window:
            recent.popleft()
        if not exempt and len(recent) >= burst:
            return result("dropped", reason="rate limit: %d packets per %g s per key (ACKs and paths excepted)" % (burst, window),
                          retry_after=round(max(recent[0] + window - now, 0.1), 1))
        if not exempt:
            recent.append(now)
        self.last_used[conn.key_id] = now_s()
        if self.room.vr is not None and pkt.is_direct and pkt.hop_count and pkt.ptype != PT_TRACE:
            pkt.path, pkt.path_len = self.room.vr.strip_first_hops(pkt.path, pkt.path_len)   # (as the room does: our own
                                                                                             # repeater is this radio)
        if self.room.offer(pkt, self) and (pkt.is_flood or pkt.hop_count == 0 or pkt.ptype == PT_TRACE):
            self.stats["local"] += 1
            return result("local")                          # only for a node on this radio: it never goes on the air
        self.room.queue_tx(pkt, KAAS_PRIO, 0.0, deferrable=not exempt, src=self, tag=(conn, rid))
        result("queued")

    def sent(self, tag):
        conn, rid = tag
        self.stats["sent"] += 1
        conn.send_json({"type": "send_result", "id": rid, "status": "sent"})

    def dropped(self, tag, reason):
        """A queued packet that never went out."""
        conn, rid = tag
        self.stats["dropped"] += 1
        conn.send_json({"type": "send_result", "id": rid, "status": "dropped", "reason": reason})

    def periodic(self):
        """Close connections whose key was revoked or has expired; save the per-key stats now and then; the backlog."""
        now = time.monotonic()
        self.backlog_periodic()
        if now >= self.next_save:
            self.next_save = now + KAAS_STATS_SAVE_S
            self.save_stats()
        if now < self.next_check or not self.conns:
            return
        self.next_check = now + 1.0
        t = time.time()
        cfg = self.room.cfg
        for c in self.conns:
            if c.closed:
                continue                                    # (closing: kicked, banned or deleted a moment ago)
            if c.web:
                if not cfg.web_login:
                    c.close(4004, "web logins were turned off")
                elif self.web_banned(c.web):
                    c.close(4003, "this key is banned from this server")
                else:
                    self.web_seen(c.web)
                    with self.slock:                        # connected: they get everything as it comes
                        if c.web in self.wusers and not getattr(c, "replaying", False):
                            self.wusers[c.web]["seq"] = self.bk_seq
                    send = self.web_can_send(c.web)
                    if send != c.can_send:                  # heard on the air at last, or allowed / unallowed by the admin
                        c.can_send = send
                        c.send_json({"type": "access", "send": send, "state": "allowed" if send else "pending"})
                continue
            k = self.key_by_id(c.key_id)
            if k is None:
                c.close(4001, "key revoked")
            elif not self.valid(k, t):
                c.close(4002, "key expired")


# ============================================================================
# Dashboard (own thread; reads only the snapshot the main loop publishes)
# ============================================================================

WEB_UNLOCK_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>MeshCore Web</title>
<style>:root{color-scheme:dark}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#111418;color:#d8dee6;
font:14px/1.45 system-ui,sans-serif;padding:16px}form{background:#1a1f26;border:1px solid #2a313b;border-radius:8px;padding:22px;
width:100%;max-width:360px}h1{font-size:20px;margin:0 0 6px}p{color:#8a94a3;margin:0 0 14px}input{width:100%;box-sizing:border-box;
padding:9px 11px;border:1px solid #2a313b;border-radius:4px;background:#111418;color:inherit;font:inherit}button{width:100%;
margin-top:14px;padding:10px;border:1px solid #5cb3ff;border-radius:4px;background:#5cb3ff;color:#0b1420;font:inherit;font-weight:600;
cursor:pointer}.err{color:#e05a5a;margin:12px 0 0}</style></head><body>
<form method="post" action="unlock"><h1>MeshCore Web</h1><p>This server's MeshCore Web needs a password.</p>
<input type="password" name="password" autocomplete="current-password" placeholder="Password" autofocus required aria-label="Password">
{error}<button type="submit">Open</button></form></body></html>"""


DASHBOARD_HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>meshroom</title>
<meta name="referrer" content="strict-origin-when-cross-origin">
<link rel="stylesheet" href="static/leaflet.css">
<script src="static/leaflet.js"></script>
<style>
:root{--link:#8fd0ff;--bg:#111418;--card:#1a1f26;--line:#2a313b;--fg:#d8dee6;--dim:#8a94a3;--acc:#5cb3ff;--ok:#4caf7a;--warn:#e0a83e;--bad:#e05a5a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.4 system-ui,sans-serif}
header{padding:12px 18px;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:18px;align-items:baseline}
header h1{font-size:18px;margin:0}.dim{color:var(--dim)}main{padding:14px 18px;display:grid;gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;overflow-x:auto}
.card h2{font-size:14px;margin:0 0 8px;color:var(--acc);text-transform:uppercase;letter-spacing:.04em}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:4px 8px;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:top}
th{color:var(--dim);font-weight:500}.tag{padding:1px 6px;border-radius:4px;font-size:12px}
.synced{background:#24382c;color:var(--ok)}.queued,.sent{background:#1f3042;color:var(--acc)}.retry{background:#3a3220;color:var(--warn)}.backoff,.gave_up,.suspended{background:#3d2424;color:var(--bad)}
button{background:#2a313b;color:var(--fg);border:1px solid var(--line);border-radius:4px;padding:2px 10px;cursor:pointer}
.mapwrap{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px}
@media (max-width:900px){.mapwrap{grid-template-columns:1fr}}
#map{height:520px;border-radius:6px}
.rdetail{background:#151a20;border:1px solid var(--line);border-radius:6px;padding:12px 14px;max-height:540px;overflow:auto}
.rdetail .pick{display:flex;align-items:center;justify-content:center;height:100%;min-height:200px}
.rdetail h3{margin:0 0 2px;font-size:16px}.rdetail .sec{margin:12px 0 4px;color:var(--acc);text-transform:uppercase;font-size:11px;letter-spacing:.05em}
.rdetail table td,.rdetail table th{padding:3px 6px;font-size:12px}.kv td:first-child{color:var(--dim);width:110px}.mono{font-family:ui-monospace,monospace;word-break:break-all;white-space:normal}.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}
.volt{font-weight:600}.volt .dim{font-weight:400}
.mqdot{display:inline-block;width:9px;height:9px;border-radius:50%;vertical-align:0}.mqdot.on{background:#4caf7a}.mqdot.off{background:#e05a5a}
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
.mqrow{display:flex;gap:14px;align-items:center;margin:6px 0}.mqrow.sub{margin-left:26px}
.rprow{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;margin:8px 0 6px 26px}
.rprow label{display:flex;gap:6px;align-items:center}
.rprow input,.rprow select{width:auto;flex:none;padding:4px 6px;background:#0d1014;border:1px solid var(--line);border-radius:4px;color:var(--fg)}.sw{cursor:pointer}
.mqrow input[type=checkbox]{transform:scale(1.2);margin-right:6px}.mqrow input[type=text],.mqrow input[type=password],.mqrow input[type=number],.mqrow select{width:auto;min-width:110px;padding:4px 6px;background:#0d1014;border:1px solid var(--line);border-radius:4px;color:var(--fg)}.mqnote{margin-top:10px;padding:8px 10px;border-left:3px solid var(--acc);background:#151a20;color:var(--dim);font-size:12px}
.advrow{display:flex;gap:26px;align-items:center;flex-wrap:wrap}.adv{display:flex;gap:10px;align-items:center}
.hdesc{color:var(--dim);font-weight:400;text-transform:none;letter-spacing:0;font-size:12px;margin-left:8px}.hdesc a{color:var(--acc)}.wbkey{font-family:ui-monospace,monospace}.wbacts{display:flex;flex-wrap:wrap;gap:4px;min-width:150px}.wbacts button{white-space:nowrap}.wbacts .wbwarn{color:var(--bad)}
#wb_motd{font:inherit;max-width:100%;padding:6px 8px;background:#0d1014;border:1px solid var(--line);border-radius:4px;color:var(--fg);resize:vertical}
#wb_motd:focus{outline:none;border-color:var(--acc)}
.airtab td{padding:3px 8px}.airtab input{width:4.5em;padding:4px 6px;background:#0d1014;border:1px solid var(--line);border-radius:4px;color:var(--fg)}.airbar{display:inline-block;width:160px;height:8px;background:var(--line);border-radius:4px;position:relative;vertical-align:middle;overflow:hidden}
.airbar i{position:absolute;left:0;top:0;bottom:0;background:var(--acc)}.airbar b{position:absolute;top:0;bottom:0;width:2px;background:var(--fg);opacity:.6}
.dlg{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:14px 18px;min-width:min(420px,90vw)}
.dlg::backdrop{background:rgb(0 0 0/.5)}.dlg h3{margin:0 0 10px;font-size:15px}.dlgrow{display:flex;gap:8px;align-items:center;margin:6px 0}
.dlgbtns{display:flex;gap:8px;justify-content:flex-end;margin-top:12px}.dlg .wbwarn{color:var(--bad)}
#members tr.mrow{cursor:pointer}#members tr.mrow:hover td{background:#1e252d}#members tr.mrow.exp td{background:#1b2229}
.hexr{font-family:ui-monospace,monospace;white-space:nowrap}.caret{color:var(--dim);font-size:11px;margin-right:4px}
.mbox.wide{width:520px}.ac{position:relative}.aclist{background:#0d1014;border:1px solid var(--line);border-top:none;
 border-radius:0 0 4px 4px;max-height:200px;overflow:auto;display:none}.aclist div{padding:5px 8px;cursor:pointer;font-size:13px}
.aclist div.on,.aclist div:hover{background:#243447}.hint{color:var(--dim);font-size:12px;margin:6px 0}#sgprev{font-size:12px;margin-top:6px;min-height:16px}#members td{vertical-align:middle}
#tip{position:fixed;z-index:2000;display:none;max-width:460px;background:#0d1014;border:1px solid var(--line);border-radius:6px;padding:8px 10px;font-size:12px;pointer-events:none;box-shadow:0 4px 18px #0008}
#tip h4{margin:0 0 4px;font-size:13px;color:var(--acc)}#tip .sec{margin-top:6px;color:var(--dim);text-transform:uppercase;font-size:10px;letter-spacing:.05em}
#rpts tr[data-i]{cursor:pointer}#rpts tr[data-i]:hover td{background:#222a33}#rpts tr.sel td{background:#243447}.good{color:var(--ok)}.reldot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px;vertical-align:middle;background:currentColor}.bestwrap{display:flex;gap:14px;flex-wrap:wrap;align-items:flex-start}#bestmapbox{flex:0 1 420px;min-width:260px}#bestmap{height:320px;border-radius:6px;background:#0d1014}.besttab{flex:1 1 360px;min-width:0;overflow-x:auto}.mid{color:var(--warn)}.poor{color:var(--bad)}.small{font-size:12px}.kpis{display:flex;flex-wrap:wrap;gap:22px}.kpi b{font-size:18px;display:block}
.traffic-chart{height:88px;display:flex;align-items:flex-end;gap:1px;border-bottom:1px solid var(--line);padding:0 1px;margin:8px 0 4px}.traffic-chart i{display:block;flex:1;min-width:2px;background:var(--acc);border-radius:2px 2px 0 0}.traffic-chart i.zero{height:1px!important;background:var(--line)}.traffic-label{display:flex;justify-content:space-between}
.host #memberscard,.host #suspendedcard,.host #banscard,.host #chatcard{display:none!important}#tnlist a{color:var(--acc)}.tenant #rmqtt,.tenant #rrpt,.tenant #rvc,.tenant #rsys,.tenant #rweb{display:none}#vcopts.locked{opacity:.5}#vcopts.locked *{cursor:not-allowed}#kpicard{order:0}#bestcard{order:1}#aircard{order:2}#roomcard{order:3}#chatcard{order:4}#memberscard{order:5}#suspendedcard{order:6}#banscard{order:7}#tncard{order:8}#rpcard{order:9}#vccard{order:10}#kaascard{order:11}#webcard{order:12}#welcomecard{order:13}#mqcard{order:14}#observercard{order:15}#trafficcard{order:16}#mapcard{order:17}#repeaterscard{order:18}
.card input:not([type=checkbox]):not([type=radio]):not([type=button]):not([type=submit]),.card select,.card textarea{padding:4px 6px;background:#0d1014;border:1px solid var(--line);border-radius:4px;color:var(--fg);font:inherit}.card input:focus,.card select:focus,.card textarea:focus{outline:none;border-color:var(--acc)}.advbtns{display:inline-flex;gap:6px;align-items:center;margin-left:10px}.advbtns .act:disabled{opacity:.35;cursor:not-allowed}
</style></head><body>
<header><h1 id="rname">meshroom</h1><span class="dim" id="rinfo"></span><span class="dim" id="rclock"></span><span id="rmqtt" class="volt"></span><span id="rrpt" class="volt"></span><span id="rvc" class="volt"></span><span id="rweb" class="volt"></span><span id="rsys" class="volt"></span><span id="rvolt" class="volt"></span>
<span style="margin-left:auto"><span id="who" class="dim small"></span> <button id="loginbtn" onclick="loginClick()">Log in</button></span>
<div id="hstats" class="hstats"></div></header>
<div id="suggestbox" class="modal"><div class="mbox wide"><h3 id="sgtitle">Suggest a route</h3>
<div class="hint">Repeaters in order from the room outward: the first is one the room hears directly, the last is nearest the member.
Separate with commas. Type a name or id for suggestions.</div>
<div class="ac"><input id="sgpath" placeholder="e.g. Seaside (E3C5), Williams Hill (4322)" autocomplete="off"><div id="aclist" class="aclist"></div></div>
<div id="sgprev" class="dim"></div><div id="sgerr" class="poor small"></div>
<div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end"><button onclick="closeSuggest()">Cancel</button><button onclick="doSuggest()">Add route</button></div></div></div>
<div id="kkbox" class="modal"><div class="mbox wide"><h3>API key</h3>
<div class="hint">Copy it now: it is shown only this once. The server keeps only a hash of it.</div>
<input id="kk_token" readonly class="mono" onclick="this.select()"><div id="kkcopied" class="good small"></div>
<div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end"><button onclick="kkCopy()">Copy</button><button onclick="kkDone()">Done</button></div></div></div>
<div id="loginbox" class="modal"><div class="mbox"><h3>Admin log in</h3><input id="pw" type="password" placeholder="Password" onkeydown="if(event.key==='Enter')doLogin()">
<div id="loginerr" class="poor small"></div><div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end"><button onclick="closeLogin()">Cancel</button><button onclick="doLogin()">Log in</button></div></div></div>
<main>
<div class="card" id="kpicard"><div class="kpis" id="kpis"></div></div>
<div class="card" id="aircard" style="display:none"><h2>Airtime <span class="hdesc">Max transmit duty cycle</span></h2>
<div class="rprow"><label>Max duty cycle <input id="air_duty" type="number" min="1" max="100" step="1" style="width:4.5em" oninput="airSum()">% of the time</label>
<span class="dim small">everything this radio sends together, over about a minute (ACKs and replies may go briefly over)</span></div>
<table id="airtab" class="airtab"></table>
<div class="rprow"><button onclick="airSave()">Save</button><span id="airmsg" class="small"></span></div>
<div class="hint" style="margin-left:26px">Weights are any numbers: each class is guaranteed its weight's part of the max duty cycle
(weight &divide; total), and may borrow what others leave unused, up to the max. The virtual repeater and companion don't count while they're off.
Packets over their share wait their turn; relays waiting over 20 s, and web, companion or API packets over 2 minutes, are dropped.</div></div>
<div class="card" id="mqcard" style="display:none"><h2>MQTT augmentation <span class="hdesc">listen to the observer network as well as the radio</span></h2>
<div class="mqrow"><label class="sw"><input type="checkbox" id="mq_en" onchange="mqSet({enabled:this.checked})"> <b>MQTT augmentation</b></label>
<span id="mqstat" class="dim small"></span></div>
<div class="mqrow sub"><label class="sw" title="Trusts the feed: anyone who can publish to it could mark a post delivered that never arrived, so the member misses it. Off by default"><input type="checkbox" id="mq_ack" onchange="mqSet({ack_ingest:this.checked})"> ACK ingestion <span class="dim">&mdash; determine delivery via observers (trusts the feed)</span></label></div>
<div class="mqrow sub"><label class="sw"><input type="checkbox" id="mq_msg" onchange="mqSet({msg_ingest:this.checked})"> Message ingestion <span class="dim">&mdash; capture room posts via observers</span></label></div>
<div class="mqrow sub"><label class="sw"><input type="checkbox" id="mq_topo" onchange="mqSet({topo_ingest:this.checked})"> Topology ingestion <span class="dim">&mdash; collect route, SNR, and path reliability data for known infrastructure</span></label></div>
<div class="mqrow sub"><label class="sw"><input type="checkbox" id="mq_adv" onchange="mqSet({advert_ingest:this.checked})"> Advert ingestion <span class="dim">&mdash; discover users and their locations</span></label></div>
<div class="mqrow sub"><label class="sw"><input type="checkbox" id="mq_act" onchange="mqSet({activity:this.checked})"> Activity monitor <span class="dim">&mdash; packets from an inactive member resume sync (at most every 15 min)</span><span id="mqch" class="dim small"></span></label></div>
<div class="mqrow sub"><label>Subscriber username <input id="mq_user" type="text" autocomplete="username" placeholder="GoMesh username"></label><label>Subscriber password <input id="mq_pass" type="password" autocomplete="current-password" placeholder="GoMesh password"></label><button onclick="mqCredentials()">Save subscriber credentials</button><span id="mqcred" class="dim small"></span></div>
<div class="mqrow sub"><label>Broker host <input id="mq_host" type="text" autocomplete="off" placeholder="mqtt.example.org"></label><label>Port <input id="mq_port" type="number" min="1" max="65535"></label><label>Transport <select id="mq_transport"><option value="websockets">WebSockets</option><option value="tcp">TCP</option></select></label><label>WebSocket path <input id="mq_path" type="text" autocomplete="off" placeholder="/mqtt"></label></div>
<div class="mqrow sub"><label title="Observers publish under their region's code (an airport code, as your own observer's IATA). Only these regions' reports are taken in; empty takes the whole world">Regions <input id="mq_regions" type="text" size="26" autocomplete="off" placeholder="all, or e.g. SJC, SFO, MRY"></label><button onclick="mqRegions(this)">Save regions</button><span id="mqreg" class="dim small"></span></div>
<div class="mqrow sub"><label class="sw"><input id="mq_tls" type="checkbox"> TLS</label><label class="sw"><input id="mq_verify" type="checkbox"> Verify TLS certificate</label><label>Topic filter(s) <input id="mq_topics" type="text" autocomplete="off" placeholder="meshcore/REGION/+/packets"></label><button onclick="mqConnection()">Save broker and topics</button><span id="mqconn" class="dim small"></span></div>
<div class="mqnote">RF will always be used for fallback and route calculations: what the observers report never changes routes,
delivery scores or the push pace, and if the broker is unreachable the room carries on exactly as before.</div></div>
<div class="card" id="rpcard" style="display:none"><h2>Virtual repeater <span class="hdesc">a second identity on the room's radio that relays for the mesh</span></h2>
<div class="mqrow sub"><label>Import private key <input id="rp_key" type="password" autocomplete="new-password" placeholder="64 or 128 hex characters"></label><button onclick="rpImportKey()">Import key</button><span id="rpkeymsg" class="dim small"></span></div>
<div class="mqrow"><label class="sw"><input type="checkbox" id="rp_en" onchange="rpSet({enabled:this.checked})"> <b>Virtual repeater</b></label><span class="advbtns"><button class="act" title="Advert: zero-hop, heard by direct neighbours" onclick="sendAdvert(false,this,'repeater')"><img src="icons/advert.png" alt="advert"></button><button class="act" title="Flood advert: spreads across the whole mesh" onclick="sendAdvert(true,this,'repeater')"><img src="icons/flood_advert.png" alt="flood advert"></button><span class="dim small advmsg"></span></span>
<span id="rpstat" class="dim small"></span></div>
<div class="mqrow sub"><label class="sw"><input type="checkbox" id="rp_relay" onchange="rpSet({relay:this.checked})"> Relay packets <span class="dim">&mdash; turning this off stops relaying at once (queued relays are dropped); it keeps advertising</span></label></div>
<div class="rprow"><label>Name <input id="rp_name" maxlength="31" size="16"></label>
<label>Scoped floods <select id="rp_mode"><option value="allow">relay only these regions</option><option value="deny">relay all except these regions</option></select></label>
<label><input id="rp_regions" size="24" placeholder="e.g. us-ca, #monterey"></label>
<span class="dim small">unscoped floods are always relayed</span></div>
<div class="rprow"><label>Position <input id="rp_lat" size="10" placeholder="room's"> , <input id="rp_lon" size="11" placeholder="room's"></label>
<span class="dim small">lat, lon in degrees; blank = the room's (set it a little apart so map icons don't overlap)</span></div>
<div class="rprow"><label title="its weight on the Airtime card: its guaranteed part of the max duty cycle; it may borrow more when the channel is quiet">Airtime weight <input id="rp_air" type="number" min="0" max="10000" step="1" style="width:4.5em"></label>
<label>Loop detection <select id="rp_loop"><option>off</option><option>minimal</option><option>moderate</option><option>strict</option></select></label>
<label>Adverts every <input id="rp_adv" type="number" min="0" max="1440" style="width:5em"> min</label>
<label>flood every <input id="rp_fadv" type="number" min="0" max="168" style="width:4.5em"> h</label>
<button onclick="rpSave()">Save</button><span id="rpmsg" class="small"></span></div>
<div id="rpcounts" class="dim small" style="margin-left:26px"></div>
</div>
<div class="card" id="vccard" style="display:none"><h2>Virtual companion <span class="hdesc">a chat node on the room's radio that MeshCore apps connect to over the network</span></h2>
<div class="mqrow"><label class="sw"><input type="checkbox" id="vc_en" onchange="vcToggle(this)"> <b>Virtual companion</b></label><span class="advbtns"><button class="act" title="Advert: zero-hop, heard by direct neighbours" onclick="sendAdvert(false,this,'companion')"><img src="icons/advert.png" alt="advert"></button><button class="act" title="Flood advert: spreads across the whole mesh" onclick="sendAdvert(true,this,'companion')"><img src="icons/flood_advert.png" alt="flood advert"></button><span class="dim small advmsg"></span></span>
<span id="vcstat" class="dim small"></span><span id="vcmsg" class="small"></span></div>
<div id="vcopts"><div class="hint" id="vclockhint" style="margin-left:26px"></div>
<div class="mqrow sub"><label>Import private key <input id="vc_key" type="password" autocomplete="new-password" placeholder="64 or 128 hex characters"></label><button onclick="vcImportKey()">Import key</button><span id="vckeymsg" class="dim small"></span></div>
<div class="hint" style="margin:-2px 0 6px 26px">Optional. If no private key is imported, one is generated randomly the first time the companion is turned on and kept in the config, so its identity stays the same across restarts.</div>
<div class="rprow"><label>Name <input id="vc_name" maxlength="31" size="16"></label>
<label>TCP port <input id="vc_port" type="number" min="1" max="65535" style="width:6em"></label>
<label>Allowed addresses <input id="vc_allow" size="26" placeholder="anyone who can reach the port"></label></div>
<div class="rprow"><label class="sw"><input type="checkbox" id="vc_auto"> Auto advert</label>
<label>every <input id="vc_int" type="number" min="1" max="10080" style="width:5em"> min</label>
<label>as <select id="vc_flood"><option value="0">zero-hop</option><option value="1">flood</option></select></label></div></div>
<div id="vccounts" class="dim small" style="margin-left:26px"></div>
<div class="mqnote">Connect a MeshCore app to this server's address and port as a WiFi/TCP companion. The port is open only while
the companion is enabled. The companion protocol has no password: anyone who can reach the port can read its messages and send
as it, so keep it on your own network (never forward it from the internet) and list allowed addresses (e.g. 192.168.1.0/24) to
narrow it further. Radio settings, the Bluetooth PIN, reboot and factory reset from the app are acknowledged and ignored.
Messages between the companion and this room or its repeater never go on the air.</div></div>
<div class="card" id="tncard" style="display:none"><h2>Rooms <span class="hdesc">the rooms on this radio, each with its own page, members and passwords</span></h2>
<div class="rprow"><label>Room name <input id="tn_name" maxlength="31" size="16"></label>
<label>Path <span class="dim" id="tn_base"></span><input id="tn_path" maxlength="32" size="12" placeholder="e.g. hiking" autocomplete="off"></label>
<label>Private key <input id="tn_key" type="password" autocomplete="new-password" size="22" placeholder="blank = random"></label></div>
<div class="rprow"><label>Join password <input id="tn_join" type="password" autocomplete="new-password" maxlength="15" size="12" placeholder="blank = open room"></label>
<label>Admin password <input id="tn_admin" type="password" autocomplete="new-password" maxlength="15" size="12" placeholder="blank = no RF admin"></label>
<label>Web UI password <input id="tn_web" type="password" autocomplete="new-password" size="12" placeholder="6+ characters"></label></div>
<div class="rprow"><label>Latitude <input id="tn_lat" size="10" placeholder="blank = none" autocomplete="off"></label>
<label>Longitude <input id="tn_lon" size="10" placeholder="blank = none" autocomplete="off"></label>
<button onclick="tnCreate(this)">Create</button><span id="tnmsg" class="small"></span></div>
<div class="hint" style="margin-left:26px">If no private key is entered, one is generated randomly. Each room gets its own page at its path, where its
admins (web UI password) see its members and the map, chat, advert, resync, suggest routes, kick and ban. The join and admin passwords are what
people use from their MeshCore apps. The location is what the room's adverts put on maps; the room's admins can change it on its page, as can you from its Actions.
Rooms share this radio, its map and its airtime; nothing a room's admin does reaches outside their room.</div>
<table id="tnlist" style="margin-top:8px"></table></div>
<div class="card" id="kaascard" style="display:none"><h2>KaaS <span class="hdesc">KISS radio as an API service - useful for bots or other integrations</span></h2>
<div class="rprow"><label><input id="kk_receive" type="checkbox" checked> Receive</label><label><input id="kk_send" type="checkbox"> Send</label>
<label>Description <input id="kk_desc" maxlength="80" size="22" placeholder="e.g. weather bot"></label>
<label>Expires <input id="kk_exp" type="date"></label><span class="dim small">(optional)</span>
<button onclick="kkCreate(this)">Save</button><span id="kkmsg" class="small"></span></div>
<div class="hint" style="margin-left:26px">Clients connect a websocket to <code id="kk_url"></code> with the header <code>Authorization: Bearer &lt;key&gt;</code>.
Receive streams every packet this radio hears and sends. Send may send raw packets: <span id="kk_burst">3</span> per <span id="kk_win">20</span> s per key (ACKs and path returns excepted), within the API clients' share
of airtime (<span id="kk_air">10</span>% guaranteed, more when the channel is quiet: see Airtime), after everything of the room's. Clients do their own MeshCore crypto: see docs/api.md and the Python client in client/.
A key is shown once, when it is made: only a hash of it is kept, so a lost key can't be recovered, only revoked and replaced.</div>
<table id="kklist" style="margin-top:8px"></table></div>
<div class="card" id="webcard" style="display:none"><h2>Web users <span class="hdesc">MeshCore Web: people log in by signing with their node's private key, which never leaves their browser &middot; <a href="meshcore-web/" target="_blank" rel="noopener">open MeshCore Web</a></span></h2>
<div class="rprow"><label><input id="wb_on" type="checkbox" onchange="wbSettings({web_login:this.checked})"> Allow web logins</label>
<span class="dim small"><span id="wb_conn">0</span> of <span id="wb_max">32</span> sessions in use</span><span id="wbmsg" class="small"></span></div>
<div class="rprow"><label>Page password <input id="wb_pw" type="password" size="18" maxlength="64" autocomplete="new-password" placeholder="none"></label>
<button onclick="wbPagePw(this,false)">Set</button><button id="wb_pw_rm" onclick="wbPagePw(this,true)">Remove</button>
<span class="dim small" id="wb_pw_state"></span></div>
<div class="rprow"><label title="The names people reach MeshCore Web by, through a proxy or a domain (this server's own ip:port always works). A login signed for any other name is refused: another server can't relay its visitors' logins here">Host names
<input id="wb_hosts" type="text" size="40" maxlength="600" autocomplete="off" placeholder="mesh.example.com, ..."></label><button onclick="wbHosts(this)">Save</button>
<span class="small" id="wb_refused"></span></div>
<div class="rprow"><label title="Shown to a web user whose key may not send yet: not heard advertising on this radio (an MQTT report doesn't count), and not allowed by you">Unknown key message
<input id="wb_unk" type="text" size="60" maxlength="200" autocomplete="off"></label><button onclick="wbUnknown(this)">Save</button></div>
<div class="rprow" style="align-items:flex-start"><label class="sw" title="Shown to web users as a popup when they log in or open the page (each can tick &quot;don't show this again&quot;, until you change the text)"><input id="wb_motd_on" type="checkbox" onchange="wbSettings({motd_enabled:this.checked})"> Message of the day</label>
<textarea id="wb_motd" rows="3" cols="60" maxlength="1000" placeholder="Shown when web users log in"></textarea><button onclick="wbMotd(this)">Save</button></div>
<div class="rprow"><label title="For MeshCore Web's GIF picker: a free key from developers.giphy.com (an API key, not an SDK key). Web users' browsers use it to search Giphy">Giphy API key
<input id="wb_giphy" type="password" size="18" maxlength="64" autocomplete="off" placeholder="none"></label>
<button onclick="wbGiphy(this,false)">Set</button><button id="wb_giphy_rm" onclick="wbGiphy(this,true)">Remove</button>
<span class="dim small" id="wb_giphy_state"></span></div>
<div class="rprow"><label title="Channel messages and DMs, so web users catch up on what they missed while away (0 = keep none)">Backlog: keep
<input id="wb_days" type="number" min="0" step="1" style="width:5em"> days</label><button onclick="wbBacklog(this)">Save</button>
<label title="Also keep what MQTT observers report (each packet is kept once, whether heard here or reported), and show it to web users as it comes"><input id="wb_bk_mqtt" type="checkbox" onchange="wbSettings({web_backlog_mqtt:this.checked})"> Include MQTT packets</label>
<span class="dim small" id="wb_bk_state"></span></div>
<div class="hint" style="margin-left:26px">Anyone can log in and read. A key may send once this radio has heard it advertise (or after you press Allow send):
<span id="wb_burst">3</span> packets per <span id="wb_win">20</span> s each, within the web users' share of airtime, and only as itself. A ban is by public key: a new key starts out unable to send.</div>
<table id="wblist" style="margin-top:8px"></table>
<div class="rprow" style="margin-top:10px"><label>Ban a public key <input id="wb_banpub" class="mono" size="40" maxlength="64" placeholder="64 hex characters"></label>
<button onclick="wbBanKey(this)">Ban</button><span id="wbbanmsg" class="small"></span></div>
<table id="wbbanned" style="margin-top:8px"></table></div>
<dialog id="wbbandlg" class="dlg"><form method="dialog"><h3 id="wbban_title">Ban</h3>
<label class="dlgrow"><input type="checkbox" id="wbban_key"> Public key <span class="wbkey" id="wbban_pub"></span></label>
<label class="dlgrow"><input type="checkbox" id="wbban_ip"> IP address <span class="wbkey" id="wbban_addr"></span></label>
<div class="small" id="wbban_note"></div>
<div class="dlgbtns"><button value="cancel">Cancel</button><button id="wbban_go" value="ban" class="wbwarn">Ban</button></div></form></dialog>
<div class="card" id="roomcard" style="display:none"><h2>Room <span class="hdesc">this room's adverts and location</span></h2>
<div class="advrow"><b>Advert</b><span class="advbtns"><button class="act" title="Advert: zero-hop, heard by direct neighbours" onclick="sendAdvert(false,this)"><img src="icons/advert.png" alt="advert"></button><button class="act" title="Flood advert: spreads across the whole mesh" onclick="sendAdvert(true,this)"><img src="icons/flood_advert.png" alt="flood advert"></button><span class="dim small advmsg"></span></span></div>
<div class="rprow"><label>Latitude <input id="rm_lat" size="10" placeholder="none" autocomplete="off"></label>
<label>Longitude <input id="rm_lon" size="11" placeholder="none" autocomplete="off"></label><button onclick="roomLoc(this)">Save location</button><span id="rmlocmsg" class="small"></span></div>
<div class="hint">What the room's adverts put on maps. Blank both for no position. An advert with the new position goes out within seconds.</div></div>
<div class="card" id="chatcard" style="display:none"><h2>Room chat</h2>
<div id="chatlog" class="chatlog"><div class="dim">loading...</div></div>
<div class="chatin"><input id="chatmsg" maxlength="400" placeholder="Message everyone in the room (sent as the room)" autocomplete="off">
<span id="chatleft" class="dim small"></span><button id="chatsend" onclick="sendChat()">Send</button></div>
<div id="chaterr" class="poor small"></div></div>
<div class="card" id="bestcard"><h2>Best neighbour repeaters <span class="dim small">(by trace reliability)</span></h2>
<div class="bestwrap"><div id="bestmapbox"><div id="bestmap"></div><div id="bestmapnote" class="dim small"></div></div><div class="besttab"><table id="toplinks"></table></div></div></div>
<div class="card" id="memberscard"><h2>Members <span class="hdesc">Room members &middot; tap a row for details</span></h2><table id="members"></table></div>
<div class="card" id="suspendedcard"><h2>Suspended <span class="hdesc">Inactive members, will be returned to member list when they are heard on the mesh</span></h2><table id="suspended"></table></div>
<div class="card" id="banscard"><h2>Banned <span class="hdesc">Room members who FAFO'd</span></h2><table id="bans"></table></div>
<div class="card" id="mapcard"><h2>Repeater map</h2>
<div class="mapwrap"><div><div id="map"></div><div id="mapnote" class="dim small"></div></div>
<div id="rdetail" class="rdetail"><div class="dim pick">Select a repeater from the map</div></div></div></div>
<div class="card" id="observercard" style="display:none"><h2>MQTT observer <span class="hdesc">admin only</span></h2>
<div class="advrow"><label title="The node the observer reports as: its public key and name are what MQTT maps show">Report as <select id="obs_who" onchange="saveObserverWho()"></select></label>
<label><input id="obs_enabled" type="checkbox" onchange="saveObserverToggle()"> Enabled</label><span id="obswho_note" class="small dim"></span><label>IATA <input id="obs_iata" maxlength="3" size="6" placeholder="e.g. SJC" title="Your region: the nearest airport code. Required: everything the observer publishes is filed under it"></label>
<label><input id="obs_status" type="checkbox"> Status</label><label><input id="obs_packets" type="checkbox"> Packets</label><label><input id="obs_rx" type="checkbox"> RX</label>
<label>Queue <input id="obs_queue" type="number" min="10" max="10000" style="width:80px"></label><button onclick="saveObserver()">Save observer settings</button><span id="obsmsg" class="small dim"></span></div>
<div class="rprow"><label>Name <input id="os_name" placeholder="Regional MQTT"></label><label>Host <input id="os_host" placeholder="mqtt.example.org"></label><label>Port <input id="os_port" type="number" value="443"></label><label>Audience <input id="os_aud" placeholder="mqtt.example.org"></label><label>Path <input id="os_path" value="/"></label><label>Prefix <input id="os_prefix" value="meshcore"></label><label><input id="os_enabled" type="checkbox" checked> Enabled</label><label><input id="os_tls" type="checkbox" checked> TLS</label><label><input id="os_verify" type="checkbox" checked> Verify TLS</label><button onclick="addObserverServer()">Add server</button></div>
<table id="observerservers" style="margin-top:8px"></table>
<table id="observerstatus" style="margin-top:10px"></table></div>
<div class="card" id="trafficcard" style="display:none"><div id="observertraffic"></div></div>
<div class="card" id="welcomecard" style="display:none"><h2>Welcome DMs <span class="hdesc">admin only &middot; sent only to newly logged-in members</span></h2>
<div class="advrow"><label><input id="welcome_enabled" type="checkbox"> Send welcome DM</label><button onclick="saveWelcome()">Save welcome settings</button><span id="welcomemsg" class="small dim"></span></div>
<div style="margin-top:10px"><label>Welcome message<br><textarea id="welcome_message" rows="2" maxlength="151" style="width:min(680px,100%);box-sizing:border-box"></textarea></label></div>
<div style="margin-top:8px"><label>Name-unknown hint <span class="dim small">(optional; appended when the member has not sent an advert)</span><br><textarea id="welcome_hint" rows="2" maxlength="151" style="width:min(680px,100%);box-sizing:border-box"></textarea></label></div>
<div class="hint">Use <code>{room}</code> for the room name. The rendered welcome message and optional hint together may be at most 151 UTF-8 bytes.</div></div>
<div class="card" id="repeaterscard"><h2>Repeaters heard</h2><table id="rpts"></table></div>
</main>
<script>
const TENANT=!!window.TENANT;document.body.classList.add(TENANT?"tenant":"host");
const $=id=>document.getElementById(id), esc=s=>String(s??"").replace(/[&<>"'`]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;","`":"&#96;"}[c]));
function ago(t){if(!t)return"never";let d=Math.max(0,Date.now()/1000-t);return d<60?Math.round(d)+"s":d<3600?Math.round(d/60)+"m":d<86400?(d/3600).toFixed(1)+"h":(d/86400).toFixed(1)+"d"}
async function act(url,label){if(!confirm(label))return;const r=await fetch(url,{method:"POST"});if(r.status===401){await session();alert("Your admin session has expired: log in again.")}setTimeout(load,300)}
async function resync(m,btn){btn.disabled=true;await fetch("api/members/"+m.pub+"/resync",{method:"POST"});
 btn.title=m.outstanding?"Resync started":"Nothing outstanding for this member";setTimeout(load,300)}
function score(m){if(m.delivery==null)return'<span class="dim">new</span>';const c=m.delivery>=80?"good":m.delivery>=50?"mid":"poor";
 return `<span class="${c}">${m.delivery}%</span> <span class="dim small">${m.avg_attempts} tries &middot; ${m.deliveries}</span>`}
function route(r){return r==null?'<span class="dim">unknown (flood)</span>':r.length?r.map(esc).join(" &rsaquo; "):'direct'}
let EXP=new Set(),map=null,layer=null,RPTS=[],MEMBERS=[],LAST=null,ADMIN=false,LOGIN_ON=false;
let CHAT_TS=0,CHAT_MAX=151,CHAT_BUSY=false,WELCOME_LOADED=false;let VCA={},MAINADM=false,TN_ROWS=[];
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
async function rpSet(o){const r=await fetch("api/repeater",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(o)});
 let m="";if(!r.ok){m="Could not save";try{m=(await r.json()).error||m}catch(e){}}
 if(r.status===401){m="Your admin session has expired: log in again.";session()}
 $("rpmsg").className=r.ok?"good small":"poor small";$("rpmsg").textContent=r.ok?"saved":m;delete SIG.rpform;setTimeout(load,400);return r.ok}
async function rpImportKey(){const k=$("rp_key").value.trim();if(!k)return;const ok=await rpSet({private_key:k});$("rp_key").value="";$("rpkeymsg").textContent=ok?"key imported; repeater remains disabled":"key was not imported"}
const AIR_CLASSES=[["control","Control","ACKs, replies, and path returns"],["relay","Relays","virtual repeater transmit (when enabled)"],
 ["room","Room","message delivery to members (all rooms)"],["web","Web users","users connected to web client"],
 ["companion","Virtual companion","packets sent by virtual companion (when enabled)"],["kaas","KaaS","API clients"],["background","Background","adverts and traces"]];
function renderAir(A){if(!A||!A.weight)return;const off=AIR_OFF=new Set(A.off||[]);const f=document.activeElement,typing=f&&f.closest&&f.closest("#aircard")&&f.type==="number";
 const scale=Math.max(A.ceiling_pct,A.total_pct,1),bar=(u,g)=>`<span class="airbar"><i style="width:${Math.min(100,100*u/scale)}%"></i><b style="left:${Math.min(100,100*g/scale)}%"></b></span>`;
 if(!typing&&changed("airform",[A.ceiling_pct,JSON.stringify(A.weight),A.off])){$("air_duty").value=A.ceiling_pct;
  $("airtab").innerHTML="<tr><th>Class</th><th>Weight</th><th>Guaranteed</th><th>Used (last "+Math.round(A.window_s/60)+" min)</th><th></th></tr>"+AIR_CLASSES.map(([k,n,t])=>
   `<tr${off.has(k)?' class="dim"':""}><td title="${t}">${n} <span class="dim small">${t}</span></td><td><input type="number" min="0" max="10000" step="1" id="air_${k}" oninput="airSum()"></td>`+
   `<td id="airg_${k}" class="small"></td><td id="airu_${k}"></td><td id="aird_${k}" class="small"></td></tr>`).join("")+
   `<tr><td><b>Total</b></td><td id="air_sum"></td><td class="small">${A.ceiling_pct}%</td><td id="airu_total"></td><td></td></tr>`;
  for(const [k] of AIR_CLASSES)$("air_"+k).value=A.weight[k];airSum()}
 for(const [k] of AIR_CLASSES){$("airu_"+k).innerHTML=off.has(k)?"":bar(A.used_pct[k],A.share_pct[k])+` ${A.used_pct[k]}%`;const d=A.dropped[k];$("aird_"+k).innerHTML=d?`<span class="poor">${d} dropped</span>`:""}
 $("airu_total").innerHTML=bar(A.total_pct,A.ceiling_pct)+` ${A.total_pct}% <span class="dim small">of ${A.ceiling_pct}%</span>`}
let AIR_OFF=new Set();
function airSum(){const w=k=>Math.max(0,+$("air_"+k).value||0),tot=AIR_CLASSES.reduce((a,[k])=>a+(AIR_OFF.has(k)?0:w(k)),0),max=+$("air_duty").value||0;
 $("air_sum").textContent=Math.round(tot*100)/100;
 for(const [k] of AIR_CLASSES)$("airg_"+k).innerHTML=AIR_OFF.has(k)?'<span class="dim">off: not counted</span>':tot?Math.round(max*w(k)/tot*10)/10+"%":"0%"}
async function airSave(){const wt={};for(const [k] of AIR_CLASSES)wt[k]=+$("air_"+k).value;
 const r=await fetch("api/airtime",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({duty_pct:+$("air_duty").value,weight:wt})});
 let m="Saved";if(!r.ok){m="Could not save";try{m=(await r.json()).error||m}catch(e){}}$("airmsg").className=r.ok?"dim small":"poor small";$("airmsg").textContent=" "+m;setTimeout(load,500)}
function rpSave(){rpSet({name:$("rp_name").value,lat:$("rp_lat").value.trim(),lon:$("rp_lon").value.trim(),scope_mode:$("rp_mode").value,regions:$("rp_regions").value,
 airtime_cap:+$("rp_air").value,loop_detect:$("rp_loop").value,advert_min:+$("rp_adv").value,flood_advert_h:+$("rp_fadv").value})}
async function vcSet(o){const r=await fetch("api/companion",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(o)});
 let m="";if(!r.ok){m="Could not save";try{m=(await r.json()).error||m}catch(e){}}
 if(r.status===401){m="Your admin session has expired: log in again.";session()}
 $("vcmsg").className=r.ok?"good small":"poor small";$("vcmsg").textContent=r.ok?"":" "+m;delete SIG.vcform;setTimeout(load,400);return r.ok}
async function vcImportKey(){const k=$("vc_key").value.trim();if(!k)return;const ok=await vcSet({private_key:k});$("vc_key").value="";$("vckeymsg").textContent=ok?"key imported; companion remains disabled":"key was not imported"}
const VC_WARNING="The virtual companion is meant for use on a trusted local network only. Its port has no login: anyone "+
 "who can reach it can read and delete its messages, read its channel secrets, see its contacts, send as it and "+
 "have it sign data with its key.\n\nNever expose the port to the internet. Limit it to the devices you use with "+
 "\"Allowed addresses\" (or bind it to 127.0.0.1).\n\nTurn the virtual companion on?";
async function vcToggle(cb){   // turning it on saves the options with it; they stay locked until it's turned off again
 if(cb.checked&&!confirm(VC_WARNING)){cb.checked=false;return}
 const o=cb.checked?{enabled:true,name:$("vc_name").value,port:+$("vc_port").value,allow:$("vc_allow").value,auto_advert:$("vc_auto").checked,
  advert_min:+$("vc_int").value,advert_flood:$("vc_flood").value==="1"}:{enabled:false};
 cb.disabled=true;const ok=await vcSet(o);cb.disabled=false;if(!ok)cb.checked=!cb.checked}
async function loadTenants(){if(!MAINADM)return;try{const r=await fetch("api/tenants");if(!r.ok)return;const d=await r.json();TN_ROWS=d.rooms||[]}catch(e){return}
 $("tn_base").textContent=location.host+"/";
 const t=$("tnlist");if(!TN_ROWS.length){t.innerHTML='<tr><td class="dim">No rooms yet: create one above.</td></tr>';return}
 if(t.querySelector("select:focus"))return;
 t.innerHTML="<tr><th>Room</th><th>Page</th><th>ID</th><th>Location</th><th>Members</th><th>Suspended</th><th>Posts</th><th></th></tr>"+TN_ROWS.map(x=>
  `<tr><td>${esc(x.name)}</td><td><a href="${encodeURI(x.path)}/" target="_blank">/${esc(x.path)}/</a></td><td class="mono4" title="${esc(x.key)}">${esc(x.id)}</td>`+
  `<td>${x.lat||x.lon?x.lat.toFixed(5)+", "+x.lon.toFixed(5):'<span class="dim">none</span>'}</td>`+
  `<td>${x.members}</td><td>${x.suspended}</td><td>${x.posts}</td><td><select data-key="${esc(x.key)}" data-name="${esc(x.name)}" data-loc="${x.lat||x.lon?x.lat+", "+x.lon:""}" onchange="tnAction(this)">`+
  `<option value="">Actions&hellip;</option><option value="loc">Set location</option><option value="pw">Reset web UI password</option><option value="del">Delete room</option></select></td></tr>`).join("")}
let KK_ROWS=[];
async function loadKaas(){if(!MAINADM)return;let d;try{const r=await fetch("api/v1/kaas/keys");if(!r.ok)return;d=await r.json()}catch(e){return}
 KK_ROWS=d.keys||[];$("kk_url").textContent=(location.protocol==="https:"?"wss://":"ws://")+location.host+d.path;$("kk_burst").textContent=d.send_burst;$("kk_win").textContent=d.send_window_s;$("kk_air").textContent=d.airtime_pct;
 const t=$("kklist");if(!KK_ROWS.length){t.innerHTML='<tr><td class="dim">No API keys yet.</td></tr>';return}
 const day=x=>x?new Date(x*1000).toLocaleDateString():"never";
 t.innerHTML="<tr><th>Description</th><th>Access</th><th>Expires</th><th>Last used</th><th>Connected</th>"+
  '<th title="packets streamed to this key: last 24 h / total">Received <span class=\"dim small\">24h / total</span></th><th title="packets this key sent: last 24 h / total">Sent <span class=\"dim small\">24h / total</span></th>'+
  '<th title="refused sends and other errors: last 24 h / total">Errors <span class=\"dim small\">24h / total</span></th><th></th></tr>'+KK_ROWS.map(k=>
  `<tr><td>${esc(k.description)||'<span class="dim">(no description)</span>'}</td><td>${[k.receive?"Receive":"",k.send?"Send":""].filter(Boolean).join(" + ")}</td>`+
  `<td class="${k.expired?"poor":""}">${k.expired?"expired "+day(k.expires):day(k.expires)}</td><td>${k.last_used?ago(k.last_used)+" ago":"never"}</td>`+
  `<td>${k.connected?'<span class="mqdot on"></span> '+k.connected:'<span class="dim">no</span>'}</td>`+
  ["rx","tx","err"].map(f=>{const v=(k.stats||{})[f]||[0,0];return `<td class="${f==="err"&&v[0]?"poor":""}">${v[0].toLocaleString()} <span class="dim">/ ${v[1].toLocaleString()}</span></td>`}).join("")+
  `<td><button data-id="${esc(k.id)}" data-name="${esc(k.description||"(no description)")}" onclick="kkRevoke(this)">Revoke</button></td></tr>`).join("")}
async function kkCreate(btn){const v=$("kk_exp").value;const o={receive:$("kk_receive").checked,send:$("kk_send").checked,description:$("kk_desc").value.trim(),
 expires:v?Math.floor(new Date(v+"T23:59:59").getTime()/1000):null};
 btn.disabled=true;const r=await fetch("api/v1/kaas/keys",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(o)});btn.disabled=false;
 let d={};try{d=await r.json()}catch(e){}
 if(!r.ok){let m=d.error||"Could not save";if(r.status===401){m="Your admin session has expired: log in again.";session()}$("kkmsg").className="poor small";$("kkmsg").textContent=" "+m;return}
 $("kkmsg").textContent="";$("kk_desc").value="";$("kk_exp").value="";$("kk_token").value=d.token;$("kkcopied").textContent="";$("kkbox").style.display="flex";setTimeout(loadKaas,700)}
async function kkCopy(){const i=$("kk_token");i.select();try{await navigator.clipboard.writeText(i.value)}catch(e){document.execCommand("copy")}$("kkcopied").textContent="Copied."}
function kkDone(){$("kk_token").value="";$("kkbox").style.display="none"}
async function kkRevoke(b){if(!confirm("Revoke the API key "+b.dataset.name+"? Clients using it are disconnected now and can't connect again."))return;
 const m=await tnPost("api/v1/kaas/keys/"+b.dataset.id+"/revoke",{});if(m)alert(m);setTimeout(loadKaas,500)}
let WB={users:[],banned:[]};
async function loadWeb(){if(!MAINADM)return;let d;try{const r=await fetch("api/v1/web/users");if(!r.ok)return;d=await r.json()}catch(e){return}
 WB=d;$("wb_on").checked=d.enabled;$("wb_pw_state").textContent=d.page_password?"set: the page and its logins ask for it":"none: anyone who can reach this server can open the page";$("wb_pw_rm").disabled=!d.page_password;
 $("wb_giphy_state").textContent=d.giphy_key?"set: web users get a GIF picker":"none: no GIF picker (Giphy links still show)";$("wb_giphy_rm").disabled=!d.giphy_key;
 {const b=d.backlog||{};if(document.activeElement!==$("wb_days"))$("wb_days").value=b.days;$("wb_bk_mqtt").checked=!!b.mqtt;
  $("wb_bk_state").textContent=b.days?(b.count||0).toLocaleString()+" packets kept"+(b.oldest?", the oldest from "+ago(b.oldest)+" ago":""):"off: web users don't catch up";}if(document.activeElement!==$("wb_unk"))$("wb_unk").value=d.unknown_key_message||"";
 $("wb_motd_on").checked=!!d.motd_enabled;if(document.activeElement!==$("wb_motd"))$("wb_motd").value=d.motd||"";
 WBH=d.hosts||[];if(document.activeElement!==$("wb_hosts"))$("wb_hosts").value=WBH.join(", ");
 $("wb_refused").innerHTML=(d.refused_hosts||[]).length?'<span class="mid">Refused:</span> '+d.refused_hosts.map(r=>
  `<span class="mono">${esc(r.host)}</span> <span class="dim">(${r.count}, ${ago(r.last)} ago)</span> <button data-h="${esc(r.host)}" onclick="wbHosts(this,this.dataset.h)">Allow</button>`).join(" "):"";$("wb_conn").textContent=d.connected;$("wb_max").textContent=d.max;
 $("wb_burst").textContent=$("kk_burst").textContent;$("wb_win").textContent=$("kk_win").textContent;
 const t=$("wblist");if(!d.users.length){t.innerHTML='<tr><td class="dim">'+(d.enabled?"Nobody has logged in yet.":"Web logins are off.")+'</td></tr>'}else{
 const key=p=>`<span class="wbkey" title="${esc(p)}">${esc(p.slice(0,8))}&hellip;</span>`;
 const addr=u=>u.ip?`<br><span class="dim small${u.ip_banned?" poor":""}" title="last logged in from${u.ip_shared?" (and "+u.ip_shared+" other user"+(u.ip_shared>1?"s":"")+")":""}">${esc(u.ip)}${u.ip_banned?" banned":u.ip_shared?" +"+u.ip_shared:""}</span>`:"";
 const access=u=>u.banned?'<span class="poor">banned</span>':u.send?('<span class="good">can send</span> <span class="dim small">'+(u.heard_rf?"heard "+ago(u.heard_rf)+" ago":u.approved?"allowed":"heard by an observer")+'</span>'):'<span class="mid">pending</span> <span class="dim small">not heard on the air</span>';
 t.innerHTML="<tr><th>Name</th><th>Public key</th><th>Access</th><th>Last active</th><th>Connected</th>"+
  '<th title="packets streamed to this user: last 24 h / total">Received <span class="dim small">24h / total</span></th><th title="packets this user sent: last 24 h / total">Sent <span class="dim small">24h / total</span></th>'+
  '<th title="refused sends and other errors: last 24 h / total">Errors <span class="dim small">24h / total</span></th>'+
  '<th title="backlog packets kept since they were last connected: they catch up on these when they come back">Missed</th><th></th></tr>'+d.users.map(u=>
  `<tr><td>${esc(u.name)||'<span class="dim">(no name)</span>'}${u.advert_name&&u.advert_name!==u.name?' <span class="dim small">adverts as '+esc(u.advert_name)+'</span>':''}</td><td>${key(u.pub)}${addr(u)}</td>`+
  `<td>${access(u)}</td><td>${ago(u.last)} ago</td><td>${u.connected?'<span class="mqdot on"></span> '+u.connected:'<span class="dim">no</span>'}</td>`+
  ["rx","tx","err"].map(f=>{const v=(u.stats||{})[f]||[0,0];return `<td class="${f==="err"&&v[0]?"poor":""}">${v[0].toLocaleString()} <span class="dim">/ ${v[1].toLocaleString()}</span></td>`}).join("")+
  `<td>${u.connected?'<span class="dim">-</span>':(u.missed||0).toLocaleString()}</td>`+
  `<td><div class="wbacts">${[[!u.send&&!u.banned,"allow","Allow send","let this key send before the radio hears it"],
   [u.approved&&!u.banned,"unallow","Unallow","take back Allow send: it sends again once the radio hears it"],
   [u.connected,"kick","Kick","disconnect now; they can log in again"],
   [u.missed,"purge","Purge","count them as caught up to now: they won't get what they missed"],
   [!u.banned||(u.ip&&!u.ip_banned),"ban","Ban","disconnect, and refuse this key and/or its address from now on"],
   [true,"delete","Delete","disconnect and forget them (not a ban: they can log in again as a new user)"]].filter(x=>x[0]).map(([,a,l,tip])=>
   `<button data-pub="${esc(u.pub)}" data-name="${esc(u.name)}" data-act="${a}" data-ip="${esc(u.ip||"")}" data-shared="${u.ip_shared||0}" data-banned="${u.banned?1:""}" data-ipbanned="${u.ip_banned?1:""}" title="${tip}"${a==="ban"||a==="delete"?' class="wbwarn"':""} onclick="wbAct(this)">${l}</button>`).join("")}</div></td></tr>`).join("")}
 const bi=d.banned_ips||[],b=$("wbbanned");b.innerHTML=d.banned.length||bi.length?"<tr><th>Banned</th><th>Public key or address</th><th>Since</th><th></th></tr>"+d.banned.map(x=>
  `<tr><td>${esc(x.name)||'<span class="dim">(no name)</span>'}</td><td class="mono">${esc(x.pub)}</td><td>${ago(x.ts)} ago</td>`+
  `<td><button data-pub="${esc(x.pub)}" data-act="unban" onclick="wbAct(this)">Unban</button></td></tr>`).join("")+bi.map(x=>
  `<tr><td>${esc(x.name)||'<span class="dim">(no name)</span>'}</td><td class="mono">${esc(x.ip)} <span class="dim small">address</span></td><td>${ago(x.ts)} ago</td>`+
  `<td><button data-ip="${esc(x.ip)}" onclick="wbIp(this)">Unban</button></td></tr>`).join(""):""}
async function wbBacklog(btn){const n=Number($("wb_days").value);
 if(!Number.isInteger(n)||n<0){$("wbmsg").className="poor small";$("wbmsg").textContent=" Days: a whole number, 0 for none.";return}
 if(n===0&&!confirm("Keep no backlog? What's kept now is deleted, and web users won't catch up on what they missed."))return;
 btn.disabled=true;await wbSettings({web_backlog_days:n});btn.disabled=false}
async function wbPagePw(btn,remove){const pw=remove?"":$("wb_pw").value;
 if(!remove&&(pw.length<4||pw.length>64)){$("wbmsg").className="poor small";$("wbmsg").textContent=" A page password is 4 to 64 characters.";return}
 if(remove&&!confirm("Remove the MeshCore Web page password? Anyone who can reach this server can then open the page."))return;
 btn.disabled=true;await wbSettings({page_password:pw});btn.disabled=false;$("wb_pw").value=""}
let WBH=[];
async function wbHosts(btn,add){const l=add?[...WBH,add]:$("wb_hosts").value.split(/[\s,]+/).filter(Boolean);
 if(l.some(h=>!/^[A-Za-z0-9.\-:\[\]]{1,100}$/.test(h))){$("wbmsg").className="poor small";$("wbmsg").textContent=" Host names look like mesh.example.com or 10.0.0.5:8081.";return}
 btn.disabled=true;await wbSettings({web_hosts:l});btn.disabled=false}
async function wbMotd(btn){btn.disabled=true;await wbSettings({motd:$("wb_motd").value});btn.disabled=false}
async function wbUnknown(btn){const t=$("wb_unk").value.trim();
 if(!t){$("wbmsg").className="poor small";$("wbmsg").textContent=" The unknown key message can't be empty.";return}
 btn.disabled=true;await wbSettings({unknown_key_message:t});btn.disabled=false}
async function wbGiphy(btn,remove){const k=remove?"":$("wb_giphy").value.trim();
 if(!remove&&!/^[A-Za-z0-9]{8,64}$/.test(k)){$("wbmsg").className="poor small";$("wbmsg").textContent=" A Giphy API key is letters and digits.";return}
 btn.disabled=true;await wbSettings({giphy_key:k});btn.disabled=false;$("wb_giphy").value=""}
async function wbSettings(o){const m=await tnPost("api/v1/web/settings",o);$("wbmsg").className="poor small";$("wbmsg").textContent=m?" "+m:"";setTimeout(loadWeb,500)}
function wbBan(btn){const d=btn.dataset,p=d.pub,ip=d.ip,dlg=$("wbbandlg");
 $("wbban_title").textContent="Ban "+(d.name||p.slice(0,8));$("wbban_pub").textContent=p.slice(0,16)+"\u2026";
 $("wbban_key").checked=!d.banned;$("wbban_key").disabled=!!d.banned;
 $("wbban_addr").textContent=ip||"(not known)";$("wbban_ip").checked=false;$("wbban_ip").disabled=!ip||!!d.ipbanned;
 const sh=+d.shared||0;$("wbban_note").className="small"+(sh?" poor":" dim");
 $("wbban_note").textContent=d.banned?"The key is banned already.":sh?"That address was also used by "+sh+" other user"+(sh>1?"s":"")+": banning it shuts them out too. (Behind a proxy that doesn't pass on the visitor's address, everyone shares one.)":
  "A key is free to make, so a key ban alone is easy to get round; an address ban hits everyone behind that address.";
 dlg.onclose=async()=>{if(dlg.returnValue!=="ban")return;const k=$("wbban_key").checked&&!d.banned,i=$("wbban_ip").checked;
  if(!k&&!i)return;btn.disabled=true;const m=await tnPost("api/v1/web/users/"+p+"/ban",{name:d.name||"",key:k,ip:i});if(m)alert(m);setTimeout(loadWeb,500)};
 dlg.returnValue="";dlg.showModal()}
async function wbIp(btn){btn.disabled=true;const m=await tnPost("api/v1/web/ips/"+encodeURIComponent(btn.dataset.ip)+"/unban",{});if(m)alert(m);setTimeout(loadWeb,500)}
async function wbAct(btn){const a=btn.dataset.act,p=btn.dataset.pub;if(!a)return;
 if(a==="ban")return wbBan(btn);
 if(a==="kick"&&!confirm("Disconnect "+p.slice(0,8)+"? They can log in again."))return;
 if(a==="delete"&&!confirm("Delete "+(btn.dataset.name||p.slice(0,8))+"? They are disconnected and forgotten, and lose \"allow send\". It isn't a ban: they can log in again as a new user."))return;
 if(a==="purge"&&!confirm("Purge "+(btn.dataset.name||p.slice(0,8))+"'s backlog? They'll count as caught up to now, and won't get what they missed."))return;
 btn.disabled=true;const m=await tnPost("api/v1/web/users/"+p+"/"+a,{name:btn.dataset.name||""});if(m)alert(m);setTimeout(loadWeb,500)}
async function wbBanKey(btn){const p=$("wb_banpub").value.trim().toLowerCase();if(!/^[0-9a-f]{64}$/.test(p)){$("wbbanmsg").className="poor small";$("wbbanmsg").textContent=" A public key is 64 hex characters.";return}
 btn.disabled=true;const m=await tnPost("api/v1/web/users/"+p+"/ban",{});btn.disabled=false;$("wbbanmsg").className=m?"poor small":"dim small";$("wbbanmsg").textContent=" "+(m||"Banned.");if(!m)$("wb_banpub").value="";setTimeout(loadWeb,500)}
async function tnPost(url,o){const r=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(o)});
 let m="";if(!r.ok){m="Failed";try{m=(await r.json()).error||m}catch(e){}}if(r.status===401){m="Your admin session has expired: log in again.";session()}return m}
async function tnCreate(btn){const o={name:$("tn_name").value.trim(),path:$("tn_path").value.trim(),private_key:$("tn_key").value.trim(),
 room_password:$("tn_join").value,admin_password:$("tn_admin").value,web_password:$("tn_web").value,lat:$("tn_lat").value.trim(),lon:$("tn_lon").value.trim()};
 btn.disabled=true;const m=await tnPost("api/tenants",o);btn.disabled=false;
 $("tnmsg").className=m?"poor small":"good small";$("tnmsg").textContent=m?" "+m:" created: /"+o.path.toLowerCase()+"/";
 if(!m){["tn_name","tn_path","tn_key","tn_join","tn_admin","tn_web","tn_lat","tn_lon"].forEach(id=>$(id).value="");setTimeout(loadTenants,700)}}
async function tnAction(sel){const k=sel.dataset.key,n=sel.dataset.name,a=sel.value;sel.value="";if(!a)return;let m;
 if(a==="loc"){const v=prompt("Location of "+n+" as latitude, longitude (e.g. 37.77490, -122.41940). Leave empty for none.",sel.dataset.loc);if(v===null)return;
  const p=v.split(",").map(x=>x.trim());if(v.trim()&&p.length!==2){alert("Enter latitude, longitude separated by a comma.");return}
  m=await tnPost("api/tenants/"+k+"/location",v.trim()?{lat:p[0],lon:p[1]}:{lat:"",lon:""});alert(m||"Location of "+n+" saved; it advertises it shortly.")}
 else if(a==="pw"){const pw=prompt("New web UI password for "+n+" (6+ characters). Anyone logged in to its page is logged out.");if(pw===null)return;
  m=await tnPost("api/tenants/"+k+"/password",{web_password:pw});alert(m||"Web UI password for "+n+" reset.")}
 else if(a==="del"){if(!confirm("Delete the room "+n+"? Its members, posts, settings and key are erased for good."))return;
  const pw=prompt("Your admin (web) password, to confirm deleting "+n+":");if(pw===null)return;
  m=await tnPost("api/tenants/"+k+"/delete",{password:pw});alert(m||n+" deleted.")}
 setTimeout(loadTenants,700)}
async function mqSet(o){const r=await fetch("api/mqtt",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(o)});
 if(r.status===401){alert("Your admin session has expired: log in again.");session()}setTimeout(load,400)}
async function mqCredentials(){const u=$("mq_user").value.trim(),p=$("mq_pass").value;if(!u||!p){$("mqcred").textContent="username and password are both required";$("mqcred").className="poor small";return}
 const r=await fetch("api/mqtt",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});let m="credentials were not saved";if(r.ok){$("mq_user").value="";$("mq_pass").value="";m="subscriber credentials saved; reconnecting"}else{try{m=(await r.json()).error||m}catch(e){}}if(r.status===401){m="Your admin session has expired: log in again.";session()}$("mqcred").className=r.ok?"good small":"poor small";$("mqcred").textContent=m;setTimeout(load,700)}
// The region codes a set of topic filters stands for ("" = every region), or null when they're something else.
function regionsOf(topics){const l=(topics||[]).map(t=>String(t).trim()).filter(Boolean);if(!l.length||(l.length===1&&l[0]==="meshcore/#"))return "";
 const m=l.map(t=>/^meshcore\/([A-Za-z0-9]+)\/(\+\/packets|#)$/.exec(t));return m.every(Boolean)?m.map(x=>x[1].toUpperCase()).join(", "):null}
async function mqRegions(btn){const codes=[...new Set($("mq_regions").value.toUpperCase().split(/[\s,]+/).filter(Boolean))];
 if(codes.some(c=>!/^[A-Z0-9]{2,8}$/.test(c))||codes.length>16){$("mqreg").className="poor small";$("mqreg").textContent=" Regions are codes like SJC, SFO, MRY (up to 16).";return}
 btn.disabled=true;const r=await fetch("api/mqtt",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({topics:codes.length?codes.map(c=>"meshcore/"+c+"/+/packets"):["meshcore/#"]})});btn.disabled=false;
 let m=r.ok?(codes.length?"saved: only "+codes.join(", ")+"; reconnecting":"saved: every region; reconnecting"):"not saved";if(!r.ok){try{m=(await r.json()).error||m}catch(e){}}
 if(r.status===401){m="Your admin session has expired: log in again.";session()}$("mqreg").className=r.ok?"good small":"poor small";$("mqreg").textContent=m;delete SIG.mqconn;setTimeout(load,700)}
async function mqConnection(){const o={host:$("mq_host").value.trim(),port:+$("mq_port").value,transport:$("mq_transport").value,ws_path:$("mq_path").value.trim(),tls:$("mq_tls").checked,tls_verify:$("mq_verify").checked,topics:$("mq_topics").value};const r=await fetch("api/mqtt",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(o)});let m="broker settings were not saved";if(r.ok)m="broker settings saved; reconnecting";else{try{m=(await r.json()).error||m}catch(e){}}if(r.status===401){m="Your admin session has expired: log in again.";session()}$("mqconn").className=r.ok?"good small":"poor small";$("mqconn").textContent=m;delete SIG.mqconn;setTimeout(load,700)}
async function sendAdvert(flood,btn,node){
 if(flood&&!confirm("Send a flood advert? It is relayed across the whole mesh."))return;
 btn.disabled=true;btn.dataset.busy=1;const r=await fetch("api/advert",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(node?{flood,node}:{flood})});
 let m=r.ok?(flood?"Flood advert sent":"Advert sent (zero-hop)"):"Could not send";try{const d=await r.json();if(!r.ok)m=d.error||m}catch(e){}
 if(r.status===401){m="Your admin session has expired: log in again.";session()}
 btn.parentElement.querySelector(".advmsg").textContent=m+" · "+new Date().toLocaleTimeString();setTimeout(()=>{btn.disabled=false;delete btn.dataset.busy},10000)}
async function roomLoc(btn){btn.disabled=true;const r=await fetch("api/location",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({lat:$("rm_lat").value.trim(),lon:$("rm_lon").value.trim()})});btn.disabled=false;
 let m=r.ok?"saved":"Could not save";try{if(!r.ok)m=(await r.json()).error||m}catch(e){}if(r.status===401){m="Your admin session has expired: log in again.";session()}
 $("rmlocmsg").className=r.ok?"good small":"poor small";$("rmlocmsg").textContent=" "+m;delete SIG.rmloc;setTimeout(load,600)}
async function sendChat(){const t=$("chatmsg").value.trim();if(!t)return;$("chaterr").textContent="";
 const r=await fetch("api/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text:t})});
 if(r.ok){$("chatmsg").value="";chatLeft();setTimeout(()=>loadChat(false),700)}
 else{let e="Could not send";try{e=(await r.json()).error||e}catch(x){}if(r.status===401){e="Your admin session has expired: log in again.";session()}$("chaterr").textContent=e}}
async function session(){try{const r=await (await fetch("api/session")).json();ADMIN=r.admin;LOGIN_ON=r.login_enabled}catch(e){}
 MAINADM=ADMIN&&!TENANT;
 const was=$("chatcard").style.display!=="none";$("chatcard").style.display=ADMIN?"":"none";$("roomcard").style.display=ADMIN&&TENANT?"":"none";$("observercard").style.display=MAINADM?"":"none";$("trafficcard").style.display=MAINADM?"":"none";$("welcomecard").style.display=ADMIN&&TENANT?"":"none";if(ADMIN&&!was)loadChat(true);if(ADMIN&&TENANT&&!WELCOME_LOADED)loadWelcome();if(!ADMIN)WELCOME_LOADED=false;
 $("mqcard").style.display=MAINADM?"":"none";
 $("rpcard").style.display=MAINADM?"":"none";$("aircard").style.display=MAINADM?"":"none";
 $("vccard").style.display=MAINADM?"":"none";
 $("tncard").style.display=MAINADM?"":"none";if(MAINADM)loadTenants();
 $("kaascard").style.display=MAINADM?"":"none";if(MAINADM)loadKaas();$("webcard").style.display=MAINADM?"":"none";if(MAINADM)loadWeb();
 $("loginbtn").textContent=ADMIN?"Log out":"Log in";$("loginbtn").style.display=LOGIN_ON||ADMIN?"":"none";$("who").textContent=ADMIN?"admin":""}
let OBS_SERVERS=[];
function renderObserverServers(){const t=$("observerservers");t.innerHTML="<tr><th>Name</th><th>Endpoint</th><th>Audience</th><th>Prefix</th><th>State</th><th></th></tr>"+OBS_SERVERS.map((s,i)=>`<tr><td>${esc(s.name)}</td><td>${esc(s.host)}:${s.port}${esc(s.ws_path)}</td><td>${esc(s.audience)}</td><td>${esc(s.topic_prefix)}</td><td>${s.enabled?"enabled":"off"}</td><td><button onclick="removeObserverServer(${i})">Delete</button></td></tr>`).join("")}
function saveObserverServers(){fetch("api/observer",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({observer_servers:OBS_SERVERS})}).then(r=>r.json().then(d=>({ok:r.ok,d}))).then(x=>{$("obsmsg").textContent=x.ok?"Observer servers saved; refreshing.":(x.d.error||"Could not save");setTimeout(load,500)}).catch(()=>{$("obsmsg").textContent="Could not save"})}
function addObserverServer(){const n=$("os_name").value.trim(),h=$("os_host").value.trim();if(!n||!h){$("obsmsg").textContent="Server name and host are required";return}OBS_SERVERS.push({name:n,host:h,port:+$("os_port").value,audience:$("os_aud").value.trim()||h,ws_path:$("os_path").value.trim()||"/",topic_prefix:$("os_prefix").value.trim()||"meshcore",enabled:$("os_enabled").checked,tls:$("os_tls").checked,tls_verify:$("os_verify").checked});saveObserverServers()}
function removeObserverServer(i){if(confirm("Delete this observer server?")){OBS_SERVERS.splice(i,1);saveObserverServers()}}
function observerState(o){
 const d=o||{enabled:false,iata:"",queue_depth:0,queue_max:1000,dropped:0,uptime:0,last_rx:0,last_error:"",brokers:{}};
 if(ADMIN){const ch=d.choices||[],sel=$("obs_who"),valid=ch.some(c=>c.id===d.identity);
  if(document.activeElement!==sel&&changed("obswho",[ch,d.identity])){sel.innerHTML='<option value="">— choose —</option>'+ch.map(c=>`<option value="${esc(c.id)}">${esc(c.label)}</option>`).join("");sel.value=valid?d.identity:""}
  $("obs_enabled").disabled=!valid&&!d.enabled;
  $("obswho_note").textContent=!ch.length?"Turn on the virtual repeater or create a room: the observer reports as one of them.":!valid?"Choose who it reports as to enable it.":"";
  $("obs_enabled").checked=!!d.enabled;
  const f=document.activeElement,typing=f&&f.closest&&f.closest("#observercard")&&f.tagName!=="BUTTON"&&f.type!=="checkbox";
  if(!typing&&changed("obsform",[d.iata,d.status,d.packets,d.rx,d.queue_max])){$("obs_iata").value=d.iata||"";$("obs_status").checked=d.status!==false;$("obs_packets").checked=d.packets!==false;$("obs_rx").checked=d.rx!==false;$("obs_queue").value=d.queue_max||1000}
  if(changed("obssrv",d.servers||[])){OBS_SERVERS=d.servers||[];renderObserverServers()}}
 const bs=d.brokers||{}, row=n=>{const b=bs[n]||{},s=b.connected?'<span class="good">connected</span>':'<span class="poor">disconnected</span>';return `<tr><td>${n}</td><td>${s}</td><td>${b.last_publish?ago(b.last_publish)+" ago":"never"}</td><td class="small">${esc(b.last_error||"-")}</td></tr>`};
 $("observerstatus").innerHTML=`<tr><th>Public key</th><td class="mono">${esc(d.public_key||((d.choices||[]).find(c=>c.id===d.identity)||{}).key||"-")}</td><th>Queue</th><td>${d.queue_depth}/${d.queue_max} &middot; ${d.dropped} dropped</td><th>Uptime</th><td>${d.uptime||0}s</td></tr>`+
  `<tr><th>Broker</th><th>State</th><th>Last publish</th><th colspan="3">Last error</th></tr>`+Object.keys(bs).map(row).join("")+(d.last_error?`<tr><th>Observer</th><td colspan="5" class="poor">${esc(d.last_error)}</td></tr>`:"");
}
async function saveObserver(){
 const body={observer_enabled:$("obs_enabled").checked,observer_iata:$("obs_iata").value.trim().toUpperCase(),observer_status:$("obs_status").checked,observer_packets:$("obs_packets").checked,observer_rx:$("obs_rx").checked,observer_queue_max:Number($("obs_queue").value)};
 const r=await fetch("api/observer",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});let m=r.ok?"Saved; broker settings are being refreshed.":"Could not save";try{if(!r.ok)m=(await r.json()).error||m}catch(e){}if(r.status===401){m="Your admin session has expired: log in again.";session()}$("obsmsg").textContent=m;setTimeout(load,500);
}
async function saveObserverWho(){const r=await fetch("api/observer",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({observer_identity:$("obs_who").value})});
 let m=r.ok?"Saved: the observer now reports as "+($("obs_who").selectedOptions[0]||{}).text+".":"Could not save";try{if(!r.ok)m=(await r.json()).error||m}catch(e){}$("obsmsg").textContent=m;delete SIG.obswho;setTimeout(load,500)}
async function saveObserverToggle(){
 const enabled=$("obs_enabled").checked;$("obsmsg").textContent="Saving observer state…";
 const r=await fetch("api/observer",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({observer_enabled:enabled})});let m=r.ok?(enabled?"Observer enabled; broker settings are being refreshed.":"Observer disabled; brokers are disconnecting."):"Could not save";try{if(!r.ok)m=(await r.json()).error||m}catch(e){}if(r.status===401){m="Your admin session has expired: log in again.";session()}$("obsmsg").textContent=m;setTimeout(load,500);
}
function fmtBytes(n){return n<1024?n+" B":n<1048576?(n/1024).toFixed(1)+" KiB":(n/1048576).toFixed(1)+" MiB"}
function fmtDuration(n){n=Math.max(0,Math.floor(n||0));const h=Math.floor(n/3600),m=Math.floor(n%3600/60),s=n%60;return h?`${h}h ${m}m`:m?`${m}m ${s}s`:`${s}s`}
function observerTraffic(d){
 const box=$("observertraffic");if(!ADMIN){box.innerHTML="";return}if(!d||!d.available){box.innerHTML='<h2>Traffic statistics</h2><span class="dim small">Observer statistics are available after the observer is enabled.</span>';return}
 const v=d.rf_per_minute||[],max=Math.max(0,...v),bars=max?`<div class="traffic-chart">${v.map(n=>`<i title="${n} RF packet${n===1?"":"s"}" class="${n?"":"zero"}" style="height:${n?Math.max(3,Math.round(100*n/max)):1}%"></i>`).join("")}</div><div class="traffic-label dim small"><span>60 minutes ago</span><span>now</span></div>`:'<div class="traffic-chart">'+Array.from({length:60},()=>'<i class="zero"></i>').join("")+'</div><div class="dim small">No RF traffic received in the last 60 minutes.</div>';
 const b=d.brokers||{},row=n=>{const x=b[n]||{},state=x.connected?'<span class="good">connected</span>':'<span class="poor">disconnected</span>';return `<tr><td>${n}</td><td>${state}</td><td>${x.attempts||0}</td><td>${x.accepted||0}</td><td>${x.failures||0}</td><td>${fmtBytes(x.payload_bytes||0)}</td><td>${x.last_success?ago(x.last_success)+" ago":"never"}</td><td class="small">${esc(x.last_error||"-")}</td></tr>`};
 box.innerHTML=`<h2>Traffic statistics <span class="hdesc">admin only &middot; local measurements</span></h2><div class="kpis"><div class="kpi"><span class="dim small">RF packets received</span><b>${d.rf_total||0}</b></div><div class="kpi"><span class="dim small">Current traffic</span><b>${d.rf_current_ppm||0}/min</b></div><div class="kpi"><span class="dim small">Peak traffic</span><b>${d.rf_peak_ppm||0}/min</b></div><div class="kpi"><span class="dim small">Last 60 minutes</span><b>${d.rf_last_60m||0}</b></div><div class="kpi"><span class="dim small">Observer uptime</span><b>${fmtDuration(d.uptime)}</b></div><div class="kpi"><span class="dim small">Queue dropped</span><b>${d.dropped||0}</b></div></div><h3>RF traffic: last 60 minutes</h3>${bars}<h3>MQTT broker traffic <span class="hdesc">local publish submissions; QoS 0 does not confirm broker delivery</span></h3><table><tr><th>Broker</th><th>State</th><th>Attempts</th><th>Accepted</th><th>Failures</th><th>Payload bytes</th><th>Last accepted</th><th>Last error</th></tr>${row("gomesh")}${row("meshmapper")}</table>`;
}
async function loadObserverTraffic(){if(!ADMIN)return;try{const r=await fetch("api/observer/stats");if(r.ok)observerTraffic(await r.json())}catch(e){}}
async function loadWelcome(){
 const r=await fetch("api/welcome");if(!r.ok)return;const d=await r.json();$("welcome_enabled").checked=!!d.welcome_new_members;$("welcome_message").value=d.welcome_message||"";$("welcome_hint").value=d.welcome_advert_hint||"";WELCOME_LOADED=true;
}
async function saveWelcome(){
 const body={welcome_new_members:$("welcome_enabled").checked,welcome_message:$("welcome_message").value,welcome_advert_hint:$("welcome_hint").value};
 const r=await fetch("api/welcome",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});let m=r.ok?"Welcome settings saved.":"Could not save";try{if(!r.ok)m=(await r.json()).error||m}catch(e){}if(r.status===401){m="Your admin session has expired: log in again.";session()}$("welcomemsg").textContent=m;
}
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
 const nb=l=>l.length?"<table><tr><th>Repeater</th><th>Avg SNR</th><th>Seen</th></tr>"+l.map(x=>`<tr><td>${esc(x.name)}${x.obs?' <span class="dim small" title="only heard by observers (MQTT)">via observers</span>':""}</td><td>${sn(x.snr)}</td><td>${x.seen}</td></tr>`).join("")+"</table>":'<span class="dim">none yet</span>';
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
let MAPSHAPE=true,DRAWNSEL=undefined;
function select(hash){SEL=hash;const r=RPTS.find(x=>x.hash===hash);
 $("rdetail").innerHTML=r?detail(r):'<div class="dim pick">Select a repeater from the map</div>';
 document.querySelectorAll("#rpts tr[data-i]").forEach(tr=>tr.classList.toggle("sel",RPTS[+tr.dataset.i]&&RPTS[+tr.dataset.i].hash===SEL));
 if(map&&layer&&(MAPSHAPE||DRAWNSEL!==SEL))drawMap(LAST);
 DRAWNSEL=SEL;MAPSHAPE=false}
let MAPSIG="",MAPVER=null,MAPBUSY=false;
async function loadMap(){
 if(MAPBUSY)return; MAPBUSY=true;
 let MP; try{MP=await (await fetch("api/map")).json()}catch(e){MAPBUSY=false;return}
 MAPBUSY=false;
 if(!MP.repeaters)return;
 const shapeChanged=MP.version!==MAPVER; MAPVER=MP.version;
 const sig=JSON.stringify(MP.repeaters)+JSON.stringify(MP.edges);
 if(sig===MAPSIG)return;                                     // nothing changed: leave the table, map and panel alone
 MAPSIG=sig;
 $("rpts").innerHTML="<tr><th>Repeater</th><th>Activity</th><th>Last seen</th><th>Heard directly</th><th>SNR (direct)</th><th>Position</th><th>Best routes from room</th></tr>"+
  MP.repeaters.map((r,i)=>`<tr data-i="${i}"><td>${esc(r.name)||'<span class="dim">?</span>'} <span class="dim">${r.hash}</span></td><td>${r.activity}</td><td>${ago(r.last)}</td><td>${r.last_direct?ago(r.last_direct):"-"}</td><td>${r.snr??"-"}</td><td class="small">${r.lat!=null?r.lat.toFixed(4)+", "+r.lon.toFixed(4):'<span class="dim">none sent</span>'}</td><td class="small">${r.routes.length?r.routes.map(x=>route(x.path)+` <span class="dim">${x.conf}%</span>`).join("<br>"):"-"}</td></tr>`).join("");
 RPTS=MP.repeaters; LAST=MP; MAPSHAPE=shapeChanged; drawBestMap();
 document.querySelectorAll("#rpts tr[data-i]").forEach(tr=>{const r=RPTS[+tr.dataset.i];tr.onclick=()=>select(r.hash)});
 if(SEL)select(SEL); else if(shapeChanged||!map)drawMap(MP);
}
const SIG={};
function changed(k,v){const j=typeof v==="string"?v:JSON.stringify(v);if(SIG[k]===j)return false;SIG[k]=j;return true}
const CID=Math.random().toString(36).slice(2,12);           // this tab's id (for the viewer count)
async function load(){
 let st; try{st=await (await fetch("api/state?c="+CID)).json()}catch(e){return}
 if(!st.room)return; const R=st.room,S=st.stats;
 $("rname").textContent=R.name; document.title=R.name+" - meshroom";
 $("rinfo").textContent=(R.radio?(R.radio[0]/1e6).toFixed(3)+" MHz BW"+R.radio[1]/1e3+" SF"+R.radio[2]+" CR4/"+R.radio[3]:"")+"  key "+R.key.slice(0,12)+"  "+R.fw;
 const Mq=st.mqtt||{};
 const Md=Mq.diagnostics||{}, Ms=Mq.subscriptions||{}, subValues=Object.values(Ms), granted=subValues.filter(x=>x.state==="granted").length,
  denied=subValues.filter(x=>x.state==="denied").length, pending=subValues.filter(x=>x.state==="pending").length,
  subStatus=denied?`<span class="poor">subscription denied</span>${Mq.subscription_error?": "+esc(Mq.subscription_error):""}`:
   pending?`<span class="mid">subscription awaiting broker acknowledgement</span>`:
   granted?`<span class="good">subscription granted</span>`:`<span class="mid">no topic subscription configured</span>`;
 $("rmqtt").innerHTML=Mq.enabled?`<span class="dim">MQTT ingestion</span> <span class="mqdot ${Mq.connected?"on":"off"}" title="${esc(Mq.connected?"connected":(Mq.error||"connecting..."))}"></span> ${esc(Mq.host||"")} <span class="dim small">pps: ${Mq.pps} (${Mq.rel_pps} relevant)</span>`
   :'<span class="dim">MQTT ingestion off</span>';
 if(ADMIN){$("mq_en").checked=!!Mq.enabled;$("mq_ack").checked=!!Mq.ack_ingest;$("mq_msg").checked=!!Mq.msg_ingest;
  $("mq_topo").checked=!!Mq.topo_ingest;$("mq_adv").checked=!!Mq.advert_ingest;$("mq_act").checked=!!Mq.activity;
  $("mq_ack").disabled=$("mq_msg").disabled=$("mq_topo").disabled=$("mq_adv").disabled=$("mq_act").disabled=!Mq.enabled;
  $("mqch").textContent=(Mq.channels||[]).length?" · channels watched: "+Mq.channels.join(", "):"";
  $("mqcred").innerHTML=Mq.credentials_configured?'<span class="good">subscriber credentials configured</span>':'<span class="mid">subscriber credentials not configured</span>';
  const mf=document.activeElement,mqTyping=mf&&mf.closest&&mf.closest("#mqcard")&&["text","password","number"].includes(mf.type);
  if(!mqTyping&&changed("mqconn",[Mq.host,Mq.port,Mq.transport,Mq.ws_path,Mq.tls,Mq.tls_verify,Mq.topics])){$("mq_host").value=Mq.host||"";$("mq_port").value=Mq.port||"";$("mq_transport").value=Mq.transport||"websockets";$("mq_path").value=Mq.ws_path||"/mqtt";$("mq_tls").checked=!!Mq.tls;$("mq_verify").checked=!!Mq.tls_verify;$("mq_topics").value=(Mq.topics||[]).join(", ");
  const rg=regionsOf(Mq.topics);$("mq_regions").value=rg||"";$("mqreg").className="dim small";$("mqreg").textContent=rg===null?"custom topic filters in use (below)":rg?"taking in only these regions":"every region";}
  $("mqstat").innerHTML=Mq.enabled?(Mq.connected?`connected to ${esc(Mq.host)} &middot; ${subStatus} &middot; MQTT packets received: ${Md.received||0}; accepted: ${Md.accepted||0} &middot; deliveries confirmed: ${Mq.acks} &middot; posts captured: ${Mq.posts} &middot; links: ${Mq.links} &middot; adverts: ${Mq.adverts} &middot; channel msgs: ${Mq.channel_msgs} &middot; wakes: ${Mq.wakes}`
   :`<span class="poor">not connected</span> ${esc(Mq.error||"(connecting...)")}`):"off"}
 if(MAINADM)renderAir(st.airtime);
 if(TENANT&&ADMIN){const f=document.activeElement,typing=f&&f.closest&&f.closest("#roomcard")&&f.tagName==="INPUT";
  if(!typing&&changed("rmloc",[R.lat,R.lon])){const has=R.lat||R.lon;$("rm_lat").value=has?R.lat:"";$("rm_lon").value=has?R.lon:""}}
 const Rp=st.repeater||{};
 $("rrpt").innerHTML=Rp.enabled?`<span class="dim">Repeater</span> ${esc(Rp.name)} <span class="dim small">${esc(Rp.id||"")}</span> `+
   (Rp.relay?`<span class="good">relaying</span> <span class="dim small">${Rp.per_min}/min &middot; ${Rp.airtime_used}% air (airtime weight ${Rp.airtime_cap})</span>`:'<span class="mid">not relaying</span>')
   :'<span class="dim">Repeater off</span>';
 document.querySelectorAll("#rpcard .advbtns .act").forEach(b=>{if(!b.dataset.busy)b.disabled=!Rp.enabled});
 if(ADMIN){$("rp_en").checked=!!Rp.enabled;$("rp_relay").checked=!!Rp.relay;$("rp_relay").disabled=!Rp.enabled;
  const f=document.activeElement,typing=f&&f.closest&&f.closest("#rpcard")&&f.tagName!=="BUTTON"&&f.type!=="checkbox";
  if(!typing&&changed("rpform",[Rp.name,Rp.lat,Rp.lon,Rp.scope_mode,Rp.regions,Rp.airtime_cap,Rp.loop_detect,Rp.advert_min,Rp.flood_advert_h])){
   $("rp_name").value=Rp.name||"";$("rp_lat").value=Rp.lat||Rp.lon?Rp.lat:"";$("rp_lon").value=Rp.lat||Rp.lon?Rp.lon:"";$("rp_mode").value=Rp.scope_mode||"allow";$("rp_regions").value=(Rp.regions||[]).join(", ");
   $("rp_air").value=Rp.airtime_cap;$("rp_loop").value=Rp.loop_detect||"minimal";$("rp_adv").value=Rp.advert_min;$("rp_fadv").value=Rp.flood_advert_h}
  $("rpstat").innerHTML=Rp.enabled?`id ${esc(Rp.id)} &middot; key ${esc((Rp.key||"").slice(0,16))}&hellip;`:"off";
  $("rpcounts").innerHTML=Rp.enabled?`relayed: ${Rp.flood} flood, ${Rp.direct} direct, ${Rp.acks} ACKs, ${Rp.traces} traces &middot; discovery answers: ${Rp.discovery} &middot; `+
   `kept internal: ${Rp.internal} &middot; duplicates: ${Rp.dups} &middot; not relayed: ${Rp.drop_scope} scope, ${Rp.drop_hops} hop limit, ${Rp.drop_loop} loop, `+
   `${Rp.drop_airtime} airtime, ${Rp.drop_queue} queue full${Rp.relay?"":`, ${Rp.drop_off} while off`} &middot; adverts: ${Rp.adverts}`:""}
 const Vc=st.companion||{};
 document.querySelectorAll("#vccard .advbtns .act").forEach(b=>{if(!b.dataset.busy)b.disabled=!Vc.enabled});
 if(MAINADM){try{const r=await fetch("api/companion");if(r.ok)VCA=await r.json()}catch(e){}}
 $("rvc").innerHTML=Vc.enabled?`<span class="dim">Companion</span> ${esc(Vc.name)} `+(Vc.client?`<span class="good">app connected</span>`:Vc.listening?'<span class="dim small">no app connected</span>':'<span class="poor">port not open</span>'):"";
 if(ADMIN){if(!$("vc_en").disabled)$("vc_en").checked=!!Vc.enabled;
  $("vcopts").classList.toggle("locked",!!Vc.enabled);$("vcopts").querySelectorAll("input,select,button").forEach(e=>e.disabled=!!Vc.enabled);
  $("vclockhint").textContent=Vc.enabled?"Turn the companion off to change these settings (name and position can also be set from the app).":
   "Settings are saved when you turn the companion on.";
  const f=document.activeElement,typing=f&&f.closest&&f.closest("#vccard")&&f.tagName!=="BUTTON"&&f.id!=="vc_en";
  if(!typing&&changed("vcform",[Vc.name,Vc.port,VCA.allow,Vc.auto_advert,Vc.advert_min,Vc.advert_flood])){
   $("vc_name").value=Vc.name||"";$("vc_port").value=Vc.port;$("vc_allow").value=(VCA.allow||[]).join(", ");$("vc_auto").checked=!!Vc.auto_advert;
   $("vc_int").value=Vc.advert_min;$("vc_flood").value=Vc.advert_flood?"1":"0"}
  $("vcstat").innerHTML=Vc.enabled?(Vc.listening?`listening on port ${esc(Vc.listen_port)}`:`<span class="poor">port ${esc(Vc.port)} not open: ${esc(Vc.error)}</span>`)+
   ` &middot; id ${esc(Vc.id)} &middot; key ${esc((Vc.key||"").slice(0,16))}&hellip; &middot; `+(Vc.client?`<span class="good">app connected</span>${VCA.client?" from "+esc(VCA.client):""}`:"no app connected"):"off (port closed)";
  $("vccounts").innerHTML=Vc.enabled?`${Vc.contacts} contacts &middot; ${Vc.channels} channels &middot; ${Vc.queued} message(s) waiting for the app &middot; `+
   `messages received ${Vc.msgs_in}, sent ${Vc.msgs_out} &middot; kept off the air: ${Vc.internal_in} in, ${Vc.internal_out} out &middot; app settings ignored: ${Vc.ignored}`:""}
 const Wb=st.web||{};
 $("rweb").innerHTML=`<span class="dim">Web</span> ${Wb.viewers||0} viewer${Wb.viewers==1?"":"s"}${Wb.admins?` <span class="dim small">(${Wb.admins} admin)</span>`:""}`;
 if(st.map_version!==MAPVER)loadMap();                       // the map's shape changed (e.g. a new repeater): fetch now
 const Sy=st.sys, lvl=v=>v>=85?"poor":v>=60?"mid":"";
 $("rsys").innerHTML=Sy?`<span class="dim">CPU</span> <span class="${lvl(Sy.cpu)}">${Sy.cpu}%</span> <span class="dim small">(${Sy.window_min>=10?"10m":Sy.window_min+"m"} avg ${Sy.cpu_avg}%)</span> &nbsp; `+
  `<span class="dim">Mem</span> <span class="${lvl(Sy.mem)}">${Sy.mem}%</span> <span class="dim small">(avg ${Sy.mem_avg}% of ${Sy.mem_total_mb} MB)</span>`:"";
 $("rvolt").innerHTML=R.batt_mv?`<span class="dim">modem</span> ${(R.batt_mv/1000).toFixed(2)} V`:'<span class="dim">modem voltage n/a</span>';
 const Hs=st.hour;
 $("hstats").innerHTML=Hs?[
  `<span><span class="dim">Noise floor</span><b>${Hs.nf_avg??"-"}</b> <span class="dim small">avg &middot; ${Hs.nf_min??"-"} / ${Hs.nf_max??"-"} min / max dBm</span></span>`,
  `<span><span class="dim">Channel use</span>TX <b>${Hs.tx_pct}%</b> &middot; RX <b>${Hs.rx_pct}%</b></span>`,
  `<span><span class="dim">Packets / min</span>RX <b>${Hs.rx_pm}</b> &middot; TX <b>${Hs.tx_pm}</b></span>`,
  ...(R.host?[]:[`<span><span class="dim">Push pace</span><b>${Hs.pace} s</b></span>`,
  `<span><span class="dim">Pushes / min</span><b>${Hs.pushes_pm}</b>${Hs.push_rf!=null?` &middot; <b class="${Hs.push_rf>=80?"good":Hs.push_rf>=50?"mid":"poor"}">${Hs.push_rf}%</b> delivered${(st.mqtt||{}).enabled?` <span class="dim small">(${Hs.push_ok}% per MQTT)</span>`:""}`:""}</span>`]),
  `<span class="dim small">last ${Hs.minutes>=60?"hour":Hs.minutes+" min"}</span>`].join(""):'<span class="dim small">stats appear after the first minute</span>';
 $("rclock").textContent="up "+ago(Date.now()/1000-R.uptime).replace("s"," s")+(R.clock_ok?"":"  CLOCK NOT SYNCED");
 observerState(st.observer);if(MAINADM)loadObserverTraffic();
 const k=[...(R.host?[["Rooms",R.rooms]]:[["Members",st.members.length],["Posts held",S.posts_held],["Pushes",S.pushes],["Delivered",S.acks],["Late ACKs",S.late_acks],["Timeouts",S.timeouts],["Floods failed",S.flood_fallbacks]]),
  ["Duplicates dropped",S.deduped],["Traces heard",S.traces],["Noise floor",R.noise_floor+" dBm"],["RX / TX",S.recv+" / "+S.sent],["TX queue",S.tx_queue],["Names known",S.names_known]];
 $("kpis").innerHTML=k.map(x=>`<div class="kpi"><span class="dim small">${x[0]}</span><b>${esc(x[1])}</b></div>`).join("");
 const IC=n=>`<img src="icons/${n}.png" alt="${n}">`;
 const memSig=JSON.stringify(st.members)+"|"+ADMIN+"|"+[...EXP].join(",");
 if(changed("members",memSig)){
 const PUSH_TIP={synced:"Up to date: nothing to send",queued:"Posts waiting; nothing sent yet",sent:"First attempt sent",retry:"Retrying: count of retries sent for this post",backoff:"Every attempt failed: one more try (best route, then floods) when the timer ends",suspended:"No ACKs: paused until we hear from them (a flood probe every 6 h)"};
 const ACTS=(m,i)=>ADMIN?`<td class="acts"><button class="act" title="Force resync: clear backoff/suspension, retry now via best routes, then floods${m.outstanding?"":" (nothing outstanding)"}" onclick="event.stopPropagation();resync(MEMBERS[${i}],this)">${IC("resync")}</button><button class="act" title="Suggest a route to this member" onclick="event.stopPropagation();openSuggest(MEMBERS[${i}])">${IC("suggest")}</button><button class="act" title="Kick: remove from the room (they can rejoin)" data-u="api/members/${m.pub}/kick" data-m="Kick ${esc(m.name||m.key)}? They are removed as if they never joined, and can log in again." onclick="event.stopPropagation();act(this.dataset.u,this.dataset.m)">${IC("kick")}</button><button class="act" title="Ban: the room ignores them completely" data-u="api/members/${m.pub}/ban" data-m="Ban ${esc(m.name||m.key)}? The room will stop responding to them entirely." onclick="event.stopPropagation();act(this.dataset.u,this.dataset.m)">${IC("ban")}</button></td>`:"";
 const IDC=(m,caret)=>`<td class="idcell">${caret}<b>${esc(m.name)||'<span class="dim">unknown</span>'}</b><br><span class="dim mono4">${m.key.slice(0,4)}</span><br><span class="small">${m.role}</span></td>`;
 const HX=h=>h==null?'<span class="dim">unknown</span>':h.length?h.join(" &rsaquo; "):"direct";
 const NM=p=>p==null?'<span class="dim">unknown</span>':p.length?p.map(esc).join(" &rsaquo; "):"direct";
 const row=(tag,cls,body)=>`<div><span class="dir ${cls}">${tag}</span><span>${body}</span></div>`;
 const act_=st.members.map((m,i)=>[m,i]).filter(([m])=>m.push!=="suspended"), sus=st.members.map((m,i)=>[m,i]).filter(([m])=>m.push==="suspended").sort((x,y)=>(y[0].last_heard||0)-(x[0].last_heard||0));   // longest silence at the bottom
 $("members").innerHTML="<tr>"+(ADMIN?"<th></th>":"")+"<th>ID</th><th>Delivery</th><th>Last heard</th><th>Synced to</th><th>Behind</th><th>Push</th><th>Current route</th><th>Other routes</th><th>Usually near</th></tr>"+
  (act_.length?act_.map(([m,i])=>{const ex=EXP.has(m.key), others=m.routes.filter(r=>!r.current);
   const cur=ex?row("TX","tx",route(m.route))+row("RX","rx",NM(m.in_route)):row("TX","tx",`<span class="hexr">${HX(m.route_hex)}</span>`)+row("RX","rx",`<span class="hexr">${HX(m.in_route_hex)}</span>`);
   const oth=ex?[...others.slice(0,5).map(r=>row("TX","tx",`${route(r.path)} <span class="dim">${r.rate}%</span>`)),...(m.in_routes||[]).slice(0,5).map(r=>row("RX","rx",`${NM(r.path)} <span class="dim">${r.share}%</span>`))].join("")
              :[...others.slice(0,2).map(r=>row("TX","tx",`<span class="hexr">${HX(r.hex)}</span> <span class="dim">${r.rate}%</span>`)),...(m.in_routes||[]).slice(0,2).map(r=>row("RX","rx",`<span class="hexr">${HX(r.hex)}</span> <span class="dim">${r.share}%</span>`))].join("");
   const near=ex?m.near.map(n=>esc(n.rpt)+` <span class="dim">${n.share}%</span>`).join("<br>"):m.near.slice(0,4).map(n=>`<span class="hexr">${n.hex}</span> <span class="dim">${n.share}%</span>`).join("<br>");
   return `<tr class="mrow${ex?" exp":""}" data-k="${m.key}">${ACTS(m,i)}${IDC(m,`<span class="caret">${ex?"&#9662;":"&#9656;"}</span>`)}<td>${score(m)}</td><td>${ago(m.last_heard)}</td><td>${ago(m.sync_since)}</td><td>${m.outstanding}</td>
   <td><span class="tag ${m.push}" title="${PUSH_TIP[m.push]||""}">${m.push==="retry"?"retry \u00d7"+m.retries:m.push}${m.retry_in?" "+Math.ceil(m.retry_in/60)+"m":""}</span></td>
   <td class="small ${ex?"rcell":""}">${cur}</td><td class="small ${ex?"rcell":""}">${oth||'<span class="dim">-</span>'}</td><td class="small">${near||'<span class="dim">-</span>'}</td></tr>`}).join("")
  :`<tr><td class="dim">no active members</td></tr>`);
 document.querySelectorAll("#members tr.mrow").forEach(tr=>tr.onclick=()=>{const k=tr.dataset.k;EXP.has(k)?EXP.delete(k):EXP.add(k);SIG.members="";load()});
 $("suspended").innerHTML=sus.length?"<tr>"+(ADMIN?"<th></th>":"")+"<th>ID</th><th>Last heard</th><th>Suspended for</th><th>Posts waiting</th><th>Usually near</th></tr>"+
  sus.map(([m,i])=>`<tr>${ACTS(m,i)}${IDC(m,"")}<td>${ago(m.last_heard)}</td><td>${m.suspended_at?ago(m.suspended_at):"-"}</td><td>${m.outstanding}</td>
   <td class="small">${m.near.slice(0,4).map(n=>`<span class="hexr">${n.hex}</span> <span class="dim">${n.share}%</span>`).join("<br>")||'<span class="dim">-</span>'}</td></tr>`).join("")
  :'<tr><td class="dim">nobody</td></tr>';
 }
 if(changed("toplinks",{t:st.top_links,d:st.discovery_min})){
 const TL=st.top_links||[], sn=a=>a==null?"-":(a>0?"+":"")+a;
 BEST=TL;
 $("toplinks").innerHTML=TL.length?"<tr><th>Repeater</th><th>Reliability</th><th>SNR in/out avg</th><th>Last test</th></tr>"+
  TL.map(r=>{const c=relClass(r);
   return `<tr><td><span class="reldot ${c}"></span>${esc(r.name)}</td><td>${r.virtual?'<span class="good">100%</span> <span class="dim small">same radio</span>':r.loss==null?'<span class="dim">not traced yet</span>':`<span class="${c}">${(100-r.loss).toFixed(1)}%</span> <span class="dim small">${r.traces} trace${r.traces==1?"":"s"}${r.few?" &middot; few traces":""}</span>`}</td>`+
   `<td>${sn(r.in_avg)}<span class="dim"> / </span>${sn(r.out_avg)}</td><td>${r.last_test?ago(r.last_test)+" ago":r.virtual?'<span class="dim">-</span>':"never"}</td></tr>`}).join("")
  :`<tr><td class="dim">no neighbours yet: the room discovers its direct repeaters every ${st.discovery_min||15} minutes</td></tr>`;
 drawBestMap();
 }
 MEMBERS=st.members;
 const bans=st.bans||[];
 if(changed("bans",{b:bans,a:ADMIN}))
 $("bans").innerHTML=bans.length?"<tr><th>Name</th><th>Key</th><th>Banned</th><th></th></tr>"+bans.map(b=>`<tr><td>${esc(b.name)||'<span class="dim">unknown</span>'}</td><td class="dim">${b.key}</td><td>${ago(b.ts)} ago</td><td>${ADMIN?`<button data-u="api/bans/${b.pub}/unban" data-m="Unban ${esc(b.name||b.key)}? They will be able to log in again." onclick="act(this.dataset.u,this.dataset.m)">Unban</button>`:""}</td></tr>`).join(""):'<tr><td class="dim">nobody</td></tr>';
}
// Reliability class for a best-neighbour row: green 80%+, yellow 70%+, red below (grey: not traced yet).
function relClass(r){return r.virtual?"good":r.loss==null?"dim":r.loss<=20?"good":r.loss<=30?"mid":"poor"}
// Best neighbours mini map: each neighbour a dot, joined to the room by a line, both in its reliability colour;
// links between neighbours that are known to hear each other in light blue.
let BEST=[],bestmap=null,bestlayer=null,BESTSIG="";
function drawBestMap(){
 const box=$("bestmapbox"),note=$("bestmapnote");
 if(typeof L==="undefined"){box.style.display="none";return}
 if(!LAST||!LAST.repeaters)return;                              // map data not loaded yet: loadMap() calls back
 const pos={};LAST.repeaters.forEach(r=>{if(r.on_map!==false&&r.lat!=null&&(r.lat||r.lon))pos[r.hash]=[r.lat,r.lon]});
 const R=LAST.room,room=(R.lat||R.lon)?[R.lat,R.lon]:null;
 const css=getComputedStyle(document.documentElement),col={good:css.getPropertyValue("--ok").trim(),mid:css.getPropertyValue("--warn").trim(),
  poor:css.getPropertyValue("--bad").trim(),dim:css.getPropertyValue("--dim").trim()},link=css.getPropertyValue("--link").trim();
 const pts=BEST.filter(r=>pos[r.hash]).map(r=>({h:r.hash,p:pos[r.hash],c:col[relClass(r)],name:r.name,
  rel:r.virtual?"same radio":r.loss==null?"not traced yet":(100-r.loss).toFixed(1)+"%"}));
 const inBest=new Set(pts.map(x=>x.h));
 const links=(LAST.edges||[]).filter(e=>e.a&&e.b&&e.a!==e.b&&inBest.has(e.a)&&inBest.has(e.b));
 const missing=BEST.length-pts.length;
 note.textContent=!pts.length?(BEST.length?"No positions known for these repeaters yet.":""):missing?`${missing} without a known position not shown.`:"";
 if(!pts.length){$("bestmap").style.display="none";return}
 $("bestmap").style.display="";
 const sig=JSON.stringify([room,pts.map(x=>[x.h,x.p,x.c]),links.map(e=>[e.a,e.b,e.obs])]);
 if(sig===BESTSIG&&bestmap)return; BESTSIG=sig;
 if(!bestmap){
  bestmap=L.map("bestmap",{zoomControl:true,attributionControl:true}).setView(pts[0].p,11);
  L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png",{maxZoom:18,attribution:"&copy; OpenStreetMap",
   referrerPolicy:"strict-origin-when-cross-origin"}).addTo(bestmap);
 }
 if(bestlayer)bestlayer.remove(); bestlayer=L.layerGroup().addTo(bestmap);
 const name=h=>{const x=pts.find(p=>p.h===h);return x?esc(x.name):h};
 links.forEach(e=>L.polyline([pos[e.a],pos[e.b]],{color:link,weight:1.5,opacity:.7,dashArray:e.obs?"4 4":null})
  .bindTooltip(`${name(e.a)} &harr; ${name(e.b)}${e.obs?"<br><i>via observers</i>":""}`).addTo(bestlayer));
 if(room)pts.forEach(x=>L.polyline([room,x.p],{color:x.c,weight:3,opacity:.85}).bindTooltip(`${esc(x.name)}: ${x.rel}`).addTo(bestlayer));
 pts.forEach(x=>L.circleMarker(x.p,{radius:7,color:"#0d1014",weight:1.5,fillColor:x.c,fillOpacity:1})
  .bindTooltip(`${esc(x.name)}<br>reliability ${x.rel}`).addTo(bestlayer));
 if(room)L.circleMarker(room,{radius:8,color:"#0d1014",weight:1.5,fillColor:"#ffffff",fillOpacity:1}).bindTooltip(esc(R.name)+" (room)").addTo(bestlayer);
 const all=pts.map(x=>x.p).concat(room?[room]:[]);
 bestmap.fitBounds(all,{padding:[24,24],maxZoom:13});
 setTimeout(()=>bestmap.invalidateSize(),0);
}
function drawMap(st){
 if(typeof L==="undefined"){$("mapnote").textContent="Map needs internet access (Leaflet / OpenStreetMap). Tables above still work.";return}
 const R=st.room,pos={},tip={};st.repeaters.forEach(r=>{if(r.on_map!==false&&r.lat!=null&&(r.lat||r.lon)){pos[r.hash]=[r.lat,r.lon,r.name||r.hash];tip[r.hash]=`${esc(r.name||r.hash)} (${hopsTxt(hops(r))})`}});
 if(R.lat||R.lon)pos[""]=[R.lat,R.lon,R.name+" (room)"];
 const pts=Object.values(pos);
 if(!map){
  // the map must have a real view BEFORE anything is drawn on it, or Leaflet places markers off-screen
  const c=pts.length?pts[0]:[R.lat||0,R.lon||0], z=pts.length||R.lat||R.lon?11:2;
  map=L.map("map").setView([c[0],c[1]],z);
  // OSM's tile servers refuse requests without a Referer: set it on the tiles themselves so a strict
  // Referrer-Policy from a proxy / load balancer can't strip it
  L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png",{maxZoom:18,attribution:"&copy; OpenStreetMap",
   referrerPolicy:"strict-origin-when-cross-origin"}).addTo(map);
  map.on("click",()=>{if(SEL)select(null)});                 // empty map: show everything again
 }
 const sig=Object.keys(pos).sort().join(",");
 if(pts.length&&map._sig!==sig){map.fitBounds(pts.map(p=>p.slice(0,2)),{padding:[30,30],maxZoom:12});map._sig=sig}
 if(layer)layer.remove(); layer=L.layerGroup().addTo(map);
 // lines only for the selected repeater (none when nothing is selected); its neighbours stay bright
 const linked=new Set();
 st.edges.forEach(e=>{if(!SEL||(e.a!==SEL&&e.b!==SEL))return;const a=pos[e.a],b=pos[e.b];if(!a||!b)return;
  if(SEL){linked.add(e.a);linked.add(e.b)}
  L.polyline([a.slice(0,2),b.slice(0,2)],{weight:1.5,color:e.b===""||e.a===""?"#5cb3ff":"#8a94a3",opacity:SEL?.9:.55,interactive:true,dashArray:e.obs?"4 4":null})
   .bindTooltip(`${esc(a[2])} &rarr; ${esc(b[2])}<br>seen ${e.w}${e.snr!=null?"<br>SNR "+e.snr:""}${e.obs?"<br><i>via observers</i>":""}`).addTo(layer)});
 Object.entries(pos).forEach(([h,p])=>{const sel=h===SEL, dim=SEL&&!sel&&!linked.has(h);
  const mk=L.circleMarker(p.slice(0,2),{radius:h===""?8:sel?10:7,color:h===""?"#4caf7a":sel?"#ffd166":"#5cb3ff",weight:sel?3:2,
   opacity:dim?.25:1,fillOpacity:dim?.15:.9}).bindTooltip(tip[h]||esc(p[2]),{direction:"top",offset:[0,-6]}).addTo(layer);
  if(h!=="")mk.on("click",ev=>{L.DomEvent.stopPropagation(ev);select(h===SEL?null:h)})});
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
setInterval(()=>loadChat(false),3000);setInterval(loadTenants,5000);setInterval(loadKaas,5000);setInterval(loadWeb,5000);
session().then(()=>{load();loadMap()});setInterval(load,1000);setInterval(loadMap,30000);setInterval(session,60000);
</script></body></html>"""


ICON_NAMES = ("resync", "suggest", "kick", "ban", "advert", "flood_advert")
PACKAGED_ICONS_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "icons")
MESHCORE_WEB_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "meshcore-web.html")   # web/


def dashboard_icon_file(data_dir, name):
    """Return a local icon override or the PNG bundled with this checkout."""
    for root in (os.path.join(data_dir, "icons"), PACKAGED_ICONS_DIR):
        path = os.path.join(root, name + ".png")
        if os.path.isfile(path):
            return path
    return None


BUILTIN_ICONS = {   # final fallback when neither a local nor bundled PNG exists
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
        clock_ = threading.Lock()
        slots = threading.BoundedSemaphore(16)
        failures, flock = {}, threading.Lock()              # address -> recent failed logins (monotonic): see _locked_out
        recent_by_ip = {}                                   # (what, address) -> recent requests (monotonic): see _ip_rate
        last_advert = [float("-inf")]

        files = {}                                          # path -> (mtime, raw, gzipped or None)
        page = (DASHBOARD_HTML.encode(), gzip.compress(DASHBOARD_HTML.encode(), 6))   # the page never changes while running
        stats_ = {"disk_reads": 0}

        def cached_file(f, compress):
            """Read + (optionally) gzip a file once, then serve it from RAM; re-read only if it changed on disk."""
            mt = os.path.getmtime(f)
            with clock_:
                hit = files.get(f)
                if hit and hit[0] == mt:
                    return hit
            with open(f, "rb") as fh:
                raw = fh.read()
            stats_["disk_reads"] += 1
            ent = (mt, raw, gzip.compress(raw, 6) if compress else None)
            with clock_:
                files[f] = ent
            return ent

        snaps = {}                                          # name -> (dict object, raw json, gzipped)
        # tenant rooms' pages: the same dashboard in tenant mode, their own logins (cookie scoped to /{path}/)
        assert DASHBOARD_HTML.count("<script>\nconst TENANT=") == 1
        thtml = DASHBOARD_HTML.replace("<script>\nconst TENANT=", "<script>window.TENANT=true</script><script>\nconst TENANT=")
        tpage = (thtml.encode(), gzip.compress(thtml.encode(), 6))
        tsessions = {}                                      # token -> (expiry, tenant key hex)
        tsnaps = {}                                         # tenant key -> (state dict, raw, gzipped)
        t_last_advert = {}
        viewers = {}                                        # client id -> (last seen, admin)

        def note_viewer(qs, admin):
            cid = ""
            for kv in qs.split("&"):
                k, _, v = kv.partition("=")
                if k == "c":
                    cid = v[:32]
            if not cid:
                return
            nowm = time.monotonic()
            with clock_:
                viewers[cid] = (nowm, admin)
                for k in [k for k, (ts_, _) in viewers.items() if nowm - ts_ > 15]:
                    del viewers[k]
                room.web_clients = (len(viewers), sum(1 for _, a in viewers.values() if a))

        def snap_bytes(name, gz=False):
            """Encode + compress each snapshot once (the main loop swaps in a new dict; never mutates one)."""
            st = getattr(room, name)
            with clock_:
                hit = snaps.get(name)
                if hit is None or hit[0] is not st:
                    raw = json.dumps(st, default=str, separators=(",", ":")).encode()
                    hit = snaps[name] = (st, raw, gzip.compress(raw, 5))
                return hit[2] if gz else hit[1]

        class H(http.server.BaseHTTPRequestHandler):
            timeout = HTTP_TIMEOUT_S                        # (a websocket lifts it once it's open: pings take over)

            def log_message(self, *a):
                pass

            def _raw_body(self):
                """The request body, read once (do_POST reads it before taking a request slot). At most
                HTTP_MAX_BODY: a bigger one is refused there with 413, unread."""
                if not hasattr(self, "_body_bytes"):
                    try:
                        n = int(self.headers.get("Content-Length") or 0)
                    except ValueError:
                        n = 0
                    self._body_bytes = self.rfile.read(n) if 0 < n <= HTTP_MAX_BODY else b""
                return self._body_bytes

            def _https(self):
                """The browser reached us over HTTPS: a TLS proxy on a private address says so (X-Forwarded-Proto)."""
                if (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower() != "https":
                    return False
                try:
                    return ipaddress.ip_address(self.client_address[0].replace("::ffff:", "")).is_private
                except ValueError:
                    return False

            def _cross_site(self):
                """A POST another site's page sent (its Origin isn't this server): refused unless it's one of the
                public login endpoints. SameSite=Strict cookies already keep the admin session out of those; this is
                the second lock."""
                if self.path.split("?")[0] in CROSS_SITE_POSTS:
                    return False
                site = (self.headers.get("Sec-Fetch-Site") or "").lower()
                if site:                                    # (browsers say so even where Origin is "null": no-referrer)
                    return site == "cross-site"
                origin = self.headers.get("Origin")
                if origin is None:
                    return False                            # (not a browser's request: no cookie to misuse)
                host = urllib.parse.urlsplit(origin).netloc.lower()
                return host not in {(self.headers.get("Host") or "").lower()} | self._web_hosts()

            def _client_ip(self):
                """Who's asking: the connecting address, or behind a proxy on a private address, the address it says
                it forwarded for (X-Forwarded-For, last entry). Else everyone behind a proxy would share one lockout."""
                ip = self.client_address[0]
                fwd = (self.headers.get("X-Forwarded-For") or "").split(",")[-1].strip()
                if fwd:
                    try:
                        if ipaddress.ip_address(ip.replace("::ffff:", "")).is_private:
                            return str(ipaddress.ip_address(fwd))
                    except ValueError:
                        pass
                return ip

            def _ip_limited(self):
                """The per-address limits are for visitors' addresses: not the LAN's, nor a proxy's that doesn't pass
                on who it forwarded for (that would put everyone behind it under one limit)."""
                try:
                    a = ipaddress.ip_address(self._client_ip().replace("::ffff:", ""))
                except ValueError:
                    return True
                return not (a.is_loopback or a.is_link_local or any(a in n for n in LAN_NETS))

            def _ip_rate(self, what, limit, window=60.0):
                """Count one request of this kind from this address: 0 if within limit a window, else seconds to wait."""
                if not self._ip_limited():
                    return 0
                ip, now = self._client_ip(), time.monotonic()
                with flock:
                    q = recent_by_ip.setdefault((what, ip), collections.deque())
                    while q and now - q[0] >= window:
                        q.popleft()
                    if len(q) >= limit:
                        return max(1, int(q[0] + window - now + 1)) if q else int(window)
                    q.append(now)
                    if len(recent_by_ip) > 20000:           # (addresses gone quiet)
                        for k in [k for k, d in recent_by_ip.items() if not d or now - d[-1] >= window]:
                            del recent_by_ip[k]
                return 0

            def _locked_out(self):
                """Too many wrong passwords, keys or tickets from this address lately: 429, at once."""
                ip, now = self._client_ip(), time.monotonic()
                with flock:
                    q = failures.get(ip)
                    while q and now - q[0] >= FAIL_WINDOW_S:
                        q.popleft()
                    locked = bool(q) and len(q) >= FAIL_LIMIT
                if locked:
                    self.close_connection = True
                    self._send(429, '{"error":"too many failed attempts from your address: try again in a few minutes"}',
                               headers={"Retry-After": str(FAIL_WINDOW_S)})
                return locked

            def _penalty(self):
                """A wrong password, key or ticket: counted against this address (see _locked_out), and answered a
                second late, without holding a request slot meanwhile (else 16 bad guesses a second would turn
                everyone else away)."""
                ip, now = self._client_ip(), time.monotonic()
                with flock:
                    failures.setdefault(ip, collections.deque(maxlen=FAIL_LIMIT * 2)).append(now)
                    if len(failures) > 10000:               # (addresses gone quiet)
                        for k in [k for k, q in failures.items() if not q or now - q[-1] >= FAIL_WINDOW_S]:
                            del failures[k]
                slots.release()
                try:
                    time.sleep(1.0)
                finally:
                    slots.acquire()

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

            def _body(self):
                try:
                    return json.loads(self._raw_body() or b"{}")
                except ValueError:
                    return None

            def _tenant_admin(self, t):
                """A tenant room's page: its own login, or the main admin's."""
                if self._is_admin():
                    return True
                for part in (self.headers.get("Cookie") or "").split(";"):
                    k, _, v = part.strip().partition("=")
                    if k == "mr_tenant":
                        with slock:
                            e = tsessions.get(v)
                            if e is not None and e[0] >= time.monotonic() and e[1] == t.key:
                                return True
                return False

            def _tenant(self, t, sub, post):
                """Everything under /{path}/: the tenant's page and API, scoped to that room only."""
                path = sub.split("?")[0]
                key, base = t.key, "/%s/" % t.path
                if not post:
                    if path.startswith(("/static/", "/icons/")):
                        self.path = sub                         # shared files
                        return self._get()
                    if path in ("/", "/index.html"):
                        gz = "gzip" in (self.headers.get("Accept-Encoding") or "")
                        return self._send(200, tpage[1] if gz else tpage[0], "text/html; charset=utf-8", gz=gz,
                                          headers=DASHBOARD_HEADERS)
                    if path == "/api/session":
                        return self._send(200, json.dumps({"admin": self._tenant_admin(t), "login_enabled": True}))
                    if path == "/api/state":
                        t.web_last_request = time.monotonic()   # (the main loop refreshes it while it's being viewed)
                        deadline = time.monotonic() + 1.5
                        while not t.web_state and time.monotonic() < deadline:
                            time.sleep(0.02)
                        st = t.web_state
                        with clock_:
                            hit = tsnaps.get(key)
                            if hit is None or hit[0] is not st:
                                raw = json.dumps(st, default=str, separators=(",", ":")).encode()
                                hit = tsnaps[key] = (st, raw, gzip.compress(raw, 5))
                        gz = "gzip" in (self.headers.get("Accept-Encoding") or "")
                        return self._send(200, hit[2] if gz else hit[1], gz=gz)
                    if path == "/api/map":
                        gz = "gzip" in (self.headers.get("Accept-Encoding") or "")
                        return self._send(200, snap_bytes("web_map", gz), gz=gz)
                    if path == "/api/welcome":
                        if not self._tenant_admin(t):
                            return self._send(401, '{"error":"log in first"}')
                        return self._send(200, json.dumps({"welcome_new_members": bool(t.cfg.welcome_new_members),
                                                           "welcome_message": str(t.cfg.welcome_message),
                                                           "welcome_advert_hint": str(t.cfg.welcome_advert_hint)}))
                    if path == "/api/chat":
                        if not self._tenant_admin(t):
                            return self._send(401, '{"error":"log in first"}')
                        since = 0
                        for kv in sub.partition("?")[2].split("&"):
                            k, _, v = kv.partition("=")
                            if k == "since" and v.isdigit():
                                since = int(v)
                        msgs = [dict(ts=ts, who=t.chat_label(a), room=(a == t.id.pub_key), text=txt)
                                for ts, a, txt, to in list(t.posts) if to is None and ts > since]
                        return self._send(200, json.dumps({"messages": msgs, "max_bytes": MAX_POST_TEXT_LEN}))
                    return self._send(404, '{"error":"not found"}')
                parts = path.strip("/").split("/")
                if parts == ["api", "login"]:
                    body = self._body() or {}
                    if not check_web_password(str(body.get("password", "")), t.cfg.web_password_hash):
                        self._penalty()
                        return self._send(401, '{"error":"wrong password"}')
                    tok = secrets.token_hex(24)
                    with slock:
                        now_m = time.monotonic()
                        for k in [k for k, e in tsessions.items() if e[0] < now_m]:
                            del tsessions[k]
                        tsessions[tok] = (now_m + SESSION_S, key)
                    return self._send(200, '{"ok":true}', cookie="mr_tenant=%s; HttpOnly; SameSite=Strict; Path=%s; Max-Age=%d" % (tok, base, SESSION_S))
                if parts == ["api", "logout"]:
                    with slock:
                        for part in (self.headers.get("Cookie") or "").split(";"):
                            k, _, v = part.strip().partition("=")
                            if k == "mr_tenant":
                                tsessions.pop(v, None)
                    return self._send(200, '{"ok":true}', cookie="mr_tenant=; HttpOnly; SameSite=Strict; Path=%s; Max-Age=0" % base)
                if not self._tenant_admin(t):                   # everything below changes things: this room's admins only
                    return self._send(401, '{"error":"log in first"}')
                if parts == ["api", "advert"]:
                    body = self._body() or {}
                    with slock:
                        if time.monotonic() - t_last_advert.get(key, float("-inf")) < 10:
                            return self._send(429, '{"error":"an advert was just sent: wait a few seconds"}')
                        t_last_advert[key] = time.monotonic()
                    events.put(("t_advert", key, bool(body.get("flood"))))
                    return self._send(200, json.dumps({"ok": True, "flood": bool(body.get("flood")), "repeater": False}))
                if parts == ["api", "welcome"]:
                    try:
                        updates = welcome_changes(self._body(), t.cfg.name, t.cfg)
                    except ValueError as e:
                        return self._send(400, json.dumps({"error": str(e)}))
                    events.put(("t_welcome", key, updates))
                    return self._send(200, json.dumps({"ok": True, "updates": updates}))
                if parts == ["api", "location"]:
                    try:
                        lat, lon = tenant_location(self._body() or {})
                    except ValueError as e:
                        return self._send(400, json.dumps({"error": str(e)}))
                    events.put(("t_loc", key, lat, lon))
                    return self._send(200, json.dumps({"ok": True, "lat": lat, "lon": lon}))
                if parts == ["api", "chat"]:
                    text = str((self._body() or {}).get("text", "")).strip()
                    if not text:
                        return self._send(400, '{"error":"empty message"}')
                    if len(text.encode()) > MAX_POST_TEXT_LEN:
                        return self._send(400, json.dumps({"error": "too long: %d bytes max" % MAX_POST_TEXT_LEN}))
                    events.put(("t_say", key, text))
                    return self._send(200, '{"ok":true}')
                if len(parts) == 4 and parts[0] == "api" and (parts[1], parts[3]) in (
                        ("members", "kick"), ("members", "ban"), ("members", "resync"), ("members", "route"), ("bans", "unban")):
                    try:
                        pub = bytes.fromhex(parts[2])
                    except ValueError:
                        return self._send(400, '{"error":"bad key"}')
                    if len(pub) != 32:
                        return self._send(400, '{"error":"bad key"}')
                    if parts[3] == "route":
                        try:
                            reps = [(r.get("name") or "", r["hash"]) for r in (room.web_map or {}).get("repeaters", [])]
                            hops = resolve_route(str((self._body() or {}).get("path", "")), reps)
                        except ValueError as e:
                            return self._send(400, json.dumps({"error": str(e)}))
                        events.put(("t_act", key, "suggest", pub, hops))
                        return self._send(200, json.dumps({"ok": True, "hops": [h.hex().upper() for h in hops]}))
                    events.put(("t_act", key, parts[3], pub))   # applied to this room only, by the main loop
                    return self._send(200, '{"ok":true}')
                return self._send(404, '{"error":"not found"}')

            def _tenant_of(self):
                seg, _, rest = self.path.lstrip("/").partition("/")
                t = room.web_tenants.get(seg.split("?")[0]) if seg else None
                return t, rest

            def _send(self, code, body, ctype="application/json", cookie=None, gz=False, cache_s=0, headers=None):
                b = body if isinstance(body, bytes) else body.encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(b)))
                if gz:
                    self.send_header("Content-Encoding", "gzip")
                    self.send_header("Vary", "Accept-Encoding")
                self.send_header("Cache-Control", "public, max-age=%d" % cache_s if cache_s else "no-store")
                if code == 503:
                    self.send_header("Retry-After", "1")
                if cookie:
                    self.send_header("Set-Cookie", cookie + ("; Secure" if self._https() else ""))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                try:
                    self.wfile.write(b)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass                                    # the client hung up (health check, closed tab): nothing to do

            def do_GET(self):
                if self.path.startswith(("/icons/", "/static/")):
                    return self._get()                      # small, cacheable files: don't count toward the cap
                if self.path.split("?")[0] == KAAS_PATH:
                    return self._kaas()                     # a websocket: holds this thread, not a request slot
                if not slots.acquire(blocking=False):
                    return self._send(503, '{"error":"busy"}')    # flood guard: at most 16 requests at once
                try:
                    self._get()
                finally:
                    slots.release()

            def do_POST(self):
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    n = -1
                if not 0 <= n <= HTTP_MAX_BODY:
                    self.close_connection = True
                    return self._send(413 if n > 0 else 400, '{"error":"a request body is at most %d bytes"}' % HTTP_MAX_BODY)
                if self._locked_out():
                    return
                if self._cross_site():
                    return self._send(403, '{"error":"a request from another site"}')
                self._raw_body()                            # (before a slot: a slow body only holds its own thread)
                if not slots.acquire(blocking=False):
                    return self._send(503, '{"error":"busy"}')
                try:
                    self._post()
                finally:
                    slots.release()

            def _tokens(self, name):
                """A header's comma-separated tokens, lowercased, across every copy of it (a proxy may send two)."""
                return {t.strip().lower() for v in (self.headers.get_all(name) or []) for t in v.split(",")} - {""}

            def _kaas(self):
                """KaaS: upgrade to a websocket for an API key (Authorization: Bearer ...), or for a web login's
                one-time ?ticket= (browsers can't send Authorization on a websocket), then stream packets."""
                hub = room.kaas
                ticket = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("ticket", [""])[0]

                def refuse(code, error, outcome, why):
                    log.warning("websocket from %s refused (%d): %s", self.client_address[0], code, why)
                    if ticket:
                        hub.ticket_outcome(ticket, outcome)
                    return self._send(code, json.dumps({"error": error}))
                if "websocket" not in self._tokens("Upgrade") or "upgrade" not in self._tokens("Connection"):
                    return refuse(426, "a websocket endpoint: see docs/api.md", "no_upgrade",
                                  "no websocket upgrade in the request (Upgrade: %r, Connection: %r, %s): a reverse proxy "
                                  "in front of pyMeshRoom has to pass the Upgrade and Connection headers on" % (
                                      ", ".join(self.headers.get_all("Upgrade") or []),
                                      ", ".join(self.headers.get_all("Connection") or []), self.request_version))
                wkey = self.headers.get("Sec-WebSocket-Key") or ""
                if not wkey or self.headers.get("Sec-WebSocket-Version") != "13":
                    return refuse(400, "websocket version 13 only", "bad_version", "not a version 13 websocket "
                                  "(Sec-WebSocket-Version: %r)" % self.headers.get("Sec-WebSocket-Version"))
                if self._locked_out():
                    return
                wait = self._ip_rate("ws", IP_WS_PER_MIN)
                if wait:
                    return refuse(429, "too many connections from your address: try again in %d s" % wait, "too_many",
                                  "over %d websockets a minute from %s" % (IP_WS_PER_MIN, self._client_ip()))
                if not slots.acquire(blocking=False):
                    return refuse(503, "busy", "busy", "too many requests at once")
                try:
                    key, why = self._kaas_key(), None
                    if key is None and ticket:
                        key, why = hub.redeem(ticket)
                    if not hub.valid(key):
                        if why:
                            log.warning("websocket from %s refused (401): %s ticket", self.client_address[0], {
                                "unknown": "an unknown or already used", "expired": "an expired",
                                "refused": "web logins are off, or the key is banned: a"}[why])
                            hub.ticket_outcome(ticket, why)
                        self._penalty()
                        return self._send(401, '{"error":"missing, unknown, revoked or expired API key or ticket"}')
                    if key.get("web") and hub.web_ip_banned(self._client_ip()):
                        return refuse(403, "this address is banned from this server", "refused", "a banned address")
                    conn = KaasConn(hub, self.connection, self.rfile, key, self.client_address[0])
                    conn.ip = self._client_ip()
                    if conn.web and self._ip_limited() and hub.web_sessions_from(conn.ip) >= IP_WEB_SESSIONS:
                        return refuse(429, "at most %d web sessions from one address: close another tab" % IP_WEB_SESSIONS,
                                      "too_many", "%s has %d web sessions open" % (conn.ip, IP_WEB_SESSIONS))
                    if not hub.add(conn):
                        return refuse(503, "at most %d %s at once" % (
                            (int(cfg.web_max_clients), "web sessions") if conn.web else (KAAS_MAX_CLIENTS, "API clients")),
                            "full", "all %d %s are in use" % (
                                (int(cfg.web_max_clients), "web sessions") if conn.web else (KAAS_MAX_CLIENTS, "API clients")))
                    try:
                        self.protocol_version = "HTTP/1.1"  # (this upgrade only) an HTTP/1.0 101 isn't valid, and
                        self.send_response(101, "Switching Protocols")   # a proxy may refuse it or add Connection: close
                        self.send_header("Upgrade", "websocket")
                        self.send_header("Connection", "Upgrade")
                        self.send_header("Sec-WebSocket-Accept", ws_accept(wkey))
                        self.end_headers()
                        self.close_connection = True
                        conn.send_json(hub.hello(key))
                    except BaseException:
                        hub.drop(conn)                      # (the peer hung up mid-upgrade: its slot isn't kept)
                        raise
                    self.connection.settimeout(None)            # (an open websocket: its pings keep watch)
                    if ticket:
                        hub.ticket_outcome(ticket, "connected")
                    if not conn.web:
                        events.put(("kaas_used", key["id"], now_s()))
                finally:
                    slots.release()
                log.info("API client %s connected (key %s)", self.client_address[0], key["id"])
                conn.run()
                log.info("API client %s disconnected (key %s)", self.client_address[0], key["id"])

            def _kaas_key(self):
                auth = self.headers.get("Authorization") or ""
                return room.kaas.find(auth[7:].strip()) if auth[:7].lower() == "bearer " else None

            def _web_hosts(self):
                """The host names a web login may be signed for: this server's own address as this connection reached
                it (ip:port), and the names the admin lists in web_hosts (a domain, or a proxy's). Never the request's
                Host header by itself: another server could relay its visitors' logins here under its own name."""
                hosts = {str(h).strip().lower() for h in (cfg.web_hosts or [])}
                ip, port = self.connection.getsockname()[:2]
                ip = ip[7:] if ip.startswith("::ffff:") else ip
                names = [("[%s]" % ip) if ":" in ip else ip] + (["localhost"] if ip in ("127.0.0.1", "::1") else [])
                for n in names:
                    hosts.add("%s:%d" % (n, port))
                    if port in (80, 443):
                        hosts.add(n)
                hosts.discard("")
                return hosts

            def _page_unlocked(self):
                """MeshCore Web's page password: none set, or this browser has a page session made under it."""
                h = cfg.web_page_password
                if not h:
                    return True
                for part in (self.headers.get("Cookie") or "").split(";"):
                    k, _, v = part.strip().partition("=")
                    if k == "mr_web" and web_page_session_ok(v, h):
                        return True
                return False

            def _page_password_ok(self, pw):
                if self._page_unlocked():
                    return True
                if pw and check_web_password(str(pw), cfg.web_page_password):
                    return True
                self._penalty()
                return False

            def _web_unlock_page(self, error=""):
                msg = '<p class="err">%s</p>' % error if error else ""
                html = WEB_UNLOCK_HTML.replace("{error}", msg)
                return self._send(401 if error else 200, html, "text/html; charset=utf-8",
                                  headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                           "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
                                           "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"})

            def _web_unlock(self):
                """POST /meshcore-web/unlock: the page password, from the form. Right: a page session (cookie), then
                the app; wrong: the form again, after a second."""
                n = int(self.headers.get("Content-Length") or 0)
                form = urllib.parse.parse_qs(self._raw_body()[:4096].decode(errors="replace")) if n else {}
                pw = (form.get("password") or [""])[0]
                if not cfg.web_page_password or not check_web_password(pw, cfg.web_page_password):
                    self._penalty()
                    return self._web_unlock_page("That isn't the password." if cfg.web_page_password else "")
                tok = web_page_session(cfg.web_page_password)
                self.send_response(303)
                self.send_header("Location", "./")
                self.send_header("Set-Cookie", "mr_web=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d%s" % (
                    tok, WEB_PAGE_SESSION_S, "; Secure" if self._https() else ""))
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _web_public(self, path):
                """POST /api/v1/web/challenge and /api/v1/web/login: logging in to MeshCore Web by signing with the
                node's private key, which never leaves the browser. Any origin may ask (CORS: *); no cookies."""
                cors = {"Access-Control-Allow-Origin": "*"}
                body = self._body()
                if room.kaas.web_ip_banned(self._client_ip()):
                    return self._send(403, '{"error":"this address is banned from this server"}', headers=cors)
                if cfg.web_login and not self._page_password_ok((body or {}).get("page_password")):
                    return self._send(401, json.dumps({"error": "MeshCore Web on this server has a password",
                                                       "page_password": True}), headers=cors)
                if path.endswith("/challenge"):
                    if not cfg.web_login:
                        return self._send(403, '{"error":"web logins are off on this server"}', headers=cors)
                    wait = self._ip_rate("login", IP_LOGINS_PER_MIN)
                    if wait:
                        return self._send(429, json.dumps({"error": "too many logins from your address: try again in "
                                                                    "%d s" % wait, "retry_after": wait}),
                                          headers=dict(cors, **{"Retry-After": str(wait)}))
                    ch = room.kaas.new_challenge()
                    if ch is None:
                        return self._send(503, '{"error":"too many logins at once: try again shortly"}', headers=cors)
                    return self._send(200, json.dumps({"challenge": ch, "expires_in": WEB_CHALLENGE_S,
                                                       "label": WEB_LOGIN_LABEL}), headers=cors)
                code, answer = room.kaas.web_login(body, self._web_hosts(), self._client_ip())
                if code == 200:
                    log.info("web login %s (%s) from %s: %s", answer["state"], (body or {}).get("pub", "")[:8],
                             self.client_address[0], (body or {}).get("name", ""))
                return self._send(code, json.dumps(answer), headers=cors)

            def _web_ticket(self):
                """POST /api/v1/web/ticket {"ticket"}: what became of a web login's websocket, for a browser whose
                websocket didn't open (it can't see why itself). The ticket is the credential (CORS: *)."""
                body = self._body()
                ticket = str((body or {}).get("ticket", "")) if isinstance(body, dict) else ""
                return self._send(200, json.dumps({"outcome": room.kaas.ticket_status(ticket)}),
                                  headers={"Access-Control-Allow-Origin": "*"})

            def do_OPTIONS(self):
                """CORS preflight, for the web login endpoints only."""
                if self.path.split("?")[0] not in (WEB_PATH + "/challenge", WEB_PATH + "/login", WEB_PATH + "/ticket"):
                    return self._send(404, '{"error":"not found"}')
                self._send(204, b"", headers={"Access-Control-Allow-Origin": "*",
                                              "Access-Control-Allow-Methods": "POST",
                                              "Access-Control-Allow-Headers": "Authorization, Content-Type",
                                              "Access-Control-Allow-Private-Network": "true",
                                              "Access-Control-Max-Age": "600"})

            def _get(self):
                t, rest = self._tenant_of()
                if t is not None:
                    if "/" not in self.path.lstrip("/"):            # /path -> /path/ (the page uses relative URLs)
                        self.send_response(301)
                        self.send_header("Location", "/%s/" % t.path)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    return self._tenant(t, "/" + rest, False)
                path = self.path.split("?")[0]
                if path == "/api/tenants":
                    if not self._is_admin():
                        return self._send(401, '{"error":"log in first"}')
                    return self._send(200, json.dumps({"rooms": room.web_tenant_rows, "max": TENANT_MAX}))
                if path == "/api/session":
                    return self._send(200, json.dumps({"admin": self._is_admin(), "login_enabled": bool(cfg.web_password)}))
                if path == WEB_PATH + "/users":
                    if not self._is_admin():
                        return self._send(401, '{"error":"log in first"}')
                    hub = room.kaas
                    return self._send(200, json.dumps({
                        "enabled": bool(cfg.web_login), "unknown_key_message": str(cfg.web_unknown_key_message or ""),
                        "motd_enabled": bool(cfg.web_motd_enabled), "motd": str(cfg.web_motd or ""),
                        "hosts": [str(h) for h in (cfg.web_hosts or [])],
                        "refused_hosts": [dict(host=h, count=v[0], last=v[1]) for h, v in list(hub.refused_hosts.items())
                                          if h not in [str(x).lower() for x in (cfg.web_hosts or [])]],
                        "page_password": bool(cfg.web_page_password), "giphy_key": bool(cfg.web_giphy_key),
                        "backlog": hub.backlog_info(),
                        "max": int(cfg.web_max_clients), "connected": sum(1 for c in hub.conns if c.web),
                        "users": hub.web_rows(), "banned": [b for b in (cfg.web_banned or []) if isinstance(b, dict)],
                        "banned_ips": [b for b in (cfg.web_banned_ips or []) if isinstance(b, dict)]}))
                if path == KAAS_PATH + "/keys":
                    if not self._is_admin():
                        return self._send(401, '{"error":"log in first"}')
                    hub = room.kaas
                    return self._send(200, json.dumps({"keys": hub.key_rows(), "path": KAAS_PATH, "max": KAAS_MAX_KEYS,
                                                       "send_burst": int(cfg.kaas_send_burst),
                                                       "send_window_s": float(cfg.kaas_send_window_s),
                                                       "airtime_pct": room.air.rates()[1]["kaas"] * 100.0,
                                                       "stats": dict(hub.stats)}))
                if path.startswith("/static/"):
                    # files in data_dir/static (e.g. a local copy of Leaflet); Leaflet falls back to the CDN
                    root = os.path.realpath(os.path.join(cfg.data_dir, "static"))
                    f = os.path.realpath(os.path.join(root, path[8:]))
                    if f.startswith(root + os.sep) and os.path.isfile(f):
                        ctype = {".js": "application/javascript", ".css": "text/css", ".png": "image/png",
                                 ".svg": "image/svg+xml"}.get(os.path.splitext(f)[1], "application/octet-stream")
                        compress = ctype in ("application/javascript", "text/css", "image/svg+xml")
                        _, raw, gzd = cached_file(f, compress)
                        gz = gzd is not None and "gzip" in (self.headers.get("Accept-Encoding") or "")
                        return self._send(200, gzd if gz else raw, ctype, cache_s=86400, gz=gz)
                    if path[8:] in ("leaflet.js", "leaflet.css") or path[8:].startswith("images/"):
                        self.send_response(302)
                        self.send_header("Location", "https://unpkg.com/leaflet@1.9.4/dist/" + path[8:])
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    return self._send(404, '{"error":"not found"}')
                if path.startswith("/icons/"):
                    name = path[7:].split(".")[0]
                    if name in ICON_NAMES:
                        f = dashboard_icon_file(cfg.data_dir, name)
                        if f:
                            return self._send(200, cached_file(f, False)[1], "image/png", cache_s=86400)   # PNG: already compressed
                        return self._send(200, BUILTIN_ICONS[name], "image/svg+xml", cache_s=86400)
                    return self._send(404, '{"error":"not found"}')
                if path in ("/", "/index.html"):
                    gz = "gzip" in (self.headers.get("Accept-Encoding") or "")
                    return self._send(200, page[1] if gz else page[0], "text/html; charset=utf-8", gz=gz,
                                      headers=DASHBOARD_HEADERS)
                if path == "/meshcore-web":
                    self.send_response(301)                     # (the page works out the server from its own address)
                    self.send_header("Location", "meshcore-web/")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if path in ("/meshcore-web/", "/meshcore-web/index.html"):
                    if not self._page_unlocked():
                        return self._web_unlock_page()
                    if not os.path.isfile(MESHCORE_WEB_FILE):
                        return self._send(404, '{"error":"MeshCore Web isn\'t built: run node build.mjs in web/"}')
                    _, raw, gzd = cached_file(MESHCORE_WEB_FILE, True)
                    gz = "gzip" in (self.headers.get("Accept-Encoding") or "")
                    return self._send(200, gzd if gz else raw, "text/html; charset=utf-8", gz=gz,
                                      headers={"Content-Security-Policy": "frame-ancestors 'none'",   # it holds a key:
                                               "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
                                               "Referrer-Policy": "no-referrer"})                 # never framed
                if path == "/api/state":
                    note_viewer(self.path.partition("?")[2], self._is_admin())
                    fresh = time.monotonic() - room.web_last_request > 20
                    room.web_last_request = time.monotonic()        # wakes up the main loop's refreshes
                    if fresh:
                        before = room.web_state
                        events.put(("web_wake",))                   # first view after idle: refresh right away...
                        deadline = time.monotonic() + 1.5
                        while room.web_state is before and time.monotonic() < deadline:
                            time.sleep(0.02)                        # ...and answer with it, not the stale one
                    gz = "gzip" in (self.headers.get("Accept-Encoding") or "")
                    return self._send(200, snap_bytes("web_state", gz), gz=gz)
                if path == "/api/observer/stats":
                    if not self._is_admin():
                        return self._send(401, '{"error":"log in first"}')
                    if room.observer is None:
                        return self._send(200, '{"available":false}')
                    snapshot = room.observer.statistics()
                    snapshot["available"] = True
                    return self._send(200, json.dumps(snapshot))
                if path == "/api/map":
                    room.web_last_request = time.monotonic()
                    if not room.web_map:
                        events.put(("web_wake",))
                        deadline = time.monotonic() + 3
                        while not room.web_map and time.monotonic() < deadline:
                            time.sleep(0.05)
                    gz = "gzip" in (self.headers.get("Accept-Encoding") or "")
                    return self._send(200, snap_bytes("web_map", gz), gz=gz)
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
                if path == "/api/companion":
                    if not self._is_admin():
                        return self._send(401, '{"error":"log in first"}')
                    return self._send(200, json.dumps(room.web_vc_admin))
                if path == "/api/welcome":
                    if not self._is_admin():
                        return self._send(401, '{"error":"log in first"}')
                    return self._send(200, json.dumps({
                        "welcome_new_members": bool(cfg.welcome_new_members),
                        "welcome_message": str(cfg.welcome_message),
                        "welcome_advert_hint": str(cfg.welcome_advert_hint),
                        "max_bytes": MAX_POST_TEXT_LEN,
                    }))
                self._send(404, '{"error":"not found"}')

            def _post(self):
                t, rest = self._tenant_of()
                if t is not None:
                    return self._tenant(t, "/" + rest, True)
                if self.path.split("?")[0] == WEB_PATH + "/ticket":
                    return self._web_ticket()
                if self.path.split("?")[0] in (WEB_PATH + "/challenge", WEB_PATH + "/login"):
                    return self._web_public(self.path.split("?")[0])
                if self.path.split("?")[0] == "/meshcore-web/unlock":
                    return self._web_unlock()
                parts = self.path.strip("/").split("/")
                if parts == ["api", "login"]:
                    if not cfg.web_password:
                        return self._send(403, '{"error":"admin login is off: set web_password in the config"}')
                    try:
                        body = json.loads(self._raw_body() or b"{}")
                    except ValueError:
                        body = {}
                    if not hmac.compare_digest(str(body.get("password", "")).encode(), str(cfg.web_password).encode()):
                        self._penalty()
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
                if parts == ["api", "v1", "kaas", "keys"]:
                    if len(room.kaas.keys()) >= KAAS_MAX_KEYS:
                        return self._send(409, json.dumps({"error": "the limit is %d API keys" % KAAS_MAX_KEYS}))
                    try:
                        spec = kaas_key_spec(self._body())
                    except ValueError as e:
                        return self._send(400, json.dumps({"error": str(e)}))
                    token, entry = room.kaas.new_key(spec)
                    events.put(("kaas_key_add", entry))             # saved (hash only) by the main loop
                    return self._send(200, json.dumps({"ok": True, "id": entry["id"], "token": token}))
                if parts == ["api", "v1", "web", "settings"]:
                    body = self._body() or {}
                    change = {k: body[k] for k in ("web_login",) if isinstance(body.get(k), bool)}
                    if "web_hosts" in body:
                        hl = body["web_hosts"]
                        if not isinstance(hl, list) or len(hl) > 16 or not all(
                                isinstance(h, str) and re.fullmatch(r"[A-Za-z0-9.\-:\[\]]{1,100}", h.strip()) for h in hl):
                            return self._send(400, '{"error":"host names: up to 16, like mesh.example.com or 10.0.0.5:8081"}')
                        change["web_hosts"] = sorted({h.strip().lower() for h in hl})
                    if "motd_enabled" in body and isinstance(body["motd_enabled"], bool):
                        change["web_motd_enabled"] = body["motd_enabled"]
                    if "motd" in body:
                        t = body["motd"]
                        if not isinstance(t, str) or len(t) > 1000:
                            return self._send(400, '{"error":"the message of the day: at most 1000 characters"}')
                        change["web_motd"] = t.replace("\r\n", "\n").strip()
                    if "unknown_key_message" in body:
                        t = body["unknown_key_message"]
                        if not isinstance(t, str) or not t.strip() or len(t) > 200:
                            return self._send(400, '{"error":"the unknown key message: 1 to 200 characters"}')
                        change["web_unknown_key_message"] = " ".join(t.split())
                    if "page_password" in body:
                        pw = body["page_password"]
                        if not isinstance(pw, str) or (pw and not 4 <= len(pw) <= 64):
                            return self._send(400, '{"error":"page password: 4 to 64 characters, or empty for none"}')
                        change["web_page_password"] = hash_web_password(pw) if pw else ""   # (hashed here: never stored)
                    if "giphy_key" in body:
                        k = body["giphy_key"]
                        if not isinstance(k, str) or not re.fullmatch(r"[A-Za-z0-9]{0,64}", k.strip()):
                            return self._send(400, '{"error":"a Giphy API key is letters and digits"}')
                        change["web_giphy_key"] = k.strip()
                    if "web_backlog_mqtt" in body and isinstance(body["web_backlog_mqtt"], bool):
                        change["web_backlog_mqtt"] = body["web_backlog_mqtt"]
                    if "web_backlog_days" in body:
                        n = body["web_backlog_days"]
                        if isinstance(n, bool) or not isinstance(n, int) or n < 0:
                            return self._send(400, '{"error":"backlog days: a whole number, 0 for none"}')
                        change["web_backlog_days"] = n
                    if "web_max_clients" in body:
                        n = body["web_max_clients"]
                        if isinstance(n, bool) or not isinstance(n, int) or not 0 <= n <= 256:
                            return self._send(400, '{"error":"web_max_clients: 0 to 256"}')
                        change["web_max_clients"] = n
                    if not change:
                        return self._send(400, '{"error":"nothing to change"}')
                    events.put(("kaas_web_admin", "settings", change))
                    return self._send(200, '{"ok":true}')
                if len(parts) == 6 and parts[:4] == ["api", "v1", "web", "users"] and \
                        parts[5] in ("allow", "unallow", "kick", "ban", "unban", "purge", "delete"):
                    try:
                        pub = bytes.fromhex(parts[4])
                    except ValueError:
                        pub = b""
                    if len(pub) != PUB_KEY_SIZE:
                        return self._send(400, '{"error":"a 32-byte public key in hex"}')
                    body = self._body() or {}
                    name = str(body.get("name", ""))[:32]
                    if parts[5] == "ban":
                        by_key, by_ip = body.get("key", True) is not False, body.get("ip") is True
                        ip = room.kaas.wusers.get(pub.hex(), {}).get("ip") if by_ip else None
                        if by_ip and not ip:
                            return self._send(400, '{"error":"no address is known for that key"}')
                        if not (by_key or by_ip):
                            return self._send(400, '{"error":"ban the key, the address, or both"}')
                        if by_ip:
                            events.put(("kaas_web_admin", "ban_ip", ip, name))
                        if by_key:
                            events.put(("kaas_web_admin", "ban", pub.hex(), name))
                        return self._send(200, json.dumps({"ok": True, "ip": ip}))
                    events.put(("kaas_web_admin", parts[5], pub.hex(), name))
                    return self._send(200, '{"ok":true}')
                if parts[:4] == ["api", "v1", "web", "ips"] and len(parts) == 6 and parts[5] in ("ban", "unban"):
                    try:
                        ip = str(ipaddress.ip_address(urllib.parse.unquote(parts[4])))
                    except ValueError:
                        return self._send(400, '{"error":"an IP address"}')
                    events.put(("kaas_web_admin", parts[5] + "_ip", ip, str((self._body() or {}).get("name", ""))[:32]))
                    return self._send(200, '{"ok":true}')
                if len(parts) == 6 and parts[:4] == ["api", "v1", "kaas", "keys"] and parts[5] == "revoke":
                    if room.kaas.key_by_id(parts[4]) is None:
                        return self._send(404, '{"error":"no such key"}')
                    events.put(("kaas_key_del", parts[4]))          # removed, and its connections closed, by the main loop
                    return self._send(200, '{"ok":true}')
                if parts == ["api", "tenants"]:
                    if len(room.web_tenants) >= TENANT_MAX:
                        return self._send(409, json.dumps({"error": "the limit is %d tenant rooms" % TENANT_MAX}))
                    keys = {x.id.pub_key for x in room.web_tenants.values()} | room.own_node_keys()
                    try:
                        spec = tenant_spec(self._body(), set(room.web_tenants), keys)
                    except ValueError as e:
                        return self._send(400, json.dumps({"error": str(e) or "bad request"}))
                    events.put(("t_create", spec))                  # created by the main loop
                    return self._send(200, json.dumps({"ok": True, "path": spec["path"]}))
                if len(parts) == 4 and parts[:2] == ["api", "tenants"] and parts[3] == "location":
                    key = parts[2].upper()
                    if not any(x.key == key for x in room.web_tenants.values()):
                        return self._send(404, '{"error":"no such tenant room"}')
                    try:
                        lat, lon = tenant_location(self._body() or {})
                    except ValueError as e:
                        return self._send(400, json.dumps({"error": str(e)}))
                    events.put(("t_loc", key, lat, lon))
                    return self._send(200, json.dumps({"ok": True, "lat": lat, "lon": lon}))
                if len(parts) == 4 and parts[:2] == ["api", "tenants"] and parts[3] in ("delete", "password"):
                    key = parts[2].upper()
                    if not any(x.key == key for x in room.web_tenants.values()):
                        return self._send(404, '{"error":"no such tenant room"}')
                    body = self._body() or {}
                    if parts[3] == "delete":
                        if not hmac.compare_digest(str(body.get("password", "")).encode(), str(cfg.web_password).encode()):
                            self._penalty()
                            return self._send(403, '{"error":"wrong admin password: the room was not deleted"}')
                        events.put(("t_delete", key))
                    else:
                        pw = str(body.get("web_password", ""))
                        if len(pw) < 6:
                            return self._send(400, '{"error":"web UI password: at least 6 characters"}')
                        events.put(("t_webpw", key, hash_web_password(pw)))
                    with slock:                                 # either way, its logged-in sessions end now
                        for k in [k for k, e in tsessions.items() if e[1] == key]:
                            del tsessions[k]
                    return self._send(200, '{"ok":true}')
                if parts == ["api", "observer"]:
                    try:
                        body = json.loads(self._raw_body() or b"{}")
                    except ValueError:
                        return self._send(400, '{"error":"invalid JSON"}')
                    bool_keys = ("observer_enabled", "observer_status", "observer_packets", "observer_rx",
                                 "observer_gomesh", "observer_meshmapper")
                    updates = {}
                    for key in bool_keys:
                        if key in body:
                            if not isinstance(body[key], bool):
                                return self._send(400, json.dumps({"error": "%s must be true or false" % key}))
                            updates[key] = body[key]
                    if "observer_iata" in body:
                        iata = str(body["observer_iata"]).strip().upper()
                        if iata and not valid_iata(iata):
                            return self._send(400, '{"error":"IATA must be exactly three letters"}')
                        updates["observer_iata"] = iata
                    if "observer_identity" in body:
                        who = str(body["observer_identity"] or "")
                        if who and who not in {c["id"] for c in room.observer_choices()}:
                            return self._send(400, '{"error":"choose the virtual repeater or one of the rooms"}')
                        updates["observer_identity"] = who
                    if updates.get("observer_enabled", cfg.observer_enabled) and \
                            updates.get("observer_identity", cfg.observer_identity) not in \
                            {c["id"] for c in room.observer_choices()}:
                        return self._send(400, '{"error":"choose who the observer reports as first: the virtual '
                                               'repeater or a room (with neither, it can\'t be enabled)"}')
                    if updates.get("observer_enabled", cfg.observer_enabled) and \
                            not valid_iata(updates.get("observer_iata", cfg.observer_iata)):
                        return self._send(400, '{"error":"set the IATA region code first: your nearest airport, like '
                                               'SJC (everything the observer publishes is filed under it)"}')
                    if "observer_queue_max" in body:
                        qmax = body["observer_queue_max"]
                        if isinstance(qmax, bool) or not isinstance(qmax, int) or not 10 <= qmax <= 10000:
                            return self._send(400, '{"error":"queue maximum must be an integer from 10 to 10000"}')
                        updates["observer_queue_max"] = qmax
                    if "observer_servers" in body:
                        try:
                            updates["observer_servers"] = observer_servers_changes(body["observer_servers"])
                        except ValueError as e:
                            return self._send(400, json.dumps({"error": str(e)}))
                    if not updates:
                        return self._send(400, '{"error":"no observer settings supplied"}')
                    events.put(("observer_config", updates))     # persisted and applied by the main loop
                    return self._send(200, json.dumps({"ok": True, "updates": updates}))
                if parts == ["api", "welcome"]:                # (the default for rooms without their own)
                    try:
                        updates = welcome_changes(json.loads(self._raw_body() or b"{}"), cfg.name, cfg)
                    except ValueError as e:
                        return self._send(400, json.dumps({"error": str(e)}))
                    events.put(("welcome_config", updates))      # main loop persists updates before a member can receive them
                    return self._send(200, json.dumps({"ok": True, "updates": updates}))
                if parts == ["api", "mqtt"]:
                    try:
                        body = json.loads(self._raw_body() or b"{}")
                        ch = mqtt_changes(body)
                    except (ValueError, TypeError) as e:
                        return self._send(400, json.dumps({"error": str(e) or "bad request"}))
                    if not ch:
                        return self._send(400, '{"error":"nothing to change"}')
                    events.put(("mqtt_cfg", ch))                    # applied (and saved) by the main loop
                    return self._send(200, json.dumps({"ok": True, "changed": list(ch)}))
                if parts == ["api", "airtime"]:
                    try:
                        ch = airtime_changes(json.loads(self._raw_body() or b"{}"))
                    except ValueError as e:
                        return self._send(400, json.dumps({"error": str(e) or "bad request"}))
                    if not ch:
                        return self._send(400, '{"error":"nothing to change"}')
                    events.put(("air_cfg", ch))                     # applied (and saved) by the main loop
                    return self._send(200, json.dumps({"ok": True, "changed": list(ch)}))
                if parts == ["api", "repeater"]:
                    try:
                        body = json.loads(self._raw_body() or b"{}")
                        if "private_key" in body and room.cfg.repeater_enabled:
                            return self._send(409, '{"error":"disable the virtual repeater before importing a private key"}')
                        ch = repeater_changes(body)
                    except ValueError as e:
                        return self._send(400, json.dumps({"error": str(e) or "bad request"}))
                    if not ch:
                        return self._send(400, '{"error":"nothing to change"}')
                    events.put(("rpt_cfg", ch))                     # applied (and saved) by the main loop
                    return self._send(200, json.dumps({"ok": True, "changed": list(ch)}))
                if parts == ["api", "companion"]:
                    try:
                        body = json.loads(self._raw_body() or b"{}")
                        if room.cfg.companion_enabled and set(body) - {"enabled"}:
                            return self._send(409, '{"error":"turn the virtual companion off to change its settings"}')
                        ch = companion_changes(body)
                    except ValueError as e:
                        return self._send(400, json.dumps({"error": str(e) or "bad request"}))
                    if not ch:
                        return self._send(400, '{"error":"nothing to change"}')
                    events.put(("vc_cfg", ch))                      # applied (and saved) by the main loop
                    return self._send(200, json.dumps({"ok": True, "changed": list(ch)}))
                if parts == ["api", "advert"]:
                    try:
                        body = json.loads(self._raw_body() or b"{}")
                    except ValueError:
                        body = {}
                    flood, node = bool(body.get("flood")), str(body.get("node") or "repeater")
                    if node not in ("repeater", "companion"):
                        return self._send(400, '{"error":"node: repeater or companion (rooms advertise from their page)"}')
                    if not (room.web_state.get(node) or {}).get("enabled"):
                        return self._send(409, json.dumps({"error": "the virtual %s is off" % node}))
                    with slock:
                        if time.monotonic() - last_advert[0] < 10:
                            return self._send(429, '{"error":"an advert was just sent: wait a few seconds"}')
                        last_advert[0] = time.monotonic()
                    events.put(("advert", flood, node))             # sent by the main loop
                    return self._send(200, json.dumps({"ok": True, "flood": flood, "node": node}))
                if parts == ["api", "chat"]:
                    return self._send(404, '{"error":"the server isn\'t a room: post from a Room\'s page"}')
                    return self._send(200, '{"ok":true}')
                if len(parts) == 4 and parts[:2] == ["api", "members"] and parts[3] == "route":
                    try:
                        pub = bytes.fromhex(parts[2])
                        body = json.loads(self._raw_body() or b"{}")
                        reps = [(r.get("name") or "", r["hash"]) for r in (room.web_map or {}).get("repeaters", [])]
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
            def process_request(self, request, client_address):
                if threading.active_count() >= HTTP_MAX_THREADS:   # (a flood of connections: refuse, don't spawn)
                    self.shutdown_request(request)
                    return
                super().process_request(request, client_address)

            def handle_error(self, request, client_address):
                # clients disconnecting early is routine: no traceback. Anything else is logged briefly.
                exc = sys.exc_info()[1]
                if isinstance(exc, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError)):
                    return
                log.warning("dashboard request from %s failed: %r", client_address[0], exc)

        self.server = Server((cfg.web_bind, int(cfg.web_port)), H)
        self.file_stats = stats_                            # (disk reads of cached files: for checking the cache)
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
    room.companion_apply()                                  # (its TCP port needs the event queue)
    room.tenants_load()
    observer = None

    def start_observer():
        """Start the optional worker without allowing its failure to stop MeshRoom."""
        nonlocal observer
        if observer or not cfg.observer_enabled:
            return
        if not valid_iata(cfg.observer_iata):
            log.error("MQTT observer not started: set its IATA region code (your nearest airport, like SJC) on the "
                      "dashboard's Observer card")
            return
        who = room.observer_who()
        if who is None:
            log.error("MQTT observer not started: choose who it reports as (the virtual repeater, or a room) on the "
                      "dashboard's Observer card")
            return
        try:
            # Kept optional: installations that do not opt in never import
            # paho-mqtt and retain their existing MeshRoom behavior.
            from meshroom_observer import ObserverBridge
            observer = ObserverBridge(cfg, who[0], name=who[1])
            room.observer = observer
            log.info("MQTT observer enabled for %s, as %s (%s)", observer.iata, who[1], hexs(who[0].pub_key[:4]))
        except Exception as e:
            # An observer failure must never prevent the radio room from
            # starting.  The error is visible in the normal MeshRoom log.
            log.error("MQTT observer disabled: %s", e)
    def observer_sync():
        """Stop the observer when it's turned off or its identity changed or went away; start it as the chosen one."""
        nonlocal observer
        who = room.observer_who() if cfg.observer_enabled else None
        if observer and (who is None or observer.public_key != hexs(who[0].pub_key) or observer.origin != who[1]):
            observer.close()
            observer = room.observer = None
            log.info("MQTT observer stopped%s", "" if who is None else ": now reporting as %s" % who[1])
        if who is not None and not observer:
            start_observer()
    start_observer()
    room.mqtt_apply()
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
    log.info("host %r, public key %s, %d room(s)", cfg.name, hexs(identity.pub_key), len(room.tenants))

    def stop(*_):
        events.put(("quit",))
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, stop)                  # terminal / SSH session closed: save and exit cleanly

    def handle(ev):
        """One event. Returns False to stop."""
        nonlocal observer
        kind = ev[0]
        if kind == "rx":
            room.on_rx(*ev[1:])
            if observer:
                # This is deliberately after normal packet handling and is
                # strictly a bounded, non-blocking queue handoff.
                observer.submit_rx(*ev[1:])
        elif kind == "txdone":
            room.on_txdone(ev[1])
        elif kind == "hw":
            room.on_hw(ev[1], ev[2])
        elif kind in ("kick", "ban", "unban", "resync"):
            getattr(room, "force_resync" if kind == "resync" else kind)(ev[1])
            room.web_dirty = True                           # refresh the dashboard once the radio is idle
        elif kind == "advert":
            room.dashboard_advert(ev[1], ev[2] if len(ev) > 2 else "repeater")
        elif kind == "say":
            room.room_say(ev[1])
        elif kind == "suggest":
            room.suggest_route(ev[1], ev[2])
            room.web_dirty = True
        elif kind == "obs":
            room.observer_event(ev)
        elif kind == "mqtt_cfg":
            reconnect = any(k in ("mqtt_username", "mqtt_password", "mqtt_host", "mqtt_port", "mqtt_transport", "mqtt_ws_path", "mqtt_tls", "mqtt_tls_verify", "mqtt_topics") for k in ev[1])
            for k, v in ev[1].items():
                room.cfg.set(k, v)                          # saved to the config file, in place
            room.mqtt_apply(restart=reconnect)
            room.web_dirty = True
        elif kind == "air_cfg":
            for k, v in ev[1].items():
                room.cfg.set(k, v)
            room.web_dirty = True
        elif kind == "rpt_cfg":
            for k, v in ev[1].items():
                room.cfg.set(k, v)
            room.repeater_apply()
            observer_sync()                                 # (it may report as the repeater)
            room.web_dirty = True
        elif kind in ("vc_cmd", "vc_conn", "vc_disc", "vc_cfg"):
            room.companion_event(ev)
        elif kind.startswith("t_"):
            room.tenant_event(ev)
            if kind == "t_delete":
                observer_sync()                             # (it may report as that room)
        elif kind.startswith("kaas_"):
            room.kaas.event(ev)
        elif kind == "web_wake":
            room.web_dirty = True
            room.next_map = 0.0                             # first view after idle: the map part too
        elif kind == "observer_config":
            for key, value in ev[1].items():
                cfg.set(key, value)
            observer_sync()
            if observer:
                observer.refresh()                            # worker owns all network lifecycle changes
            room.web_dirty = True
        elif kind == "welcome_config":
            for key, value in ev[1].items():
                cfg.set(key, value)
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
            # MQTT ingestion has its own bounded queue so a broker burst cannot
            # grow the serial/main event queue without limit.  Drain a bounded
            # slice here, after radio/UI events have had priority.
            if running and room.feed:
                for _ in range(32):
                    ev = room.feed.pop()
                    if ev is None:
                        break
                    running = handle(ev)
                    if not running:
                        break
            if running:
                room.run_once()                             # push scheduler, transmit queue, periodic jobs
        except Exception:
            log.exception("main loop")
    log.info("shutting down: saving state")
    room.kaas.close_all()
    if room.feed:
        room.feed.stop()                                    # stop inbound producer before serial/state teardown
    room.flush()
    room.flush_topology()
    if room.vc is not None:
        room.vc.close()                                     # saves its contacts, closes its TCP port
    for t in room.tenants.values():
        t.close()
    if observer:
        observer.close()
    store.close()                                           # waits for the writer thread to finish
    modem.close()


if __name__ == "__main__":
    main()
