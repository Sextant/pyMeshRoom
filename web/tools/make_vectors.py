#!/usr/bin/env python3
"""Writes test/vectors.json from pyMeshRoom's Python client (the reference): python3 web/tools/make_vectors.py"""
import hashlib
import hmac
import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "client"))
from meshroom_kaas import Identity, Packet, channel_hash, hashtag_channel_key  # noqa: E402
from meshroom_kaas import crypto  # noqa: E402
from meshroom_kaas.packet import PT_ADVERT, PT_GRP_TXT  # noqa: E402

seed = bytes(range(32))
ident = Identity(seed)
ident2 = Identity(hashlib.sha256(b"second").digest() * 2)       # a 64-byte key as given (not from a seed)
msgs = [b"", b"abc", bytes(range(200))]
out = {
    "sha256": [[m.hex(), hashlib.sha256(m).hexdigest()] for m in msgs],
    "sha512": [[m.hex(), hashlib.sha512(m).hexdigest()] for m in msgs],
    "hmac": [[k.hex(), m.hex(), hmac.new(k, m, hashlib.sha256).hexdigest()] for k in (bytes(32), b"key" * 20) for m in msgs],
    "identities": [],
    "channels": [],
}
for i in (ident, ident2):
    msg = b"meshcore advert body"
    out["identities"].append({"private": i.private_key.hex(), "public": i.pub.hex(), "msg": msg.hex(),
                              "sig": i.sign(msg).hex()})
out["identities"][0]["seed"] = seed.hex()
for name, key in (("Public", crypto.PUBLIC_CHANNEL_KEY), ("#test", hashtag_channel_key("#test")),
                  ("Ops", bytes.fromhex("00112233445566778899aabbccddeeff"))):
    data = struct.pack("<I", 1760000000) + b"\0" + "Alice: héllo wörld".encode()
    payload = bytes([channel_hash(key)]) + crypto.encrypt_then_mac(key + bytes(16), data)
    pkt = Packet.flood(PT_GRP_TXT, payload)
    out["channels"].append({"name": name, "key": key.hex(), "hash": channel_hash(key), "plain": data.hex(),
                            "raw": pkt.encode().hex(), "packet_hash": pkt.packet_hash().hex()})
app = bytes([0x81]) + b"Alice"
ts = struct.pack("<I", 1760000000)
adv = Packet.flood(PT_ADVERT, ident.pub + ts + ident.sign(ident.pub + ts + app) + app)
out["advert"] = {"private": ident.private_key.hex(), "name": "Alice", "ts": 1760000000, "raw": adv.encode().hex()}
# DMs, ACKs, path returns and rooms, as meshroom_kaas.Node makes them (from ident to ident2)
from meshroom_kaas import Node  # noqa: E402
from meshroom_kaas.crypto import sha256 as _sha  # noqa: E402
from meshroom_kaas.packet import PT_ACK, PT_ANON_REQ, PT_PATH, PT_TXT_MSG  # noqa: E402


class _Quiet:
    hello = {}

    def on_packet(self, fn):
        pass


ident2 = Identity(hashlib.sha256(b"second").digest())         # (a real key: from a seed, so clamped, as the apps' are)
a = Node(_Quiet(), ident, "Alice")
bob = a.contact(ident2.pub, "Bob")
data = struct.pack("<I", 1760000000) + bytes([0]) + "hello bob".encode()
dm = Packet.flood(PT_TXT_MSG, a._datagram(PT_TXT_MSG, bob, data))
ack = _sha(data, ident.pub)[:4]
path_ret = Packet.flood(PT_PATH, a._path_return(bob, b"\x44\x55", 2, PT_ACK, ack))
login_data = struct.pack("<II", 1760000000, 0) + b"hello"
login = Packet.flood(PT_ANON_REQ, bytes([ident2.pub[0]]) + ident.pub + crypto.encrypt_then_mac(ident.shared_secret(ident2.pub), login_data))
post = struct.pack("<I", 1760000000) + bytes([2 << 2]) + ident.pub[:4] + "a room post".encode()   # signed plain, room -> member
b_node = Node(_Quiet(), ident2, "Room")
alice_at_b = b_node.contact(ident.pub, "Alice")
room_post = Packet.flood(PT_TXT_MSG, b_node._datagram(PT_TXT_MSG, alice_at_b, post))
out["peer"] = {
    "a_private": ident.private_key.hex(), "b_private": ident2.private_key.hex(),
    "shared": ident.shared_secret(ident2.pub).hex(), "shared_ba": ident2.shared_secret(ident.pub).hex(),
    "b_public": ident2.pub.hex(),
    "dm_plain": data.hex(), "dm_raw": dm.encode().hex(), "dm_ack": ack.hex(),
    "path_return_raw": path_ret.encode().hex(),
    "room_login_raw": login.encode().hex(),
    "room_post_raw": room_post.encode().hex(), "room_post_ack": _sha(post, ident.pub)[:4].hex(),
}

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "test", "vectors.json")
with open(path, "w") as f:
    json.dump(out, f, indent=1)
print("wrote", path)
