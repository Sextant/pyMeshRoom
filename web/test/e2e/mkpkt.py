"""Packets as the radio would hear them, made by pyMeshRoom's Python client:
    mkpkt.py CHANNEL SENDER TEXT [TS]   a channel message (CHANNEL: Public, #hashtag or a private secret in hex;
                                        TS: its sender timestamp, now if left out)
    mkpkt.py --advert PRIVATE_KEY NAME [TYPE LAT LON]  a flood advert, signed with that key (TYPE: 1 person,
                                                       2 repeater, 3 room)"""
import os, struct, sys, time
sys.path.insert(0, os.path.join(os.environ["PYMESHROOM"], "client"))
from meshroom_kaas import Identity, Packet, crypto, hashtag_channel_key, channel_hash
from meshroom_kaas.packet import PT_ADVERT, PT_GRP_TXT
if sys.argv[1] == "--advert":
    ident, name = Identity(sys.argv[2]), sys.argv[3]
    kind = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    loc = struct.pack("<ii", int(float(sys.argv[5]) * 1e6), int(float(sys.argv[6]) * 1e6)) if len(sys.argv) > 6 else b""
    app = bytes([0x80 | kind | (0x10 if loc else 0)]) + loc + name.encode()
    ts = struct.pack("<I", int(time.time()))
    p = Packet.flood(PT_ADVERT, ident.pub + ts + ident.sign(ident.pub + ts + app) + app)
else:
    name, sender, text = sys.argv[1], sys.argv[2], sys.argv[3]
    key = crypto.PUBLIC_CHANNEL_KEY if name == "Public" else hashtag_channel_key(name) if name.startswith("#") else bytes.fromhex(name)
    ts = int(sys.argv[4]) if len(sys.argv) > 4 else int(time.time())
    data = struct.pack("<I", ts) + b"\0" + (sender + ": " + text).encode()
    p = Packet.flood(PT_GRP_TXT, bytes([channel_hash(key)]) + crypto.encrypt_then_mac(key + bytes(16), data))
p.path_len = 2; p.path = b"\x44\x55"
print(p.encode().hex())
