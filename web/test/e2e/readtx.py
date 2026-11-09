"""What the radio transmitted, decoded by pyMeshRoom's Python client: readtx.py DEV_LOG [#hashtag | secret hex ...]"""
import os
import sys
sys.path.insert(0, os.path.join(os.environ["PYMESHROOM"], "client"))
from meshroom_kaas import Packet, crypto, hashtag_channel_key, channel_hash
keys = {"Public": crypto.PUBLIC_CHANNEL_KEY}
for a in sys.argv[2:]:
    keys[a] = hashtag_channel_key(a) if a.startswith("#") else bytes.fromhex(a)
for line in open(sys.argv[1]):
    if not line.startswith("TX "): continue
    p = Packet.parse(bytes.fromhex(line[3:].strip()))
    if p.ptype == 5:
        hit = [n for n, k in keys.items() if p.payload[0] == channel_hash(k) and crypto.mac_then_decrypt(k + bytes(16), p.payload[1:])]
        for n in hit:
            d = crypto.mac_then_decrypt(keys[n] + bytes(16), p.payload[1:])
            print("GRP", n, repr(d[5:].split(b"\0")[0].decode()))
        if not hit: print("GRP undecryptable")
    elif p.ptype == 4:
        pl = p.payload; pub, ts, sig, app = pl[:32], pl[32:36], pl[36:100], pl[100:]
        print("ADVERT", "flood" if p.is_flood else "zero-hop", pub.hex()[:16], "valid-sig" if crypto.ed25519_verify(pub, sig, pub + ts + app) else "BAD-SIG", app[1:].decode(errors="replace"))
    else:
        print("OTHER", p.type_name)
