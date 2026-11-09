"""MeshCore packets: the wire format the KaaS API streams and accepts (raw bytes, hex in JSON)."""
import hashlib
import struct

ROUTE_TRANSPORT_FLOOD, ROUTE_FLOOD, ROUTE_DIRECT, ROUTE_TRANSPORT_DIRECT = 0, 1, 2, 3

PT_REQ, PT_RESPONSE, PT_TXT_MSG, PT_ACK, PT_ADVERT, PT_GRP_TXT, PT_GRP_DATA, PT_ANON_REQ, \
    PT_PATH, PT_TRACE, PT_MULTIPART, PT_CONTROL = range(12)
PT_NAMES = ["req", "resp", "txt", "ack", "advert", "grp_txt", "grp_data", "anon_req",
            "path", "trace", "multipart", "control"]

ADV_TYPE_CHAT, ADV_TYPE_REPEATER, ADV_TYPE_ROOM, ADV_TYPE_SENSOR = 1, 2, 3, 4
TXT_TYPE_PLAIN, TXT_TYPE_CLI_DATA, TXT_TYPE_SIGNED_PLAIN = 0, 1, 2

MAX_PACKET_PAYLOAD = 184
MAX_PATH_SIZE = 64


def path_bytes(path_len):
    """Bytes of path for a path_len byte: hop count (low 6 bits) x hash size (top 2 bits + 1)."""
    return (path_len & 63) * ((path_len >> 6) + 1)


def path_valid(path_len):
    return ((path_len >> 6) + 1) != 4 and path_bytes(path_len) <= MAX_PATH_SIZE


class Packet:
    """header (route type: low 2 bits, payload type: next 4), optional transport codes, path_len, path, payload."""

    def __init__(self, ptype=0, payload=b""):
        self.header = (ptype & 0x0F) << 2
        self.transport_codes = (0, 0)
        self.path_len = 0
        self.path = b""
        self.payload = bytes(payload)
        # set on packets from the stream
        self.dir = None         # "rx": the radio heard it; "tx": the radio sent it
        self.snr = None
        self.rssi = None
        self.ts = None

    route_type = property(lambda s: s.header & 0x03)
    ptype = property(lambda s: (s.header >> 2) & 0x0F)
    type_name = property(lambda s: PT_NAMES[s.ptype] if s.ptype < len(PT_NAMES) else str(s.ptype))
    is_flood = property(lambda s: s.route_type in (ROUTE_FLOOD, ROUTE_TRANSPORT_FLOOD))
    is_direct = property(lambda s: s.route_type in (ROUTE_DIRECT, ROUTE_TRANSPORT_DIRECT))
    has_transport = property(lambda s: s.route_type in (ROUTE_TRANSPORT_FLOOD, ROUTE_TRANSPORT_DIRECT))
    hash_size = property(lambda s: (s.path_len >> 6) + 1)
    hop_count = property(lambda s: s.path_len & 63)

    @classmethod
    def flood(cls, ptype, payload, hash_size=1):
        p = cls(ptype, payload)
        p.header |= ROUTE_FLOOD
        p.path_len = (hash_size - 1) << 6
        return p

    @classmethod
    def direct(cls, ptype, payload, path=b"", path_len=0):
        """Along a known path (path_len 0 = zero hop: only nodes that hear this radio directly)."""
        p = cls(ptype, payload)
        p.header |= ROUTE_DIRECT
        p.path_len = path_len
        p.path = bytes(path[:path_bytes(path_len)])
        return p

    @classmethod
    def parse(cls, raw):
        """bytes -> Packet, or None if it isn't a well-formed MeshCore packet."""
        raw = bytes(raw)
        if len(raw) < 2:
            return None
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
        p.path = raw[i:i + bl]; i += bl
        if i >= len(raw):
            return None
        p.payload = raw[i:]
        if len(p.payload) > MAX_PACKET_PAYLOAD:
            return None
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
        """What MeshCore nodes de-duplicate on: the same packet heard along different paths has the same hash."""
        h = hashlib.sha256()
        h.update(bytes([self.ptype]))
        if self.ptype == PT_TRACE:
            h.update(struct.pack("<H", self.path_len))
        h.update(self.payload)
        return h.digest()[:8]

    def __repr__(self):
        return "<Packet %s %s %d hops, %d bytes>" % (self.type_name, "flood" if self.is_flood else "direct",
                                                      self.hop_count, len(self.payload))
