"""MeshCore crypto: Ed25519 identities (signing, X25519 key exchange), AES-128-ECB + 2-byte HMAC, channel keys."""
import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.exceptions import InvalidSignature

PUB_KEY_SIZE = 32
CIPHER_MAC_SIZE = 2
CIPHER_BLOCK_SIZE = 16
PUBLIC_CHANNEL_KEY = base64.b64decode("izOH6cXN6mrJ5e26oRXNcg==")   # the well-known "Public" channel

_P = 2 ** 255 - 19
_ED_D = -121665 * pow(121666, _P - 2, _P) % _P
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493


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
    """MAC (2 bytes of HMAC-SHA256 keyed with the 32-byte secret) + AES-128-ECB(first 16 bytes) of the zero-padded text."""
    ct = aes_encrypt(secret, plaintext)
    return hmac.new(secret[:PUB_KEY_SIZE], ct, hashlib.sha256).digest()[:CIPHER_MAC_SIZE] + ct


def mac_then_decrypt(secret, data):
    """The plaintext (still zero-padded), or None if the MAC doesn't match."""
    if len(data) <= CIPHER_MAC_SIZE or (len(data) - CIPHER_MAC_SIZE) % CIPHER_BLOCK_SIZE:
        return None
    ct = data[CIPHER_MAC_SIZE:]
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


def ed25519_pub_to_x25519(pub):
    y = int.from_bytes(pub, "little") & ((1 << 255) - 1)
    u = (1 + y) * pow((1 - y) % _P, _P - 2, _P) % _P
    return u.to_bytes(32, "little")


def hashtag_channel_key(name):
    """A hashtag channel's key: the first 16 bytes of SHA-256 of "#name" (anyone who knows the name can read it)."""
    if not name.startswith("#"):
        name = "#" + name
    return sha256(name.encode())[:16]


def channel_hash(key16):
    """The 1-byte channel id at the start of every channel message."""
    return sha256(key16)[0]


# Ed25519 from an expanded key [scalar || prefix], the form MeshCore stores and exports private keys in.
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


class Identity:
    """A MeshCore node identity. Made from a 32-byte seed, or a 64-byte MeshCore private key (as the apps export it)."""

    def __init__(self, key):
        key = bytes.fromhex(key) if isinstance(key, str) else bytes(key)
        if len(key) == 32:
            h = bytearray(hashlib.sha512(key).digest())
            h[0] &= 248; h[31] &= 127; h[31] |= 64
            key = bytes(h)
        if len(key) != 64:
            raise ValueError("a private key is 32 or 64 bytes")
        self.private_key = key                                  # 64 bytes, MeshCore's format
        self._a = int.from_bytes(key[:32], "little") & ((1 << 255) - 1)
        self._prefix = key[32:]
        self.pub = _ed_encode(_ed_mul(self._a, _ED_B))
        self._x = X25519PrivateKey.from_private_bytes(key[:32])
        self._secrets = {}

    @classmethod
    def generate(cls):
        return cls(os.urandom(32))

    @classmethod
    def load_or_create(cls, path):
        """The identity in a file (hex), made and saved there the first time."""
        if os.path.exists(path):
            with open(path) as f:
                return cls(f.read().strip())
        ident = cls.generate()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(ident.private_key.hex() + "\n")
        return ident

    @property
    def hash(self):
        """The 1-byte id other nodes address this one by."""
        return self.pub[0]

    def sign(self, msg):
        r = int.from_bytes(hashlib.sha512(self._prefix + msg).digest(), "little") % _ED_L
        big_r = _ed_encode(_ed_mul(r, _ED_B))
        h = int.from_bytes(hashlib.sha512(big_r + self.pub + msg).digest(), "little") % _ED_L
        return big_r + ((r + h * self._a) % _ED_L).to_bytes(32, "little")

    def shared_secret(self, other_pub):
        """The 32-byte secret this node shares with another (X25519 on the converted keys), cached."""
        other_pub = bytes(other_pub)
        s = self._secrets.get(other_pub)
        if s is None:
            s = self._secrets[other_pub] = self._x.exchange(X25519PublicKey.from_public_bytes(ed25519_pub_to_x25519(other_pub)))
        return s
