// Ed25519 from MeshCore's 64-byte expanded private key [clamped scalar || prefix]. WebCrypto only takes 32-byte
// seeds, and a key exported from a MeshCore app has no seed, so the curve math is done here with BigInt.
import { concatBytes } from "./bytes.js";
import { sha512 } from "./hash.js";

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const mod = (a, m = P) => ((a % m) + m) % m;

function powMod(b, e, m = P) {
  let r = 1n;
  b = mod(b, m);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

const inv = (a) => powMod(a, P - 2n);
const D = mod(-121665n * inv(121666n));

// extended coordinates (X, Y, Z, T)
function add(p, q) {
  const a = mod((p[1] - p[0]) * (q[1] - q[0]));
  const b = mod((p[1] + p[0]) * (q[1] + q[0]));
  const c = mod(2n * p[3] * q[3] * D);
  const d = mod(2n * p[2] * q[2]);
  const e = b - a, f = d - c, g = d + c, h = b + a;
  return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
}

function mulPoint(s, p) {
  let q = [0n, 1n, 1n, 0n];
  while (s > 0n) {
    if (s & 1n) q = add(q, p);
    p = add(p, p);
    s >>= 1n;
  }
  return q;
}

const BASE = (() => {
  const y = mod(4n * inv(5n));
  const x2 = mod((y * y - 1n) * inv(D * y * y + 1n));
  let x = powMod(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = mod(x * powMod(2n, (P - 1n) / 4n));
  if (x & 1n) x = P - x;
  return [x, y, 1n, mod(x * y)];
})();

const bytesToBig = (b) => b.reduceRight((n, x) => (n << 8n) | BigInt(x), 0n);

function bigToBytes(n, len = 32) {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++, n >>= 8n) out[i] = Number(n & 255n);
  return out;
}

function encodePoint(p) {
  const zi = inv(p[2]);
  const x = mod(p[0] * zi), y = mod(p[1] * zi);
  return bigToBytes(y | ((x & 1n) << 255n));
}

// A 32-byte seed becomes the 64-byte key the way MeshCore does it: SHA-512, then clamp.
export function expandSeed(seed) {
  const h = sha512(seed);
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;
  return h;
}

export function ed25519PublicKey(priv64) {
  const a = bytesToBig(priv64.subarray(0, 32)) & ((1n << 255n) - 1n);
  return encodePoint(mulPoint(a, BASE));
}

export function ed25519Sign(priv64, pub, msg) {
  const a = bytesToBig(priv64.subarray(0, 32)) & ((1n << 255n) - 1n);
  const r = mod(bytesToBig(sha512(concatBytes(priv64.subarray(32, 64), msg))), L);
  const R = encodePoint(mulPoint(r, BASE));
  const h = mod(bytesToBig(sha512(concatBytes(R, pub, msg))), L);
  return concatBytes(R, bigToBytes(mod(r + h * a, L)));
}

// A point from its 32-byte encoding, or null if it isn't on the curve.
function decodePoint(b) {
  const n = bytesToBig(b);
  const y = n & ((1n << 255n) - 1n);
  if (y >= P) return null;
  const x2 = mod((y * y - 1n) * inv(D * y * y + 1n));
  let x = powMod(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = mod(x * powMod(2n, (P - 1n) / 4n));
  if (mod(x * x - x2) !== 0n) return null;
  if ((x & 1n) !== n >> 255n) {
    if (x === 0n) return null;
    x = P - x;
  }
  return [x, y, 1n, mod(x * y)];
}

// A key of small order: not a real node's (such a key "verifies" signatures nobody made, and its shared secret is
// known to everyone). False for anything that isn't a point at all.
export function isWeakKey(pub) {
  const A = pub.length === 32 ? decodePoint(pub) : null;
  if (!A) return false;
  const e = encodePoint(mulPoint(8n, A));
  return e[0] === 1 && e.subarray(1).every((v) => v === 0);
}

// Checks [S]B == R + [h]A, h = SHA-512(R || A || msg). (Adverts: a forged one can't rename a contact.) A key of small
// order never verifies.
export function ed25519Verify(pub, sig, msg) {
  if (pub.length !== 32 || sig.length !== 64) return false;
  const A = decodePoint(pub);
  const R = decodePoint(sig.subarray(0, 32));
  const S = bytesToBig(sig.subarray(32, 64));
  if (!A || !R || S >= L || isWeakKey(pub)) return false;
  const h = mod(bytesToBig(sha512(concatBytes(sig.subarray(0, 32), pub, msg))), L);
  const left = encodePoint(mulPoint(S, BASE));
  const right = encodePoint(add(R, mulPoint(h, A)));
  return left.every((v, i) => v === right[i]);
}

// X25519 (RFC 7748): the secret two nodes share, from one's private scalar and the other's key.
export function x25519(scalar32, u32) {
  const k = bytesToBig(scalar32.subarray(0, 32)) & ~7n & ((1n << 254n) - 1n) | (1n << 254n);
  const x1 = bytesToBig(u32) & ((1n << 255n) - 1n);
  let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, swap = 0n;
  for (let t = 254n; t >= 0n; t--) {
    const kt = (k >> t) & 1n;
    if (swap ^ kt) [x2, x3, z2, z3] = [x3, x2, z3, z2];
    swap = kt;
    const A = x2 + z2, AA = mod(A * A), B = x2 - z2, BB = mod(B * B), E = AA - BB;
    const C = x3 + z3, Dd = x3 - z3, DA = mod(Dd * A), CB = mod(C * B);
    x3 = mod((DA + CB) ** 2n);
    z3 = mod(x1 * mod((DA - CB) ** 2n));
    x2 = mod(AA * BB);
    z2 = mod(E * (AA + 121665n * E));
  }
  if (swap) [x2, z2] = [x3, z3];
  return bigToBytes(mod(x2 * inv(z2)));
}

// An Ed25519 public key as an X25519 one: u = (1 + y) / (1 - y).
export function edPubToX25519(pub) {
  const y = bytesToBig(pub) & ((1n << 255n) - 1n);
  return bigToBytes(mod((1n + y) * inv(mod(1n - y))));
}
