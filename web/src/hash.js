// SHA-256, SHA-512 and HMAC-SHA256 in plain JS: WebCrypto exists only on secure origins, and is async.
import { concatBytes } from "./bytes.js";

// The round constants and initial values come from the primes (cube and square roots), so none are typed in.
function firstPrimes(n) {
  const out = [];
  for (let c = 2; out.length < n; c++) if (out.every((p) => c % p)) out.push(c);
  return out;
}

function iroot(x, k) {
  // floor(x^(1/k)) for BigInt x, by Newton's method from above
  let r = 1n << BigInt(Math.ceil(x.toString(2).length / Number(k)) + 1);
  for (;;) {
    const next = ((k - 1n) * r + x / r ** (k - 1n)) / k;
    if (next >= r) return r;
    r = next;
  }
}

const MASK64 = (1n << 64n) - 1n;
const PRIMES = firstPrimes(80);
const K512 = PRIMES.map((p) => iroot(BigInt(p) << 192n, 3n) & MASK64);
const H512 = PRIMES.slice(0, 8).map((p) => iroot(BigInt(p) << 128n, 2n) & MASK64);
const K256 = Uint32Array.from(K512.slice(0, 64), (k) => Number(k >> 32n));
const H256 = Uint32Array.from(H512, (h) => Number(h >> 32n));

function pad(msg, blockBytes, lenBytes) {
  const n = msg.length;
  const total = Math.ceil((n + 1 + lenBytes) / blockBytes) * blockBytes;
  const out = new Uint8Array(total);
  out.set(msg);
  out[n] = 0x80;
  const bits = BigInt(n) * 8n;
  for (let i = 0; i < 8; i++) out[total - 1 - i] = Number((bits >> BigInt(8 * i)) & 255n);
  return out;
}

export function sha256(msg) {
  const m = pad(msg, 64, 8);
  const h = Uint32Array.from(H256);
  const w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < m.length; off += 64) {
    for (let i = 0; i < 16; i++) {
      const j = off + i * 4;
      w[i] = (m[j] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3];
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i]) | 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i * 4] = h[i] >>> 24; out[i * 4 + 1] = h[i] >>> 16; out[i * 4 + 2] = h[i] >>> 8; out[i * 4 + 3] = h[i];
  }
  return out;
}

// BigInt words: slow next to native code, but it only signs the odd advert.
export function sha512(msg) {
  const m = pad(msg, 128, 16);
  const h = H512.slice();
  const w = new Array(80);
  const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & MASK64;
  for (let off = 0; off < m.length; off += 128) {
    for (let i = 0; i < 16; i++) {
      let v = 0n;
      for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(m[off + i * 8 + j]);
      w[i] = v;
    }
    for (let i = 16; i < 80; i++) {
      const s0 = rotr(w[i - 15], 1n) ^ rotr(w[i - 15], 8n) ^ (w[i - 15] >> 7n);
      const s1 = rotr(w[i - 2], 19n) ^ rotr(w[i - 2], 61n) ^ (w[i - 2] >> 6n);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK64;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 80; i++) {
      const t1 = (hh + (rotr(e, 14n) ^ rotr(e, 18n) ^ rotr(e, 41n)) + ((e & f) ^ (~e & MASK64 & g)) + K512[i] + w[i]) & MASK64;
      const t2 = ((rotr(a, 28n) ^ rotr(a, 34n) ^ rotr(a, 39n)) + ((a & b) ^ (a & c) ^ (b & c))) & MASK64;
      hh = g; g = f; f = e; e = (d + t1) & MASK64; d = c; c = b; b = a; a = (t1 + t2) & MASK64;
    }
    [a, b, c, d, e, f, g, hh].forEach((v, i) => { h[i] = (h[i] + v) & MASK64; });
  }
  const out = new Uint8Array(64);
  h.forEach((v, i) => {
    for (let j = 0; j < 8; j++) out[i * 8 + j] = Number((v >> BigInt(56 - 8 * j)) & 255n);
  });
  return out;
}

export function hmacSha256(key, msg) {
  let k = key.length > 64 ? sha256(key) : key;
  const block = new Uint8Array(64);
  block.set(k);
  const ipad = block.map((b) => b ^ 0x36);
  const opad = block.map((b) => b ^ 0x5c);
  return sha256(concatBytes(opad, sha256(concatBytes(ipad, msg))));
}
