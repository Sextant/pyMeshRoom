// Byte helpers: hex, UTF-8, concatenation, randomness.

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: false });

export function hexToBytes(hex) {
  const s = String(hex).trim().replace(/^0x/i, "").replace(/\s+/g, "");
  if (s.length % 2 || /[^0-9a-f]/i.test(s)) throw new Error("not hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function base64ToBytes(b64) {
  const bin = atob(String(b64).trim());
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export const utf8Encode = (s) => textEncoder.encode(s);
export const utf8Decode = (b) => textDecoder.decode(b);

export function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

// At most n bytes of UTF-8, never ending mid-character.
export function utf8Cut(bytes, n) {
  let end = Math.min(n, bytes.length);
  if (end < bytes.length) while (end > 0 && (bytes[end] & 0xc0) === 0x80) end--;
  return bytes.subarray(0, end);
}

export function u32le(n) {
  return new Uint8Array([n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255]);
}

export function readU32le(b, i) {
  return (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
}

export function i32le(n) {
  return u32le(n | 0);
}
