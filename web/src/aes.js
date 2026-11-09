// AES-128, one block at a time (MeshCore uses ECB, which WebCrypto doesn't offer).

const SBOX = new Uint8Array(256);
const INV_SBOX = new Uint8Array(256);
const xtime = (x) => ((x << 1) ^ (x & 0x80 ? 0x1b : 0)) & 0xff;

(function makeSboxes() {
  // walk GF(2^8) with generator 3: p runs over all non-zero elements, q over their inverses
  let p = 1, q = 1;
  do {
    p = p ^ xtime(p);
    q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff;
    if (q & 0x80) q ^= 0x09;
    const rot = (x, n) => ((x << n) | (x >> (8 - n))) & 0xff;
    const s = q ^ rot(q, 1) ^ rot(q, 2) ^ rot(q, 3) ^ rot(q, 4) ^ 0x63;
    SBOX[p] = s;
    INV_SBOX[s] = p;
  } while (p !== 1);
  SBOX[0] = 0x63;
  INV_SBOX[0x63] = 0;
})();

function mul(a, b) {
  let r = 0;
  while (b) {
    if (b & 1) r ^= a;
    a = xtime(a);
    b >>= 1;
  }
  return r;
}

export function aesExpandKey(key16) {
  const w = new Uint8Array(176);
  w.set(key16.subarray(0, 16));
  let rcon = 1;
  for (let i = 16; i < 176; i += 4) {
    let t = w.slice(i - 4, i);
    if (i % 16 === 0) {
      t = new Uint8Array([SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]);
      rcon = xtime(rcon);
    }
    for (let j = 0; j < 4; j++) w[i + j] = w[i - 16 + j] ^ t[j];
  }
  return w;
}

function addRoundKey(s, w, round) {
  for (let i = 0; i < 16; i++) s[i] ^= w[round * 16 + i];
}

// state is column-major: s[c * 4 + r]
function shiftRows(s, inv) {
  const t = s.slice();
  for (let r = 1; r < 4; r++)
    for (let c = 0; c < 4; c++) s[c * 4 + r] = t[((inv ? c - r + 4 : c + r) % 4) * 4 + r];
}

function mixColumns(s, inv) {
  const m = inv ? [14, 11, 13, 9] : [2, 3, 1, 1];
  for (let c = 0; c < 4; c++) {
    const col = s.slice(c * 4, c * 4 + 4);
    for (let r = 0; r < 4; r++)
      s[c * 4 + r] = mul(col[r], m[0]) ^ mul(col[(r + 1) % 4], m[1]) ^ mul(col[(r + 2) % 4], m[2]) ^ mul(col[(r + 3) % 4], m[3]);
  }
}

export function aesEncryptBlock(w, block) {
  const s = block.slice(0, 16);
  addRoundKey(s, w, 0);
  for (let round = 1; round <= 10; round++) {
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    shiftRows(s, false);
    if (round < 10) mixColumns(s, false);
    addRoundKey(s, w, round);
  }
  return s;
}

export function aesDecryptBlock(w, block) {
  const s = block.slice(0, 16);
  addRoundKey(s, w, 10);
  for (let round = 9; round >= 0; round--) {
    shiftRows(s, true);
    for (let i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
    addRoundKey(s, w, round);
    if (round > 0) mixColumns(s, true);
  }
  return s;
}

// ECB over whole blocks; the plaintext is zero-padded to a multiple of 16 first.
export function aesEcbEncrypt(key16, data) {
  const w = aesExpandKey(key16);
  const n = Math.ceil(data.length / 16) * 16 || 16;
  const padded = new Uint8Array(n);
  padded.set(data);
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 16) out.set(aesEncryptBlock(w, padded.subarray(i, i + 16)), i);
  return out;
}

export function aesEcbDecrypt(key16, data) {
  const w = aesExpandKey(key16);
  const out = new Uint8Array(data.length);
  for (let i = 0; i + 16 <= data.length; i += 16) out.set(aesDecryptBlock(w, data.subarray(i, i + 16)), i);
  return out;
}
