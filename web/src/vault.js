// Sealing what this browser saves. The private key, with a passphrase: PBKDF2-HMAC-SHA256 makes the keys. Room
// passwords, with the private key itself: only someone holding it can read them. Either way AES-128-CTR hides the data
// and HMAC-SHA256 checks it. Plain JS, like the rest (WebCrypto exists only on secure origins), except the
// passphrase's PBKDF2: WebCrypto's where there is one (many more rounds in the same time), plain JS where not.
import { aesEncryptBlock, aesExpandKey } from "./aes.js";
import { bytesToHex, concatBytes, equalBytes, hexToBytes, randomBytes, u32le, utf8Decode, utf8Encode } from "./bytes.js";
import { hmacSha256 } from "./hash.js";

const ROUNDS = 50000;                     // plain JS: about a second in a browser, slow for guessing, fine for logging in
const ROUNDS_WEBCRYPTO = 600000;          // WebCrypto: OWASP's figure for PBKDF2-HMAC-SHA256, well under a second
const subtle = () => (typeof crypto !== "undefined" && crypto.subtle) || null;

// pbkdf2(), by WebCrypto when the page has it.
async function pbkdf2Fast(password, salt, rounds, length) {
  const s = subtle();
  if (!s) return pbkdf2(password, salt, rounds, length);
  const key = await s.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await s.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: rounds }, key, length * 8));
}

export function pbkdf2(password, salt, rounds, length = 32) {
  const out = new Uint8Array(length);
  for (let block = 1, done = 0; done < length; block++) {
    let u = hmacSha256(password, concatBytes(salt, new Uint8Array([block >>> 24, block >>> 16, block >>> 8, block])));
    const t = Uint8Array.from(u);
    for (let i = 1; i < rounds; i++) {
      u = hmacSha256(password, u);
      for (let j = 0; j < t.length; j++) t[j] ^= u[j];
    }
    out.set(t.subarray(0, length - done), done);
    done += t.length;
  }
  return out;
}

function ctr(key16, iv, data) {
  const w = aesExpandKey(key16);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 16) {
    const ks = aesEncryptBlock(w, concatBytes(iv.subarray(0, 12), u32le(i / 16)));
    for (let j = 0; j < 16 && i + j < data.length; j++) out[i + j] = data[i + j] ^ ks[j];
  }
  return out;
}

async function keys(passphrase, salt, rounds) {
  const k = await pbkdf2Fast(utf8Encode(passphrase), salt, rounds, 48);
  return { enc: k.subarray(0, 16), mac: k.subarray(16, 48) };
}

function sealWith(k, secret, salt) {
  const iv = randomBytes(12);
  const data = ctr(k.enc, iv, secret);
  const mac = hmacSha256(k.mac, concatBytes(salt, iv, data));
  return { iv: bytesToHex(iv), data: bytesToHex(data), mac: bytesToHex(mac) };
}

function unsealWith(k, box, salt) {
  const iv = hexToBytes(box.iv), data = hexToBytes(box.data);
  if (!equalBytes(hmacSha256(k.mac, concatBytes(salt, iv, data)), hexToBytes(box.mac))) return null;
  return ctr(k.enc, iv, data);
}

// -> (a promise of) {v: 1, rounds, salt, iv, data, mac} (hex), for localStorage. The rounds are kept with it.
export async function seal(secret, passphrase) {
  const salt = randomBytes(16), rounds = subtle() ? ROUNDS_WEBCRYPTO : ROUNDS;
  return { v: 1, rounds, salt: bytesToHex(salt), ...sealWith(await keys(passphrase, salt, rounds), secret, salt) };
}

// (A promise of) the secret, or null for a wrong passphrase (or a damaged record).
export async function unseal(box, passphrase) {
  try {
    const salt = hexToBytes(box.salt);
    return unsealWith(await keys(passphrase, salt, Math.min(Math.max(box.rounds | 0, 1000), 1000000)), box, salt);
  } catch {
    return null;
  }
}

// What this browser saves for an identity, sealed with a key that comes from its private key (one-way, and under a
// label of its own, so it is never usable as the node's key). A sealer: {seal(text) -> box, open(box) -> text | null}.
export function keySealer(privateKey) {
  const root = hmacSha256(privateKey, utf8Encode("meshcore-web local storage v1"));
  const k = { enc: hmacSha256(root, utf8Encode("enc")).subarray(0, 16), mac: hmacSha256(root, utf8Encode("mac")) };
  const none = new Uint8Array(0);
  return {
    seal: (text) => ({ v: 1, ...sealWith(k, utf8Encode(text), none) }),
    open: (box) => {
      try {
        const b = unsealWith(k, box, none);
        return b && utf8Decode(b);
      } catch {
        return null;
      }
    },
  };
}
