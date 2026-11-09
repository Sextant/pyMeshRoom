// Checks the browser crypto and packet code against vectors from pyMeshRoom's Python client (tools/make_vectors.py).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { aesEcbDecrypt, aesEcbEncrypt } from "../src/aes.js";
import { bytesToHex, hexToBytes, utf8Cut, utf8Encode } from "../src/bytes.js";
import { hmacSha256, sha256, sha512 } from "../src/hash.js";
import {
  Identity, PT_GRP_TXT, advertPayload, channelMessagePacket, floodPacket, makeChannel, packetHash, parsePacket,
  readChannelMessage, textBudget,
} from "../src/meshcore.js";

const V = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url)));
const h = hexToBytes;

test("sha256, sha512, hmac", () => {
  for (const [m, d] of V.sha256) assert.equal(bytesToHex(sha256(h(m))), d);
  for (const [m, d] of V.sha512) assert.equal(bytesToHex(sha512(h(m))), d);
  for (const [k, m, d] of V.hmac) assert.equal(bytesToHex(hmacSha256(h(k), h(m))), d);
});

test("aes-128 (FIPS-197 C.1)", () => {
  const key = h("000102030405060708090a0b0c0d0e0f");
  const ct = aesEcbEncrypt(key, h("00112233445566778899aabbccddeeff"));
  assert.equal(bytesToHex(ct), "69c4e0d86a7b0430d8cdb78070b4c55a");
  assert.equal(bytesToHex(aesEcbDecrypt(key, ct)), "00112233445566778899aabbccddeeff");
});

test("identities: public key and signature match the Python client", () => {
  for (const v of V.identities) {
    const id = new Identity(v.private);
    assert.equal(id.pubHex, v.public);
    assert.equal(bytesToHex(id.sign(h(v.msg))), v.sig);
  }
  const fromSeed = new Identity(V.identities[0].seed);
  assert.equal(fromSeed.privateHex, V.identities[0].private);
  assert.throws(() => new Identity("abcd"));
});

test("advert", () => {
  const id = new Identity(V.advert.private);
  const raw = floodPacket(4, advertPayload(id, V.advert.name, V.advert.ts));
  assert.equal(bytesToHex(raw), V.advert.raw);
});

test("channel messages: same bytes as Python, and read back", () => {
  for (const v of V.channels) {
    const kind = v.name === "Public" ? "public" : v.name.startsWith("#") ? "hashtag" : "private";
    const ch = makeChannel(v.name, kind, kind === "private" ? v.key : undefined);
    assert.equal(ch.keyHex, v.key);
    assert.equal(ch.hash, v.hash);
    const raw = channelMessagePacket(ch, "Alice", "héllo wörld", 1760000000);
    assert.equal(bytesToHex(raw), v.raw);
    const pkt = parsePacket(raw);
    assert.equal(pkt.ptype, PT_GRP_TXT);
    assert.equal(packetHash(pkt), v.packet_hash);
    const other = makeChannel("#other", "hashtag");
    const msg = readChannelMessage([other, ch], pkt.payload);
    assert.deepEqual([msg.channel, msg.sender, msg.text, msg.ts], [ch, "Alice", "héllo wörld", 1760000000]);
    assert.equal(readChannelMessage([other], pkt.payload), null);
  }
});

test("text is cut to fit, never mid-character", () => {
  const ch = makeChannel("Public", "public");
  const budget = textBudget("Bob");
  assert.equal(budget, 160 - 5);
  const raw = channelMessagePacket(ch, "Bob", "é".repeat(200), 1);
  const msg = readChannelMessage([ch], parsePacket(raw).payload);
  assert.equal(utf8Encode(msg.text).length, budget - 1);
  assert.equal(msg.text, "é".repeat((budget - 1) / 2));
  assert.equal(utf8Cut(utf8Encode("aé"), 2).length, 1);
});

test("keys of small order: they never verify, and can't be talked to", async () => {
  const { ed25519Verify, isWeakKey } = await import("../src/ed25519.js");
  const { Identity } = await import("../src/meshcore.js");
  const identity = hexToBytes("01" + "00".repeat(31));                  // the identity point: [8]A is itself
  const order2 = hexToBytes("ec" + "ff".repeat(30) + "7f");              // (0, -1)
  assert.equal(isWeakKey(identity) && isWeakKey(order2), true);
  // R = the identity point, S = 0: [S]B = R + [h]A for any message, when A is the identity too
  assert.equal(ed25519Verify(identity, hexToBytes("01" + "00".repeat(63)), utf8Encode("anything at all")), false);
  const me = new Identity(bytesToHex(new Uint8Array(32).fill(7)));
  assert.equal(isWeakKey(me.pub), false);
  assert.throws(() => me.sharedSecret(identity), /weak key/);
});

test("floods we start can collect 1-, 2- or 3-byte repeater ids (MeshCore's path hash mode)", () => {
  const ch = makeChannel("Public", "public");
  for (const size of [1, 2, 3]) {
    const pkt = parsePacket(channelMessagePacket(ch, "Alice", "hi", 1, size));
    assert.equal(pkt.isFlood && pkt.hops === 0 && pkt.hashSize, size);
  }
  assert.equal(parsePacket(floodPacket(PT_GRP_TXT, new Uint8Array(4))).hashSize, 1);   // (1 unless asked)
});
