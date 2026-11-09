import assert from "node:assert/strict";
import { test } from "node:test";
import { bytesToHex, utf8Encode } from "../src/bytes.js";
import { pbkdf2, seal, unseal } from "../src/vault.js";

test("PBKDF2-HMAC-SHA256 (RFC 7914 test vector)", () => {
  assert.equal(bytesToHex(pbkdf2(utf8Encode("passwd"), utf8Encode("salt"), 1, 64)),
    "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");
});

test("a sealed key opens only with its passphrase", async () => {
  const secret = new Uint8Array(64).map((_, i) => i);
  const box = await seal(secret, "correct horse");
  assert.equal(box.rounds, 600000);                                   // (WebCrypto's PBKDF2, where there is one)
  assert.equal(box.data.includes(bytesToHex(secret).slice(0, 16)), false);
  assert.deepEqual(await unseal(box, "correct horse"), secret);
  assert.equal(await unseal(box, "wrong"), null);
  assert.equal(await unseal({ ...box, data: "00" + box.data.slice(2) }, "correct horse"), null);
});

test("WebCrypto's PBKDF2 and the plain one agree (so a vault opens either way, at the rounds it was made with)", async () => {
  const pw = utf8Encode("pass"), salt = utf8Encode("saltsaltsaltsalt");
  const key = await crypto.subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
  const fast = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 3000 }, key, 384));
  assert.equal(bytesToHex(fast), bytesToHex(pbkdf2(pw, salt, 3000, 48)));
});

test("a sealer from the private key: only that key opens what it sealed", async () => {
  const { keySealer } = await import("../src/vault.js");
  const key = new Uint8Array(64).map((_, i) => i * 3);
  const box = keySealer(key).seal("room password");
  assert.equal(JSON.stringify(box).includes("room password"), false);
  assert.equal(keySealer(key).open(box), "room password");
  assert.equal(keySealer(key.map((b) => b ^ 1)).open(box), null);
  assert.equal(keySealer(key).open({ ...box, mac: "00".repeat(32) }), null);
  assert.equal(keySealer(key).open({}), null);
});
