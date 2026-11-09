// The browser's mesh node against meshroom_kaas.Node (the Python reference, via test/vectors.json), and two
// browser nodes talking over a fake radio: DMs with ACKs, path learning, rooms.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { bytesToHex, concatBytes, hexToBytes, u32le, utf8Encode } from "../src/bytes.js";
import { Identity, PT_ACK, PT_ANON_REQ, PT_PATH, PT_TXT_MSG, floodPacket, parsePacket, readAdvert } from "../src/meshcore.js";
import { MeshNode } from "../src/node.js";

const V = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url)));
const P = V.peer;

// A fake KaaS client: every packet sent goes to the other nodes on the "air", as the radio would stream it.
function air() {
  const nodes = [];
  const sent = [];
  const client = (owner) => ({
    hello: { radio: { freq_hz: 910525000, bw_hz: 62500, sf: 7, cr: 5 } },
    async send(raw) { return this.sendNow(raw); },
    async sendNow(raw) {
      sent.push({ from: owner(), raw });
      for (const n of nodes) if (n !== owner()) setTimeout(() => n.handle(parsePacket(raw)), 5);
      return { status: "sent" };
    },
  });
  return { nodes, sent, client };
}

function node(net, priv, name) {
  let me;
  const n = new MeshNode(net.client(() => me), new Identity(priv), name);
  me = n;
  net.nodes.push(n);
  return n;
}

test("same bytes as the Python client: shared secrets, DMs, path returns, room logins", () => {
  const a = new Identity(P.a_private), b = new Identity(P.b_private);
  assert.equal(bytesToHex(a.sharedSecret(b.pub)), P.shared);
  assert.equal(P.shared_ba, P.shared);                          // (the same secret from both ends)
  assert.equal(b.pubHex, P.b_public);
  assert.equal(bytesToHex(b.sharedSecret(a.pub)), P.shared_ba);
  const alice = new MeshNode({ hello: {} }, a, "Alice");
  const bob = alice.contact(b.pubHex, { name: "Bob" });
  const data = hexToBytes(P.dm_plain);
  assert.equal(bytesToHex(floodPacket(PT_TXT_MSG, alice.datagram(bob, data))), P.dm_raw);
  const ack = hexToBytes(P.dm_ack);
  assert.equal(bytesToHex(floodPacket(PT_PATH, alice.pathReturn(bob, hexToBytes("4455"), 2, PT_ACK, ack))), P.path_return_raw);
  const login = concatBytes(u32le(1760000000), u32le(0), utf8Encode("hello"));
  const payload = concatBytes(new Uint8Array([b.pub[0]]), a.pub, alice.datagram(bob, login).subarray(2));
  assert.equal(bytesToHex(floodPacket(PT_ANON_REQ, payload)), P.room_login_raw);
});

test("a room's post (signed plain) is decrypted, delivered once and ACKed with our key", async () => {
  const a = new Identity(P.a_private), b = new Identity(P.b_private);
  const sent = [];
  const alice = new MeshNode({ hello: {}, sendNow: async (raw) => { sent.push(raw); return { status: "sent" }; } }, a, "Alice");
  const room = alice.contact(b.pubHex, { type: "room" });
  room.room = { syncSince: 0, loggedIn: true };
  const posts = [];
  alice.addEventListener("post", (e) => posts.push(e.detail));
  alice.handle(parsePacket(hexToBytes(P.room_post_raw)));
  alice.handle(parsePacket(hexToBytes(P.room_post_raw)));       // the room resends after a lost ACK: shown once
  assert.deepEqual(posts.map((p) => [p.author, p.text, p.ts]), [[a.pubHex.slice(0, 8), "a room post", 1760000000]]);
  assert.equal(room.room.syncSince, 1760000000);
  assert.equal(sent.length, 2);                                  // but ACKed both times
  const reply = parsePacket(sent[0]);
  assert.equal(reply.ptype, PT_PATH);                            // a flood: the path back, carrying the ACK
  const { macThenDecrypt } = await import("../src/meshcore.js");
  const inner = macThenDecrypt(a.sharedSecret(b.pub), reply.payload.subarray(2));
  assert.equal(bytesToHex(inner.subarray(2, 6)), P.room_post_ack);
});

test("two browser nodes: a DM, its ACK, and the path learned for the next one", async () => {
  const net = air();
  const alice = node(net, P.a_private, "Alice"), bob = node(net, P.b_private, "Bob");
  const got = [];
  bob.addEventListener("dm", (e) => got.push([e.detail.contact.pubHex, e.detail.text]));
  // they know each other from adverts
  const { advertPayload } = await import("../src/meshcore.js");
  bob.handle(parsePacket(floodPacket(4, advertPayload(alice.id, "Alice", 100))));
  alice.handle(parsePacket(floodPacket(4, advertPayload(bob.id, "Bob", 100))));
  assert.equal(alice.contacts.get(bob.id.pubHex).name, "Bob");
  const res = await alice.sendDm(alice.contacts.get(bob.id.pubHex), "hi bob");
  assert.equal(res.acked, true);
  assert.deepEqual(got, [[alice.id.pubHex, "hi bob"]]);
  assert.equal(alice.contacts.get(bob.id.pubHex).outLen, 0);    // the path back came with the ACK: direct now
  const res2 = await alice.sendDm(alice.contacts.get(bob.id.pubHex), "again");
  assert.equal(res2.acked, true);
  const last = net.sent.filter((s) => s.from === alice).map((s) => parsePacket(s.raw)).filter((p) => p.ptype === PT_TXT_MSG).at(-1);
  assert.equal(last.isFlood, false);
});

test("a forged advert can't rename a contact; an older one is ignored", async () => {
  const { advertPayload } = await import("../src/meshcore.js");
  const alice = new MeshNode({ hello: {} }, new Identity(P.a_private), "Alice");
  const bob = new Identity(P.b_private);
  alice.handle(parsePacket(floodPacket(4, advertPayload(bob, "Bob", 200))));
  const forged = advertPayload(bob, "Mallory", 300);
  forged[forged.length - 1] ^= 1;                               // the name changed after signing
  assert.equal(readAdvert(forged), null);
  alice.handle(parsePacket(floodPacket(4, forged)));
  alice.handle(parsePacket(floodPacket(4, advertPayload(bob, "Old", 150))));
  assert.equal(alice.contacts.get(bob.pubHex).name, "Bob");
});

test("the server's directory fills in contacts", () => {
  const alice = new MeshNode({ hello: {} }, new Identity(P.a_private), "Alice");
  alice.mergeDirectory([{ pub: "ab".repeat(32), type: "repeater", name: "Seaside", lat: 36.5, lon: -121.9, last_heard: 5 },
    { pub: alice.id.pubHex, type: "chat", name: "me", last_heard: 5 }, { pub: "junk" }]);
  assert.deepEqual([...alice.contacts.values()].map((c) => [c.name, c.type, c.lat]), [["Seaside", "repeater", 36.5]]);
  const saved = alice.saveContacts();
  const again = new MeshNode({ hello: {} }, new Identity(P.a_private), "Alice");
  again.loadContacts(saved);
  assert.equal(again.contacts.get("ab".repeat(32)).name, "Seaside");
});

test("room passwords are saved sealed with our private key; old plaintext ones still load", () => {
  const me = new Identity(P.a_private);
  const alice = new MeshNode({ hello: {} }, me, "Alice");
  const room = alice.contact(P.b_public, { type: "room", name: "Pi Room" });
  room.room = { syncSince: 1760000000, password: "s3cret-pass", loggedIn: true };
  const saved = alice.saveContacts();
  const text = JSON.stringify(saved);
  assert.equal(text.includes("s3cret-pass"), false);
  assert.equal(text.includes('"password"'), false);
  const again = new MeshNode({ hello: {} }, me, "Alice");
  again.loadContacts(saved);
  assert.equal(again.contacts.get(P.b_public).room.password, "s3cret-pass");
  assert.equal(again.contacts.get(P.b_public).room.syncSince, 1760000000);
  const someoneElse = new MeshNode({ hello: {} }, Identity.generate(), "Mallory");
  someoneElse.loadContacts(saved);
  assert.equal(someoneElse.contacts.get(P.b_public).room.password, "");     // another key can't open it
  const legacy = new MeshNode({ hello: {} }, me, "Alice");
  legacy.loadContacts([{ pub: P.b_public, type: "room", room: { syncSince: 5, password: "old-plain" } }]);
  assert.equal(legacy.contacts.get(P.b_public).room.password, "old-plain");
  assert.equal(JSON.stringify(legacy.saveContacts()).includes("old-plain"), false);   // and sealed from then on
});

test("partial contacts (8-byte keys from the name cache): listed, never DMed, replaced by the full key", async () => {
  const { advertPayload } = await import("../src/meshcore.js");
  const alice = new MeshNode({ hello: {} }, new Identity(P.a_private), "Alice");
  const bob = new Identity(P.b_private);
  alice.mergeDirectory([{ pub: bob.pubHex.slice(0, 16), partial: true, type: "chat", name: "Bob", last_heard: 5 },
    { pub: "cd".repeat(8), partial: true, type: "chat", name: "Eve", last_heard: 4 }]);
  assert.equal(alice.contacts.get(bob.pubHex.slice(0, 16)).partial, true);
  alice.handle(parsePacket(floodPacket(4, advertPayload(bob, "Bob", 300))));      // his advert: the full key
  assert.equal(alice.contacts.has(bob.pubHex.slice(0, 16)), false);
  assert.equal(alice.contacts.get(bob.pubHex).name, "Bob");
  alice.mergeDirectory([{ pub: bob.pubHex.slice(0, 16), partial: true, type: "chat", name: "Bob", last_heard: 6 }]);
  assert.equal(alice.contacts.has(bob.pubHex.slice(0, 16)), false);             // (not back as a stub)
  assert.deepEqual([...alice.contacts.values()].map((c) => [c.name, c.partial]), [["Eve", true], ["Bob", false]]);
});

test("route plans: automatic (learned, the server's suggestions, flood), set by hand, flood", async () => {
  const net = air();
  const alice = node(net, P.a_private, "Alice");
  const c = alice.contact(node(net, P.b_private, "Bob").id.pubHex);
  const s1 = { plen: 0x42, path: hexToBytes("a1a1b2b2"), source: "map", score: 0.6 };
  const s2 = { plen: 0x01, path: hexToBytes("c3"), source: "measured", score: 0.3 };
  alice.suggest = async () => [s1, s2];
  const show = (plan) => plan.map((p) => (p.flood ? "flood" : bytesToHex(p.path) + "/" + p.source));
  assert.deepEqual(show(await alice.plan(c)), ["a1a1b2b2/map", "c3/measured", "flood"]);
  [c.outPath, c.outLen] = [hexToBytes("c3"), 0x01];                       // learned: first, and not tried twice
  assert.deepEqual(show(await alice.plan(c)), ["c3/learned", "a1a1b2b2/map", "flood"]);
  alice.suggest = async () => [{ ...s1, score: 0.1 }];                     // weak: another flood is likelier
  assert.deepEqual(show(await alice.plan(c)), ["c3/learned", "flood", "flood"]);
  alice.suggest = async () => [s1, { ...s2, path: hexToBytes("e5"), score: 0.15 }];   // only those worth a try
  [c.outPath, c.outLen] = [new Uint8Array(0), null];
  assert.deepEqual(show(await alice.plan(c)), ["a1a1b2b2/map", "flood", "flood"]);
  [c.outPath, c.outLen] = [hexToBytes("c3"), 0x01];
  alice.suggest = async () => { throw new Error("an older server"); };
  assert.deepEqual(show(await alice.plan(c)), ["c3/learned", "flood", "flood"]);
  [c.outPath, c.outLen] = [new Uint8Array(0), null];
  assert.deepEqual(show(await alice.plan(c)), ["flood", "flood", "flood"]);
  c.routeMode = "flood";
  assert.deepEqual(show(await alice.plan(c, 2)), ["flood", "flood"]);
  c.routeMode = "manual";
  c.manual = { plen: 0x41, path: hexToBytes("d4") };
  assert.deepEqual(show(await alice.plan(c)), ["d4/manual", "d4/manual", "d4/manual"]);
  const saved = alice.saveContacts().find((x) => x.pub === c.pubHex);
  assert.deepEqual([saved.routeMode, saved.manual], ["manual", { path: "d4", plen: 0x41 }]);
});

test("automatic routes: a path that gets through is kept; the learned one failing is dropped", () => {
  const net = air();
  const alice = node(net, P.a_private, "Alice");
  const c = alice.contact(node(net, P.b_private, "Bob").id.pubHex);
  alice.tried(c, { plen: 0x42, path: hexToBytes("a1a1b2b2"), source: "map" }, true);
  assert.equal(bytesToHex(c.outPath) + "/" + c.outLen, "a1a1b2b2/66");
  alice.tried(c, { plen: 0x42, path: hexToBytes("a1a1b2b2"), source: "learned" }, false);
  assert.equal(c.outLen, null);
  c.routeMode = "manual";                                                  // (set by hand: nothing changes by itself)
  alice.tried(c, { plen: 0x01, path: hexToBytes("c3"), source: "manual" }, true);
  assert.equal(c.outLen, null);
});
