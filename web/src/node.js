// A MeshCore chat node in the browser: contacts (from adverts and the server's directory), DMs with their ACKs and
// retries, path returns, and rooms (log in, receive posts, post). A port of meshroom_kaas.Node (client/ in
// pyMeshRoom); all the crypto happens here, so the server only ever sees encrypted packets.
import { bytesToHex, concatBytes, equalBytes, hexToBytes, randomBytes, u32le, utf8Cut, utf8Decode, utf8Encode } from "./bytes.js";
import { sha256 } from "./hash.js";
import { isWeakKey } from "./ed25519.js";
import { keySealer } from "./vault.js";
import {
  ADV_TYPE_CHAT, ADV_TYPE_REPEATER, ADV_TYPE_ROOM, ADV_TYPE_SENSOR, MAX_TEXT_LEN, PT_ACK, PT_ADVERT, PT_ANON_REQ,
  PT_MULTIPART, PT_PATH, PT_RESPONSE, PT_TXT_MSG, TXT_TYPE_PLAIN, TXT_TYPE_SIGNED_PLAIN, directPacket, encryptThenMac,
  floodPacket, macThenDecrypt, parsePacket, pathBytes, pathValid, readAdvert,
} from "./meshcore.js";

export const MAX_ROOM_POST_LEN = 151;       // a room keeps 9 bytes of each post for the author and timestamp
const TYPE_NAMES = { [ADV_TYPE_CHAT]: "chat", [ADV_TYPE_REPEATER]: "repeater", [ADV_TYPE_ROOM]: "room", [ADV_TYPE_SENSOR]: "sensor" };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class LoginFailed extends Error {}

// Events: "advert" (contact), "dm" ({contact, text, ts}), "post" ({room, author: 4-byte key prefix in hex, text, ts}),
// "contacts" (the list changed).
// The server's suggested paths are tried when the best scores this (else floods), and then those scoring the second
// (its room's own thresholds: _build_plan in meshroom.py).
const SUGGEST_FIRST = 0.35;
const SUGGEST_MORE = 0.2;

export class MeshNode extends EventTarget {
  constructor(client, identity, name, { markSeen = () => false, uniqueTime } = {}) {
    super();
    this.client = client;
    this.hashSize = 1;                    // bytes of each repeater's id in the paths of floods we start (1 to 3)
    this.id = identity;
    this.name = name;
    this.markSeen = markSeen;                 // the app's de-duplication: our own packets aren't handled again
    this.uniqueTime = uniqueTime || (() => Math.floor(Date.now() / 1000));
    this.contacts = new Map();                // pubHex -> contact
    this.expected = new Map();                // ACK (hex) -> resolve
    this.logins = new Map();                  // room pubHex -> {resolve}
    this.recent = new Set();                  // DMs and posts already delivered (a resend after a lost ACK: once only)
    this.sealer = keySealer(identity.privateKey);   // room passwords are saved sealed with our private key
  }

  emit(type, detail) {
    this.dispatchEvent(new CustomEvent(type, { detail }));
  }

  // ---------------------------------------------------------------- contacts

  // The contact for a public key, added if new. {pub, pubHex, name, type: "chat" | "repeater" | "room" | "sensor",
  // lat, lon, lastHeard (s), lastAdvert (advert ts), outPath, outLen (null: flood), room: {syncSince, loggedIn, ...}}
  // A "partial" contact is known by the first 8 bytes of its key only (the server's name cache): listed and mentioned,
  // but no DM until its full key turns up, which replaces it.
  contact(pubHex, fields = {}) {
    pubHex = pubHex.toLowerCase();
    let c = this.contacts.get(pubHex);
    if (!c) {
      const partial = pubHex.length === 16;
      if (!partial) {
        const stub = this.contacts.get(pubHex.slice(0, 16));
        if (stub?.partial) {
          this.contacts.delete(stub.pubHex);
          fields = { name: stub.name, lastHeard: stub.lastHeard, ...fields };
        }
      }
      c = { pub: hexToBytes(pubHex), pubHex, name: "", type: "chat", lat: null, lon: null, lastHeard: null,
        lastAdvert: null, outPath: new Uint8Array(0), outLen: null, room: null, partial };
      this.contacts.set(pubHex, c);
    }
    for (const [k, v] of Object.entries(fields)) if (v !== undefined && v !== null && v !== "") c[k] = v;
    return c;
  }

  // The server's node directory (KaaS "nodes"): fills in names, types, positions and when each was last heard.
  mergeDirectory(rows) {
    for (const r of rows || []) {
      const pub = String(r.pub || "").toLowerCase();
      if (pub === this.id.pubHex || pub === this.id.pubHex.slice(0, 16)) continue;
      if (r.partial) {
        if (!/^[0-9a-f]{16}$/.test(pub) || [...this.contacts.keys()].some((k) => k.length === 64 && k.startsWith(pub))) continue;
      } else if (!/^[0-9a-f]{64}$/.test(pub) || isWeakKey(hexToBytes(pub))) continue;
      const c = this.contact(pub);
      if (!c.lastHeard || (r.last_heard || 0) >= c.lastHeard) {
        Object.assign(c, { type: typeof r.type === "string" ? r.type : TYPE_NAMES[r.type] || c.type, lastHeard: r.last_heard });
        if (r.name) c.name = r.name;
        if (r.lat != null) [c.lat, c.lon] = [r.lat, r.lon];
      }
    }
    this.emit("contacts");
  }

  // For saving: what's worth keeping across visits (routes and room state included).
  saveContacts() {
    return [...this.contacts.values()].map((c) => ({
      pub: c.pubHex, name: c.name, type: c.type, lat: c.lat, lon: c.lon, lastHeard: c.lastHeard, lastAdvert: c.lastAdvert,
      outPath: c.outLen == null ? null : bytesToHex(c.outPath), outLen: c.outLen,
      routeMode: c.routeMode === "auto" ? undefined : c.routeMode,
      manual: c.manual ? { path: bytesToHex(c.manual.path), plen: c.manual.plen } : undefined,
      room: c.room ? { syncSince: c.room.syncSince, sealedPassword: this.sealer.seal(c.room.password || "") } : null,
    }));
  }

  loadContacts(list) {
    for (const s of list || []) {
      try {
        const c = this.contact(s.pub, { name: s.name, type: s.type, lat: s.lat, lon: s.lon, lastHeard: s.lastHeard, lastAdvert: s.lastAdvert });
        if (s.outLen != null && pathValid(s.outLen)) [c.outPath, c.outLen] = [hexToBytes(s.outPath || ""), s.outLen];
        if (s.manual && pathValid(s.manual.plen)) c.manual = { path: hexToBytes(s.manual.path || ""), plen: s.manual.plen };
        if (["manual", "flood"].includes(s.routeMode) && (s.routeMode !== "manual" || c.manual)) c.routeMode = s.routeMode;
        if (s.room) {
          // (a password saved in the clear by an older version is read too, and sealed when next saved)
          const password = s.room.sealedPassword ? this.sealer.open(s.room.sealedPassword) : s.room.password;
          c.room = { syncSince: s.room.syncSince || 0, password: password || "", loggedIn: false };
        }
      } catch {
        // a damaged entry: skip it
      }
    }
  }

  // ---------------------------------------------------------------- sending

  // Seconds of airtime for a packet this long, from the radio settings in hello (as the firmware reckons it).
  airtimeMs(length) {
    const r = this.client.hello?.radio;
    if (!r) return 400;
    const ts = (1 << r.sf) / r.bw_hz;
    const de = ts > 0.016 ? 1 : 0;
    const n = 8 + Math.max(Math.ceil((8 * length - 4 * r.sf + 28 + 16) / (4 * (r.sf - 2 * de))) * r.cr, 0);
    return Math.floor((16 + 4.25 + n) * ts * 1000);
  }

  ackTimeoutMs(raw) {
    const pkt = parsePacket(raw), t = this.airtimeMs(raw.length);
    return pkt.isFlood ? 500 + 16 * t : 500 + (t * 6 + 250) * (pkt.hops + 1);
  }

  route(c, ptype, payload, flood = false) {
    return c.outLen == null || flood ? floodPacket(ptype, payload, this.hashSize) : directPacket(ptype, payload, c.outPath, c.outLen);
  }

  // How to send to c, try by try: [{plen, path, source} | {flood: true}], `tries` long. c.routeMode: "flood", only floods;
  // "manual", only c.manual; "auto" (the default): the path learned from c (if any), the server's suggestions, then a
  // flood. A suggestion's score is the chance the room's planner gives it of delivering; as that planner does for its
  // own deliveries, none is used unless the best scores SUGGEST_FIRST, and then only those scoring SUGGEST_MORE: a
  // weaker one is less likely to get through than another flood. this.suggest(c) -> the suggestions (may be []).
  async plan(c, tries = 3) {
    const flood = { flood: true };
    if (c.routeMode === "flood") return Array(tries).fill(flood);
    if (c.routeMode === "manual" && c.manual) return Array(tries).fill({ ...c.manual, source: "manual" });
    const direct = [];
    if (c.outLen != null) direct.push({ plen: c.outLen, path: c.outPath, source: "learned" });
    if (direct.length < tries - 1 && this.suggest) {
      const got = await this.suggest(c).catch(() => []);
      const usable = got.length && got[0].score >= SUGGEST_FIRST ? got.filter((p) => p.score >= SUGGEST_MORE) : [];
      for (const p of usable) {
        if (direct.length >= tries - 1) break;
        if (!direct.some((d) => d.plen === p.plen && equalBytes(d.path, p.path))) direct.push({ ...p, source: p.source || "suggested" });
      }
    }
    if (!direct.length) return Array(tries).fill(flood);
    return [...direct, ...Array(tries - direct.length).fill(flood)];
  }

  // A try's outcome, in automatic mode: a path that worked is the one to use from now on; the learned one failing is
  // forgotten (the next message asks the server again, then floods).
  tried(c, step, ok) {
    if (c.routeMode && c.routeMode !== "auto") return;
    if (ok && !step.flood && step.source !== "learned") [c.outPath, c.outLen] = [step.path, step.plen];
    if (!ok && step.source === "learned" && c.outLen === step.plen && equalBytes(c.outPath, step.path))
      [c.outPath, c.outLen] = [new Uint8Array(0), null];
    this.emit("contacts");
  }

  packetFor(step, ptype, payload) {
    return step.flood ? floodPacket(ptype, payload, this.hashSize) : directPacket(ptype, payload, step.path, step.plen);
  }

  datagram(c, data) {
    return concatBytes(new Uint8Array([c.pub[0], this.id.pub[0]]), encryptThenMac(this.id.sharedSecret(c.pub), data));
  }

  pathReturn(c, path, pathLen, extraType = null, extra = null) {
    let data = concatBytes(new Uint8Array([pathLen]), path.subarray(0, pathBytes(pathLen)));
    data = concatBytes(data, extra ? concatBytes(new Uint8Array([extraType]), extra) : concatBytes(new Uint8Array([0xff]), randomBytes(4)));
    return this.datagram(c, data);
  }

  // ACKs and path returns skip the rate limit (the server exempts them: a node must answer what it's sent).
  sendNow(raw) {
    if (this.readOnly) return Promise.resolve({ status: "dropped", reason: "read only" });
    this.markSeen(raw);
    return this.client.sendNow(raw);
  }

  send(raw) {
    this.markSeen(raw);
    return this.client.send(raw);
  }

  // A direct message (or a post, to a room). Retries until ACKed, the last try by flood. -> {acked, status, reason}
  // ts: its timestamp (the same on every try), which a reaction to it hashes.
  // -> {acked, status, reason, via: the try that was ACKed ({plen, path, source} | {flood: true})}
  async sendDm(c, text, attempts = 3, onAttempt = () => {}, ts = this.uniqueTime()) {
    const body = utf8Cut(utf8Encode(text), c.room ? MAX_ROOM_POST_LEN : MAX_TEXT_LEN);
    const plan = await this.plan(c, attempts);
    let last = { status: "dropped", reason: "not sent" };
    for (let attempt = 0; attempt < plan.length; attempt++) {
      const step = plan[attempt];
      const data = concatBytes(u32le(ts), new Uint8Array([(TXT_TYPE_PLAIN << 2) | (attempt & 3)]), body);
      const ack = bytesToHex(sha256(concatBytes(data, this.id.pub)).subarray(0, 4));
      const raw = this.packetFor(step, PT_TXT_MSG, this.datagram(c, data));
      const acked = new Promise((resolve) => this.expected.set(ack, resolve));
      onAttempt(attempt, step);
      last = await this.send(raw);
      if (last.status === "sent" || last.status === "local") {
        const got = await Promise.race([acked.then(() => true), sleep(this.ackTimeoutMs(raw) + 2000).then(() => false)]);
        this.tried(c, step, got);
        if (got) return { acked: true, status: last.status, via: step };
      }
      this.expected.delete(ack);
    }
    return { acked: false, status: last.status, reason: last.reason || "no ACK" };
  }

  // Log in to a room server. Its posts then arrive as "post" events. Throws LoginFailed.
  async joinRoom(pubHex, password = "", timeoutMs = 30000) {
    const c = this.contact(pubHex, { type: "room" });
    c.room ||= { syncSince: 0, password: "", loggedIn: false };
    c.room.password = password;
    const data = concatBytes(u32le(this.uniqueTime()), u32le(c.room.syncSince), utf8Encode(password).subarray(0, 15));
    const payload = concatBytes(new Uint8Array([c.pub[0]]), this.id.pub, encryptThenMac(this.id.sharedSecret(c.pub), data));
    const answer = new Promise((resolve) => this.logins.set(pubHex, resolve));
    // a direct try first (when there's a path to try), then a flood with the rest of the time
    const plan = (await this.plan(c, 2)).filter((s, i, all) => !s.flood || i === all.length - 1 || !all[i + 1]?.flood);
    let ok = null, sent = null;
    for (const [i, step] of plan.entries()) {
      const res = await this.send(this.packetFor(step, PT_ANON_REQ, payload));
      if (res.status !== "sent" && res.status !== "local") {
        sent ||= res;
        continue;
      }
      sent = res;
      const wait = i < plan.length - 1 ? Math.min(12000, timeoutMs / 2) : timeoutMs;
      ok = await Promise.race([answer, sleep(wait).then(() => null)]);
      this.tried(c, step, ok !== null);
      if (ok !== null) break;
    }
    this.logins.delete(pubHex);
    if (sent && sent.status !== "sent" && sent.status !== "local")
      throw new LoginFailed("the login wasn't sent: " + (sent.reason || sent.status));
    if (ok === null) throw new LoginFailed("no answer from the room (a wrong password, or it didn't hear the login)");
    if (!ok.ok) throw new LoginFailed("the room refused the login");
    Object.assign(c.room, { loggedIn: true, isAdmin: ok.isAdmin, perms: ok.perms });
    this.emit("contacts");
    return c;
  }

  // ---------------------------------------------------------------- receiving

  // A packet the radio heard or sent (already de-duplicated by the app). readOnly: an old one (a catch-up) or one an
  // MQTT observer heard: read it, but answer nothing (no ACKs, no paths) and learn no route from it.
  handle(pkt, { readOnly = false } = {}) {
    if (!pkt.isFlood && pkt.hops > 0) return;           // still on its way through repeaters: not for us yet
    this.readOnly = readOnly;
    try {
      this.dispatch(pkt);
    } finally {
      this.readOnly = false;
    }
  }

  dispatch(pkt) {
    const t = pkt.ptype, p = pkt.payload;
    if (t === PT_ADVERT) this.rxAdvert(p);
    else if (t === PT_TXT_MSG || t === PT_RESPONSE || t === PT_PATH) this.rxPeer(pkt);
    else if (t === PT_ACK && p.length >= 4) this.rxAck(p.subarray(0, 4));
    else if (t === PT_MULTIPART && p.length >= 5 && (p[0] & 15) === PT_ACK) this.rxAck(p.subarray(1, 5));
  }

  rxAck(ack) {
    const k = bytesToHex(ack);
    const resolve = this.expected.get(k);
    if (resolve) {
      this.expected.delete(k);
      resolve();
    }
  }

  rxAdvert(payload) {
    if (payload.length < 101 || equalBytes(payload.subarray(0, 32), this.id.pub)) return;
    const known = this.contacts.get(bytesToHex(payload.subarray(0, 32)));
    const ts = (payload[32] | (payload[33] << 8) | (payload[34] << 16) | (payload[35] << 24)) >>> 0;
    if (known && known.lastAdvert != null && ts <= known.lastAdvert) return;     // older, or a replay: skip the check
    const a = readAdvert(payload);
    if (!a) return;
    const c = this.contact(a.pubHex, { name: a.name, type: TYPE_NAMES[a.type] || "chat", lastAdvert: a.ts,
      lastHeard: Math.floor(Date.now() / 1000) });
    if (a.lat != null) [c.lat, c.lon] = [a.lat, a.lon];
    this.emit("advert", c);
    this.emit("contacts");
  }

  rxPeer(pkt) {
    const p = pkt.payload;
    if (p.length <= 4 || p[0] !== this.id.pub[0]) return;
    for (const c of this.contacts.values()) {
      if (c.partial || c.pub[0] !== p[1]) continue;
      let secret;
      try {
        secret = this.id.sharedSecret(c.pub);
      } catch {
        continue;                                         // (a weak key: never a real node)
      }
      const data = macThenDecrypt(secret, p.subarray(2));
      if (!data) continue;
      if (pkt.ptype === PT_PATH) this.rxPath(pkt, c, data);
      else if (pkt.ptype === PT_TXT_MSG) this.rxTxt(pkt, c, data);
      else if (pkt.ptype === PT_RESPONSE) this.rxResponse(c, data);
      return;
    }
  }

  rxPath(pkt, c, data) {
    const plen = data[0];
    if (!pathValid(plen)) return;
    const k = 1 + pathBytes(plen);
    const path = Uint8Array.from(data.subarray(1, k));
    const extraType = k < data.length ? data[k] & 15 : 0xff;
    const extra = data.subarray(k + 1);
    if (!this.readOnly) [c.outPath, c.outLen] = [path, plen];   // how to reach them directly from now on
    if (extraType === PT_ACK && extra.length >= 4) this.rxAck(extra.subarray(0, 4));
    else if (extraType === PT_RESPONSE && extra.length) this.rxResponse(c, extra);
    if (pkt.isFlood) this.sendNow(directPacket(PT_PATH, this.pathReturn(c, pkt.path, pkt.pathLen), path, plen));
  }

  replyAck(pkt, c, ack) {
    let raw;
    if (pkt.isFlood) raw = floodPacket(PT_PATH, this.pathReturn(c, pkt.path, pkt.pathLen, PT_ACK, ack), pkt.hashSize);
    else if (c.outLen == null) raw = floodPacket(PT_ACK, ack, this.hashSize);
    else raw = directPacket(PT_ACK, ack, c.outPath, c.outLen);
    this.sendNow(raw);
  }

  rxTxt(pkt, c, data) {
    if (data.length <= 5) return;
    const ts = (data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)) >>> 0;
    const kind = data[4] >> 2;
    const end = (from) => { const z = data.indexOf(0, from); return z < 0 ? data.length : z; };
    if (kind === TXT_TYPE_PLAIN) {
      const e = end(5);
      this.replyAck(pkt, c, sha256(concatBytes(data.subarray(0, e), c.pub)).subarray(0, 4));
      const text = utf8Decode(data.subarray(5, e));
      if (this.fresh(c.pubHex + "|" + ts + "|" + text)) this.emit("dm", { contact: c, text, ts });
    } else if (kind === TXT_TYPE_SIGNED_PLAIN && data.length > 9 && c.room) {
      // a room on the server we're connected to is read through the server instead: what it pushes over the air is for
      // our radio (the same key on a companion app), so it's left for that radio to ACK
      if (this.isLocalRoom?.(c.pubHex)) return;
      const e = end(9);
      this.replyAck(pkt, c, sha256(concatBytes(data.subarray(0, e), this.id.pub)).subarray(0, 4));
      c.room.syncSince = Math.max(c.room.syncSince || 0, ts);
      const author = bytesToHex(data.subarray(5, 9)), text = utf8Decode(data.subarray(9, e));
      if (this.fresh(c.pubHex + "|" + ts + "|" + author + "|" + text)) this.emit("post", { room: c, author, text, ts });
    }
  }

  fresh(k) {
    if (this.recent.has(k)) return false;
    this.recent.add(k);
    if (this.recent.size > 512) this.recent.delete(this.recent.values().next().value);
    return true;
  }

  rxResponse(c, data) {
    const resolve = this.logins.get(c.pubHex);
    if (!resolve || data.length < 5) return;
    resolve({ ok: data[4] === 0, isAdmin: data.length >= 8 && data[6] === 1, perms: data.length >= 8 ? data[7] : 0 });
  }
}
