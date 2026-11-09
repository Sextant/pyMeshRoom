// The web app: log in, then talk on MeshCore channels, in DMs and in rooms through pyMeshRoom's KaaS API.
// The private key, channel secrets and room passwords never leave the browser; the server only sees encrypted packets.
import { bytesToHex, hexToBytes, randomBytes, utf8Decode, utf8Encode } from "./bytes.js";
import {
  QUICK_REACTIONS, buildReply, emojiOnly, hashTexts, messageHash, parseReaction, parseReply, quoteMatches, reactionText,
} from "./format.js";
import { EMOJI_CATEGORIES, RECENT_MAX } from "./emoji.js";
import { findGifs, gifFallbackUrl, gifPageUrl, gifThumbUrl, gifUrl } from "./gif.js";
import { sha256 } from "./hash.js";
import { AuthError, KaasClient, PagePasswordNeeded, kaasEndpoints } from "./kaas.js";
import { showMap } from "./map.js";
import {
  Identity, MAX_NAME_LEN, MAX_TEXT_LEN, PT_ADVERT, PT_GRP_TXT, advertPayload, channelMessagePacket, floodPacket,
  makeChannel, packetHash, parsePacket, readChannelMessage, textBudget, zeroHopPacket,
} from "./meshcore.js";
import { LoginFailed, MAX_ROOM_POST_LEN, MeshNode } from "./node.js";
import {
  loadChannels, loadContacts, loadCursor, saveCursor, loadConversations, loadHistory, loadMotdHidden, loadRecentEmoji,
  loadSettings, saveChannels, saveContacts, saveConversations, saveHistory, saveMotdHidden, saveRecentEmoji, saveSettings,
} from "./store.js";
import { seal, unseal } from "./vault.js";

const HISTORY_PER_CONVERSATION = 300;
const SUGGEST_KEEP_MS = 5 * 60 * 1000;
const SEEN_MAX = 4096;
const DIRECTORY_EVERY_MS = 15 * 60 * 1000;     // the server's node directory, refreshed this often
const DIRECTORY_DAYS = 30;
const REACTION_WINDOW_MS = 7 * 86400 * 1000;   // a reaction is matched against messages this recent
const $ = (id) => document.getElementById(id);

const app = {
  identity: null,
  name: "",
  client: null,
  node: null,                   // MeshNode: contacts, DMs, rooms
  channels: [],                 // makeChannel() objects, Public first
  dms: [],                      // public keys (hex) with a DM conversation, newest first
  active: null,                 // the conversation on screen: a channel's keyHex, "dm:<pub>" or "room:<pub>"
  history: {},                  // conversation -> [message]
  unread: {},                   // conversation -> count
  seen: new Set(),              // packet hashes already handled (floods arrive once per repeater)
  lastTs: 0,
  saveTimer: null,
  dirTimer: null,
  lastPkt: null,                // the packet being handled (for a DM's hops and SNR)
  directoryError: null,
  cursor: null,                 // the last backlog seq handled (the server numbers channel messages and DMs)
  catchingUp: false,
  replayQueue: [],
};
let autoTried = false;          // connect by ourselves once per page load (not again after logging out)

// ---------------------------------------------------------------- small DOM helpers

function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") e.className = v;
    else if (k === "dataset") Object.assign(e.dataset, v);
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c != null && c !== false) e.append(c);
  return e;
}

let toastTimer;
function toast(text) {
  const t = $("toast");
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 3500);
}

function showError(id, text) {
  $(id).textContent = text || "";
  $(id).hidden = !text;
}

function ago(s) {
  if (!s) return "never";
  const d = Math.max(0, Date.now() / 1000 - s);
  return d < 60 ? "just now" : d < 3600 ? Math.round(d / 60) + " min ago" : d < 86400 ? Math.round(d / 3600) + " h ago"
    : Math.round(d / 86400) + " d ago";
}

const newId = () => crypto.randomUUID?.() || bytesToHex(randomBytes(8));

// ---------------------------------------------------------------- theme

// How many bytes of each repeater's id the floods we start collect in their path (MeshCore's path hash mode): 2 by
// default. Longer ids mix up fewer repeaters, so the direct paths learned from those floods are surer.
function pathHashSize() {
  const n = Number(loadSettings().pathHash);
  return [1, 2, 3].includes(n) ? n : 2;
}

function applyTheme(choice = loadSettings().theme || "dark") {
  const light = choice === "light" || (choice === "system" && matchMedia("(prefers-color-scheme: light)").matches);
  if (light) document.documentElement.dataset.theme = "light";
  else delete document.documentElement.dataset.theme;
  $("theme").value = choice;
}

// ---------------------------------------------------------------- login

// Served by pyMeshRoom itself (at .../meshcore-web/): the server is the one this page came from, behind whatever
// proxy path it sits on. Otherwise (a file on disk, another host) null, and the URL is typed in.
function servedBy() {
  if (!/^https?:$/.test(location.protocol)) return null;
  const m = location.pathname.match(/^(.*?)\/meshcore-web(?:\/[^/]*)?$/);
  return m ? location.origin + m[1] : null;
}

// A phone's on-screen keyboard covers the page without resizing it (iOS, and Chrome without interactive-widget): keep
// the chat, and so the composer, within what's visible.
function fitToKeyboard() {
  const vv = window.visualViewport;
  if (!vv) return;
  const fit = () => {
    const covered = window.innerHeight - vv.height > 60;     // (more than the browser's bars: a keyboard)
    document.documentElement.style.setProperty("--app-h", covered ? vv.height + "px" : "");
    if (covered) window.scrollTo(0, 0);                        // (iOS pans the page up instead)
  };
  vv.addEventListener("resize", fit);
  vv.addEventListener("scroll", fit);
}

function initLogin() {
  const s = loadSettings();
  const served = servedBy();
  $("f-url").value = served && !s.otherServer ? served : s.url || "";
  $("url-box").hidden = !!served && !s.otherServer;
  $("url-auto").hidden = !served || !!s.otherServer;
  $("url-host").textContent = served ? new URL(served).host : "";
  $("f-name").value = s.name || "";
  $("f-remember").checked = s.remember !== false;            // (on unless they turned it off)
  $("f-pass").value = "";
  $("pass-box").hidden = s.remember === false;
  $("f-priv").value = s.remember && !s.vault ? s.privateKey || "" : "";
  setUnlockMode(!!(s.remember && s.vault));
  $("f-sitepw").value = s.remember && !s.vault ? s.pagePassword || "" : "";
  $("sitepw-box").hidden = !$("f-sitepw").value;
  updatePubPreview();
  $("login").hidden = false;
  if (!autoTried && s.remember && s.privateKey && s.name && $("f-url").value) {
    autoTried = true;                                   // remembered, without a passphrase: connect by ourselves
    return login();
  }
  autoTried = true;
  const empty = ["f-url", "f-unlock", "f-priv", "f-name"].map($).find((i) => !i.value && !i.closest("[hidden]"));
  (empty || $("login-go")).focus();
}

function setUnlockMode(on) {
  $("unlock-box").hidden = !on;
  $("priv-box").hidden = on;
  $("f-unlock").value = "";
}

let previewTimer;
function updatePubPreview() {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(() => {
    const v = $("f-priv").value.trim();
    const hint = $("f-pub");
    if (!v) {
      hint.textContent = "Exported from a MeshCore app, or press New to make one. Keep a copy: a new key is a new node.";
      return;
    }
    try {
      hint.textContent = "Public key: " + new Identity(v).pubHex;
      hint.classList.add("mono");
    } catch (e) {
      hint.textContent = e.message === "not hex" ? "That isn't hex." : e.message;
      hint.classList.remove("mono");
    }
  }, 150);
}

async function login(ev) {
  ev?.preventDefault();
  showError("login-error", "");
  const s = loadSettings();
  const url = $("f-url").value.trim();
  let pagePassword = $("f-sitepw").value;
  let priv = $("f-priv").value.trim();
  const name = $("f-name").value.trim();
  const go = $("login-go");
  if (!$("unlock-box").hidden) {
    go.disabled = true;
    go.textContent = "Unlocking…";
    await new Promise((r) => setTimeout(r, 20));        // (let the button repaint: unlocking takes about a second)
    const opened = await unseal(s.vault || {}, $("f-unlock").value);
    go.disabled = false;
    go.textContent = "Connect";
    if (!opened) return showError("login-error", "That passphrase doesn't unlock the saved key.");
    ({ privateKey: priv, pagePassword = pagePassword } = JSON.parse(utf8Decode(opened)));
  }
  let identity;
  try {
    const ep = kaasEndpoints(url);
    if (location.protocol === "https:" && !ep.secure) throw new Error("This page is on HTTPS, so the server must be too (https://).");
    identity = new Identity(priv);
    if (!name) throw new Error("Enter your name.");
    if (utf8Encode(name).length > MAX_NAME_LEN) throw new Error("Your name is at most " + MAX_NAME_LEN + " bytes.");
  } catch (e) {
    return showError("login-error", e.message === "not hex" ? "The private key isn't hex." : e.message);
  }
  const remember = $("f-remember").checked;
  const otherServer = !$("url-box").hidden && !!servedBy();
  const prefs = { url, name, remember, otherServer, gifs: s.gifs, theme: s.theme, pathHash: s.pathHash };
  if (!remember) saveSettings(prefs);
  else if (!$("unlock-box").hidden) saveSettings({ ...prefs, vault: s.vault });   // (unlocked: keep it sealed)
  else if ($("f-pass").value) {
    go.textContent = "Saving…";
    await new Promise((r) => setTimeout(r, 20));
    saveSettings({ ...prefs, vault: await seal(utf8Encode(JSON.stringify({ privateKey: identity.privateHex, pagePassword })), $("f-pass").value) });
  } else saveSettings({ ...prefs, pagePassword: pagePassword || undefined, privateKey: identity.privateHex });

  go.disabled = true;
  go.textContent = "Connecting…";
  const client = new KaasClient(url, { identity, name, pagePassword });
  try {
    await client.start();
  } catch (e) {
    client.stop();
    go.disabled = false;
    go.textContent = "Connect";
    if (e instanceof PagePasswordNeeded) {
      const asked = !$("sitepw-box").hidden;
      $("sitepw-box").hidden = false;
      $("f-sitepw").focus();
      return showError("login-error", asked && pagePassword ? "That isn't the server's page password." :
        "This server's MeshCore Web needs a password: enter it above.");
    }
    return showError("login-error", e instanceof AuthError ? "The server refused the login: " + e.message : e.message);
  }
  go.disabled = false;
  go.textContent = "Connect";
  $("f-priv").value = remember && !loadSettings().vault ? $("f-priv").value : "";
  $("f-sitepw").value = remember && !loadSettings().vault ? $("f-sitepw").value : "";
  $("f-pass").value = $("f-unlock").value = "";
  startChat(identity, name, client);
}

// ---------------------------------------------------------------- chat session

function startChat(identity, name, client) {
  Object.assign(app, { identity, name, client, unread: {}, seen: new Set(), motdShown: false });
  app.channels = [makeChannel("Public", "public")];
  for (const c of loadChannels(identity.pubHex) || []) {
    if (c.kind === "public") continue;
    try {
      if (!app.channels.some((x) => x.keyHex === c.keyHex)) app.channels.push(makeChannel(c.name, c.kind, c.keyHex));
    } catch {
      // a damaged entry: skip it
    }
  }
  app.history = loadHistory(identity.pubHex) || {};
  for (const msgs of Object.values(app.history))
    for (const m of msgs) if (m.mine && ["sending", "waiting", "retrying"].includes(m.status)) m.status = "unknown";

  const node = new MeshNode(client, identity, name, {
    markSeen: (raw) => markSeen(packetHash(parsePacket(raw))), uniqueTime,
  });
  node.loadContacts(loadContacts(identity.pubHex));
  node.isLocalRoom = isLocalRoom;
  node.hashSize = pathHashSize();
  node.suggest = suggestPaths;
  app.server = client.endpoints.ws;
  app.cursor = loadCursor(identity.pubHex, app.server);
  for (const c of node.contacts.values()) if (c.room) c.room.loggedIn = false;
  app.node = node;
  const convs = loadConversations(identity.pubHex);
  app.dms = (convs.dms || []).filter((p) => /^[0-9a-f]{64}$/.test(p));
  app.active = convs.last && conv(convs.last) ? convs.last : app.channels[0].keyHex;

  node.addEventListener("dm", (e) => onDm(e.detail));
  node.addEventListener("post", (e) => onPost(e.detail));
  node.addEventListener("contacts", () => {
    renderSidebar();
    if ($("dlg-contacts").open) renderContacts();       // (an advert heard while the list is open)
    scheduleSave();
  });
  client.addEventListener("packet", (e) => onPacket(e.detail));
  client.addEventListener("replay", (e) => onReplay(e.detail));
  client.addEventListener("state", (e) => onState(e.detail));
  client.addEventListener("hello", () => onHello());
  client.addEventListener("room_post", (e) => {
    const c = app.node.contacts.get(String(e.detail.room).toLowerCase());
    if (c?.room?.local) addLocalPost(c, e.detail);
  });
  client.addEventListener("dropped", (e) => toast("The server skipped " + e.detail + " packets (this tab fell behind)."));
  client.addEventListener("access", (e) => {
    toast(e.detail.send ? "Your key was heard on the mesh: you can send now." : "Sending was turned off for your key.");
    onState({ state: client.state });
    if (e.detail.send) loginRooms();
  });

  $("me-name").textContent = name;
  $("me-key").textContent = identity.pubHex.slice(0, 8);
  $("me-key").title = identity.pubHex;
  $("login").hidden = true;
  $("chat").hidden = false;
  onState({ state: client.state });
  onHello();
  clearInterval(app.dirTimer);
  app.dirTimer = setInterval(refreshDirectory, DIRECTORY_EVERY_MS);
  renderSidebar();
  renderConversation();
  $("text").focus();
}

// Each (re)connect: the rooms on this radio, the server's directory, and logging in to our rooms again.
function onHello() {
  const h = app.client?.hello;
  renderServer();
  if (!h) return;
  showMotd(h.motd);
  for (const pub of [h.nodes?.room, ...(h.nodes?.tenants || [])].filter(Boolean))
    app.node.contact(pub, { type: "room", name: h.names?.[pub] });
  refreshDirectory();
  loginRooms();
  catchUp();
}

async function refreshDirectory() {
  if (!app.client || app.client.state !== "open") return;
  try {
    const r = await app.client.request("nodes", { days: DIRECTORY_DAYS });
    app.directoryError = null;
    app.node.mergeDirectory(r.nodes);
  } catch (e) {
    app.directoryError = e.message;                     // (an older pyMeshRoom: adverts still fill the list)
  }
}

function loginRooms() {
  if (!canSend()) return;                                 // (rooms wait until this key may send, on this server too)
  for (const c of app.node.contacts.values()) if (c.room && !c.room.loggedIn) roomLogin(c, c.room.password || "", true);
}

// The admin's message of the day: once per login (not on every reconnect), unless this browser was asked not to show
// this one again. Plain text.
function showMotd(text) {
  if (app.motdShown || !text) return;
  app.motdShown = true;
  const id = bytesToHex(sha256(utf8Encode(text))).slice(0, 16);
  if (loadMotdHidden() === id) return;
  $("motd-text").textContent = text;
  $("motd-hide").checked = false;
  $("motd-ok").onclick = () => {
    if ($("motd-hide").checked) saveMotdHidden(id);
    $("dlg-motd").close();
  };
  $("dlg-motd").showModal();
}

// The server's suggested direct paths to c (KaaS "paths": as its room plans its own deliveries), kept 5 minutes.
// -> [{plen, path: bytes, hops: [hex], names, score, source}] (none when the server can't say, or is too old to know)
async function suggestPaths(c, fresh = false) {
  const got = c.suggested;
  if (!fresh && got && Date.now() - got.at < SUGGEST_KEEP_MS) return got.paths;
  let paths = [];
  try {
    const r = await app.client.request("paths", { node: c.pubHex, limit: 4 });
    paths = (r.paths || []).map((p) => ({ ...p, plen: p.path_len, path: hexToBytes(p.path) }));
  } catch {
    // (an older server, or none of its budget left: the learned path and floods still work)
  }
  c.suggested = { at: Date.now(), paths };
  return paths;
}

// A path for people: "a1 › b2 › c3" (repeater ids), "zero hop", or "flood".
function pathText(step) {
  if (!step || step.flood) return "flood";
  const sz = (step.plen >> 6) + 1, n = step.plen & 63;
  if (!n) return "zero hop";
  return Array.from({ length: n }, (_, i) => bytesToHex(step.path.subarray(i * sz, (i + 1) * sz))).join(" › ");
}

// What a DM or room conversation will be sent by, for its subtitle.
function routeText(c) {
  if (c.routeMode === "flood") return "route: flood (set)";
  if (c.routeMode === "manual" && c.manual) return "route: " + pathText(c.manual) + " (set)";
  return c.outLen == null ? "route: automatic (server's suggestion, then flood)"
    : "route: " + pathText({ plen: c.outLen, path: c.outPath }) + " (learned)";
}

// A room on the server we're connected to (its own room, or a tenant room).
function isLocalRoom(pubHex) {
  const n = app.client?.hello?.nodes, k = String(pubHex).toLowerCase();
  return !!n && [n.room, ...(n.tenants || [])].some((x) => String(x || "").toLowerCase() === k);
}

// A room on this server is read through the server, not logged in to over the air: the room keeps one sync point and
// one route per key, and those belong to our radio (the same key on a companion app), which would lose posts to us.
async function readLocalRoom(c, password) {
  let r;
  try {
    r = await app.client.request("room", { room: c.pubHex, since: c.room?.syncSince || 0, password: password || "" });
  } catch (e) {
    throw new LoginFailed(e.message);
  }
  c.room ||= { syncSince: 0, password: "", loggedIn: false };
  Object.assign(c.room, { password, loggedIn: true, local: true, isAdmin: r.admin, perms: r.perms, canPost: r.can_post });
  if (r.name && !c.name) c.name = r.name;
  for (const p of r.posts || []) addLocalPost(c, p);
  app.node.emit("contacts");
}

// A post from a room on this server ({ts, author: full key, name, text, private}), as an "over the air" one would be.
function addLocalPost(c, p) {
  c.room.syncSince = Math.max(c.room.syncSince || 0, p.ts);
  const author = String(p.author).slice(0, 8).toLowerCase();
  if (!app.node.fresh(c.pubHex + "|" + p.ts + "|" + author + "|" + p.text)) return;
  const key = "room:" + c.pubHex;
  if (String(p.author).toLowerCase() === app.identity.pubHex) {
    // ours: the one we're posting from this page becomes it (the room's stamp is the one reactions use)
    const ours = (app.history[key] || []).find((m) => m.mine && m.text === p.text && !m.roomTs && m.status !== "failed");
    if (ours) {
      Object.assign(ours, { ts: p.ts, roomTs: true, status: "delivered", reason: "" });
      reactionHashes.delete(ours);
      updateMessage(ours);
      return scheduleSave();
    }
  }
  onPost({ room: c, author, text: p.text, ts: p.ts, name: p.name });
}

async function roomLogin(c, password, quiet = false) {
  try {
    if (isLocalRoom(c.pubHex)) await readLocalRoom(c, password);
    else await app.node.joinRoom(c.pubHex, password);
    if (!quiet) toast("Joined " + contactName(c) + ".");
    renderSidebar();
    if (app.active === "room:" + c.pubHex) renderConversation();
    scheduleSave();
    return true;
  } catch (e) {
    if (!quiet) throw e;
    renderSidebar();
    return false;
  }
}

function logout() {
  app.client?.stop();
  clearInterval(app.dirTimer);
  flushSave();
  const s = loadSettings();
  if (!s.remember) saveSettings({ url: s.url, name: s.name, remember: false, otherServer: s.otherServer, gifs: s.gifs, theme: s.theme, pathHash: s.pathHash });
  Object.assign(app, { identity: null, client: null, node: null, channels: [], dms: [], history: {}, unread: {}, active: null });
  $("chat").hidden = true;
  $("messages").replaceChildren();
  document.title = "MeshCore Web";
  initLogin();
}

function persistChannels() {
  saveChannels(app.identity.pubHex, app.channels.map((c) => ({ name: c.name, kind: c.kind, keyHex: c.keyHex })));
}

function scheduleSave() {
  clearTimeout(app.saveTimer);
  app.saveTimer = setTimeout(flushSave, 500);
}

function flushSave() {
  clearTimeout(app.saveTimer);
  if (!app.identity) return;
  for (const k of Object.keys(app.history)) app.history[k] = app.history[k].slice(-HISTORY_PER_CONVERSATION);
  saveHistory(app.identity.pubHex, app.history);
  saveContacts(app.identity.pubHex, app.node.saveContacts());
  saveConversations(app.identity.pubHex, { dms: app.dms, last: app.active });
  if (app.cursor != null) saveCursor(app.identity.pubHex, app.server, app.cursor);
}

function markSeen(hash) {
  if (app.seen.has(hash)) return true;
  app.seen.add(hash);
  if (app.seen.size > SEEN_MAX) app.seen.delete(app.seen.values().next().value);
  return false;
}

function uniqueTime() {
  app.lastTs = Math.max(Math.floor(Date.now() / 1000), app.lastTs + 1);
  return app.lastTs;
}

// ---------------------------------------------------------------- conversations

const contactName = (c) => c.name || c.pubHex.slice(0, 8);

// The conversation for a key: {kind: "channel" | "dm" | "room", title, sub, channel | contact}, or null.
function conv(key = app.active) {
  if (!key) return null;
  if (key.startsWith("dm:") || key.startsWith("room:")) {
    const pub = key.slice(key.indexOf(":") + 1);
    if (!app.node || !/^[0-9a-f]{64}$/.test(pub)) return null;
    const c = app.node.contact(pub);
    if (key.startsWith("dm:")) {
      return { kind: "dm", key, contact: c, title: contactName(c),
        sub: "Direct message · " + pub.slice(0, 8) + " · " + routeText(c) };
    }
    if (!c.room) return null;
    return { kind: "room", key, contact: c, title: contactName(c),
      sub: "Room · " + (c.room.loggedIn ? "logged in" + (c.room.isAdmin ? " as admin" : "") : "not logged in") +
        (isLocalRoom(c.pubHex) ? " · on this server" : " · " + routeText(c)) };
  }
  const ch = app.channels.find((c) => c.keyHex === key);
  return ch && { kind: "channel", key, channel: ch, title: ch.name, sub: {
    public: "The public channel every MeshCore node knows",
    hashtag: "Hashtag channel: anyone who knows the name can read it",
    private: "Private channel: only people with its secret can read it",
  }[ch.kind] };
}

function budget(cv = conv()) {
  if (!cv) return 0;
  return cv.kind === "channel" ? textBudget(app.name) : cv.kind === "room" ? MAX_ROOM_POST_LEN : MAX_TEXT_LEN;
}

// ---------------------------------------------------------------- receiving

// A packet: live from the radio, from an MQTT observer ("mqtt"), or caught up on (old: then `at` is when the server got
// it). Old and MQTT ones are read only.
function onPacket({ dir, raw, snr, seq, old = false, at = null }) {
  if (seq != null) {
    // while catching up, only the catch-up moves the cursor: a live packet is newer than what's still to come
    if (app.catchingUp && !old) app.liveSeq = Math.max(app.liveSeq || 0, seq);
    else if (app.cursor == null || seq > app.cursor) app.cursor = seq;
  }
  const pkt = parsePacket(raw);
  if (!pkt) return;
  if (markSeen(packetHash(pkt))) return;                     // another copy, or our own packet going out
  app.lastPkt = { pkt, dir, snr, old, at };
  if (pkt.ptype === PT_GRP_TXT) onChannelPacket(pkt, dir, snr);
  else app.node.handle(pkt, { readOnly: old || dir === "mqtt" });
  app.lastPkt = null;
}

function onChannelPacket(pkt, dir, snr) {
  const m = readChannelMessage(app.channels, pkt.payload);
  if (!m) return;
  const msgs = app.history[m.channel.keyHex] || [];
  if (msgs.some((x) => x.ts === m.ts && x.sender === m.sender && x.text === m.text)) return;   // (resent)
  // a retry: the same text from the same sender, stamped anew. One message, but a reaction may hash either stamp
  const retried = msgs.slice(-30).find((x) => !x.mine && !x.reaction && x.sender === m.sender && x.text === m.text &&
    Math.abs(x.ts - m.ts) <= 120);
  if (retried) {
    retried.tsAlt = [...new Set([...(retried.tsAlt || []), m.ts])];
    reactionHashes.delete(retried);
    attachParked(m.channel.keyHex, retried);
    return scheduleSave();
  }
  addIncoming(m.channel.keyHex, { id: newId(), ts: m.ts, at: app.lastPkt?.at || Date.now(), sender: m.sender, text: m.text,
    hops: pkt.isFlood ? pkt.hops : null, snr: dir === "rx" ? snr : null, dir, old: app.lastPkt?.old || undefined });
}

function routeOf() {
  const l = app.lastPkt;
  return l ? { hops: l.pkt.isFlood ? l.pkt.hops : null, snr: l.dir === "rx" ? l.snr : null, dir: l.dir, old: l.old || undefined,
    at: l.at || Date.now() } : {};
}

function onDm({ contact, text, ts }) {
  app.dms = [contact.pubHex, ...app.dms.filter((p) => p !== contact.pubHex)];
  addIncoming("dm:" + contact.pubHex, { id: newId(), ts, sender: contactName(contact), text, ...routeOf() });
}

function onPost({ room, author, text, ts, name }) {
  const mine = author === app.identity.pubHex.slice(0, 8);
  const who = mine ? app.name : [...app.node.contacts.values()].find((c) => c.pubHex.startsWith(author));
  const msg = { id: newId(), ts, sender: mine ? app.name : who ? contactName(who) : name || author, author, text, ...routeOf() };
  if (mine) Object.assign(msg, { mine: true, status: "delivered" });
  addIncoming("room:" + room.pubHex, msg);
}

function addIncoming(key, msg) {
  if (takeReaction(key, msg)) return;
  (app.history[key] ||= []).push(msg);
  const redraw = attachParked(key, msg, false);
  scheduleSave();
  if (key !== app.active || document.hidden) app.unread[key] = (app.unread[key] || 0) + 1;
  if (app.catchingUp) return void app.touched.add(key);   // (drawn once, in order, when the catch-up ends)
  if (key === app.active) redraw ? renderConversation() : appendMessage(msg);
  renderSidebar();
  updateTitle();
}

// ---------------------------------------------------------------- catching up (the server's backlog, for web logins)

// On every connect: what was missed since our cursor. A first visit starts from now. Old packets are read only.
// Replayed packets, as the server sends them: worked through in chunks, so the page stays responsive.
function onReplay(packets) {
  app.replayQueue.push(...packets);
  if (!app.replayPump) app.replayPump = drainReplay().finally(() => { app.replayPump = null; });
}

async function drainReplay() {
  while (app.replayQueue.length) {
    for (const p of app.replayQueue.splice(0, 100)) {
      onPacket({ dir: p.dir, raw: hexToBytes(p.raw), snr: p.snr, seq: p.seq, old: true, at: (p.ts || 0) * 1000 || Date.now() });
      app.replayed++;
    }
    $("server-info").textContent = "Catching up… " + app.replayed.toLocaleString() + " packets";
    await new Promise((r) => setTimeout(r, 0));
  }
}

async function catchUp() {
  const client = app.client, key = client.hello?.key;
  if (!key?.web || app.catchingUp) return;
  Object.assign(app, { catchingUp: true, touched: new Set(), replayed: 0, liveSeq: 0 });
  try {
    const done = await client.request("replay", {
      since: app.cursor, channels: [...new Set(app.channels.map((c) => c.hash))], me: app.identity.pub[0],
    }, 10 * 60 * 1000);
    while (app.replayPump) await app.replayPump;
    app.cursor = Math.max(app.cursor ?? 0, done.last, app.liveSeq);
  } catch (e) {
    while (app.replayPump) await app.replayPump;
    if (!/catching up is for web logins|unknown message type/.test(e.message)) toast("Couldn't catch up: " + e.message);
  } finally {
    app.catchingUp = false;
    for (const k of app.touched) app.history[k].sort((a, b) => a.at - b.at);
    const n = [...app.touched].reduce((s, k) => s + (app.unread[k] || 0), 0);
    renderSidebar();
    renderConversation();
    updateTitle();
    renderServer();
    flushSave();
    if (app.replayed) toast(n ? "Caught up: " + n + " missed message" + (n === 1 ? "" : "s") + "." : "Caught up.");
  }
}

function onState({ state, reason }) {
  const dot = $("conn-dot");
  dot.className = "dot " + state;
  const label = { open: "Connected", connecting: "Connecting…", closed: "Disconnected", failed: "Stopped" }[state];
  dot.title = label + (reason ? ": " + reason : "");
  const banner = $("banner");
  const key = app.client?.hello?.key || {};
  let text = "", bad = false;
  if (state === "failed") { text = "Disconnected: " + reason + ". Log out and in again."; bad = true; }
  else if (state === "closed") text = "Disconnected: " + (reason || "connection lost") + ".";
  else if (state === "connecting") text = "Connecting…";
  else if (key.web && !key.send) text = "You can read, but not send yet: " +
    (key.pending_message || "Your key must be heard on RF before you can send messages. Please send a flood advert.");
  banner.textContent = text;
  banner.className = "banner" + (bad ? " bad" : "");
  banner.hidden = !text;
  updateComposer();
}

// ---------------------------------------------------------------- sending

// ---------------------------------------------------------------- reactions (MeshCore One's format, as MeshTrax uses it)

// An incoming message that is a reaction to one we hold: added to it, and true. Otherwise false (one that finds nothing
// stays a message, shown as a reaction note).
function takeReaction(key, msg) {
  const r = parseReaction(msg.text);
  if (!r) return false;
  const target = r.legacy ? null : findReactionTarget(key, r);
  if (!target) {
    // shown as a note until its message turns up (one still coming in a catch-up, or a retry stamped anew)
    msg.reaction = { emoji: r.emoji, to: r.targetSender || null, hash: r.legacy ? undefined : r.hash };
    return false;
  }
  addReaction(target, r.emoji, msg.sender);
  updateMessage(target);
  scheduleSave();
  return true;
}

function findReactionTarget(key, r) {
  const since = Date.now() - REACTION_WINDOW_MS;
  const msgs = (app.history[key] || []).filter((m) => !m.reaction && (m.at || m.ts * 1000) >= since);
  const hit = (m) => hashesOf(m, key).has(r.hash);
  for (const pass of [(m) => m.sender === r.targetSender, () => true])
    for (let i = msgs.length - 1; i >= 0; i--) if (pass(msgs[i]) && hit(msgs[i])) return msgs[i];
  return null;
}

// Every hash a reaction to this message may carry (worked out once): each text form (hashTexts), with each stamp it
// may have been hashed with. Received: as received, and any retry's. Ours: as sent, and the next 3 s (as MeshTrax
// tries: apps that stamp their own copy a little later); in a room, the server stamps the post with its own clock, so
// two minutes either side. (40-bit hashes: trying more stamps doesn't make a wrong match likely.)
const reactionHashes = new WeakMap();
function hashesOf(m, key) {
  let set = reactionHashes.get(m);
  if (set) return set;
  const stamps = new Set([m.ts, ...(m.tsAlt || [])]);
  if (m.mine) {
    const [from, to] = key.startsWith("room:") ? [-120, 120] : [0, 3];
    for (let d = from; d <= to; d++) stamps.add(m.ts + d);
  }
  set = new Set();
  for (const t of hashTexts(m.text)) for (const s of stamps) set.add(messageHash(t, s));
  reactionHashes.set(m, set);
  return set;
}

// A message just added: reactions to it that came first (shown as notes) go onto it. True if any did (then the
// conversation is drawn again, unless `draw` is false).
function attachParked(key, m, draw = true) {
  const list = app.history[key] || [];
  const parked = list.filter((x) => x.reaction?.hash && !x.mine);
  if (!parked.length || m.reaction) return false;
  const hashes = hashesOf(m, key);
  const hits = parked.filter((x) => hashes.has(x.reaction.hash));
  if (!hits.length) return false;
  for (const x of hits) addReaction(m, x.reaction.emoji, x.sender);
  app.history[key] = list.filter((x) => !hits.includes(x));
  scheduleSave();
  if (draw && key === app.active && !app.catchingUp) renderConversation();
  return true;
}

function addReaction(m, emoji, who) {
  m.reactions ||= {};
  const list = (m.reactions[emoji] ||= []);
  if (list.includes(who)) return false;                  // the same person, the same emoji: once
  list.push(who);
  return true;
}

async function react(m, emoji) {
  closeReactPicker();
  const key = Object.keys(app.history).find((k) => app.history[k].includes(m));
  const cv = conv(key);
  if (!cv || !canSend()) return toast("Can't send right now.");
  if (!addReaction(m, emoji, app.name)) return;
  updateMessage(m);
  scheduleSave();
  // the hash covers the text as the author's app holds it: in a channel the body trimmed, else exactly as sent
  const hash = messageHash(cv.kind === "channel" ? hashTexts(m.text)[0] : m.text, m.ts);
  const text = reactionText(emoji, hash, cv.kind === "dm" ? null : m.sender);
  let ok;
  if (cv.kind === "channel") {
    const raw = channelMessagePacket(cv.channel, app.name, text, uniqueTime(), pathHashSize());
    markSeen(packetHash(parsePacket(raw)));
    const res = await app.client.send(raw);
    ok = res.status === "sent" || res.status === "local";
  } else {
    ok = (await app.node.sendDm(cv.contact, text)).acked;
  }
  if (!ok) {
    m.reactions[emoji] = m.reactions[emoji].filter((w) => w !== app.name);
    if (!m.reactions[emoji].length) delete m.reactions[emoji];
    updateMessage(m);
    toast("The reaction wasn't delivered.");
  }
}

let pickerFor = null;

function openReactPicker(m, button) {
  const pop = $("react-pop");
  if (pickerFor === m && !pop.hidden) return closeReactPicker();
  pickerFor = m;
  pop.replaceChildren(...QUICK_REACTIONS.map((e) => el("button", { type: "button", "aria-label": "React " + e, onclick: () => react(m, e) }, e)),
    el("button", { type: "button", class: "more", "aria-label": "More emoji", title: "More emoji",
      onclick: (ev) => { ev.stopPropagation(); openPicker("emoji", button, m); } }, "＋"));
  pop.hidden = false;
  const r = button.getBoundingClientRect(), w = pop.offsetWidth;
  pop.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, r.right - w)) + "px";
  pop.style.top = Math.max(8, r.top - pop.offsetHeight - 6) + "px";
}

function closeReactPicker() {
  pickerFor = null;
  $("react-pop").hidden = true;
}

async function sendMessage(ev) {
  ev?.preventDefault();
  closeMentions();
  const ta = $("text");
  const text = ta.value.trim();
  const cv = conv();
  if (!text || !cv || !canSend()) return;
  const wire = composed(cv, text);
  if (wire === null || utf8Encode(wire).length > budget(cv)) return toast("Too long for one message.");
  ta.value = "";
  setReply(null);
  autosize();
  updateComposer();
  updateGifPreview();
  const msg = { id: newId(), ts: uniqueTime(), at: Date.now(), sender: app.name, text: wire, mine: true, status: "sending" };
  (app.history[cv.key] ||= []).push(msg);
  appendMessage(msg);
  if (cv.kind === "dm") app.dms = [cv.contact.pubHex, ...app.dms.filter((p) => p !== cv.contact.pubHex)];
  renderSidebar();
  await deliver(cv, msg);
}

async function deliver(cv, msg) {
  if (cv.kind === "channel") {
    const raw = channelMessagePacket(cv.channel, app.name, msg.text, msg.ts, pathHashSize());
    markSeen(packetHash(parsePacket(raw)));
    msg.status = app.client.backlog || app.client.state !== "open" ? "waiting" : "sending";
    updateMessage(msg);
    const res = await app.client.send(raw);
    msg.status = res.status === "sent" || res.status === "local" ? res.status : "failed";
    msg.reason = res.reason || "";
  } else if (cv.kind === "room" && isLocalRoom(cv.contact.pubHex)) {
    const c = cv.contact;
    msg.status = "sending";
    updateMessage(msg);
    if (!c.room.loggedIn && !(await roomLogin(c, c.room.password || "", true)))
      Object.assign(msg, { status: "failed", reason: "couldn't open the room" });
    else {
      try {
        const r = await app.client.request("room_post", { room: c.pubHex, text: msg.text });
        if (r.status === "duplicate") Object.assign(msg, { status: "failed", reason: "the room already has this post from you" });
        else if (!msg.roomTs) Object.assign(msg, { ts: r.ts, roomTs: true, status: "delivered", reason: "" });
        reactionHashes.delete(msg);
      } catch (e) {
        Object.assign(msg, { status: "failed", reason: e.message });
      }
    }
  } else {
    const c = cv.contact;
    if (cv.kind === "room" && !c.room.loggedIn) {
      msg.status = "sending";
      updateMessage(msg);
      if (!(await roomLogin(c, c.room.password || "", true))) {
        Object.assign(msg, { status: "failed", reason: "not logged in to the room" });
        updateMessage(msg);
        return scheduleSave();
      }
    }
    const res = await app.node.sendDm(c, msg.text, 3, (attempt, step) => {
      if (attempt) Object.assign(msg, { status: "retrying", reason: step.flood ? "by flood" : "via " + pathText(step) });
      updateMessage(msg);
    }, msg.ts);
    msg.status = res.acked ? "delivered" : res.status === "dropped" ? "failed" : "unconfirmed";
    msg.reason = res.acked ? "" : res.reason || "";
    msg.via = res.acked ? pathText(res.via) : undefined;
    if (app.active === cv.key) $("room-sub").textContent = conv().sub;
  }
  updateMessage(msg);
  scheduleSave();
}

async function retry(msg) {
  const key = Object.keys(app.history).find((k) => app.history[k].includes(msg));
  const cv = conv(key);
  if (!cv || !canSend()) return;
  msg.ts = uniqueTime();
  msg.status = "sending";
  await deliver(cv, msg);
}

async function advertise(kind) {
  $("dlg-advert").close();
  if (!canSend()) return toast("Not connected, or this key can't send.");
  const payload = advertPayload(app.identity, app.name, uniqueTime());
  const raw = kind === "flood" ? floodPacket(PT_ADVERT, payload, pathHashSize()) : zeroHopPacket(PT_ADVERT, payload);
  markSeen(packetHash(parsePacket(raw)));
  toast("Sending advert…");
  const res = await app.client.send(raw);
  toast(res.status === "sent" || res.status === "local" ? "Advert sent." : "Advert not sent: " + (res.reason || res.status));
}

function canSend() {
  return app.client && app.client.state === "open" && app.client.hello?.key?.send !== false;
}

// ---------------------------------------------------------------- rendering

function renderServer() {
  const h = app.client?.hello;
  const parts = [];
  if (h) {
    parts.push(h.server || "pyMeshRoom");
    const room = h.nodes?.room && h.names?.[h.nodes.room];
    if (room) parts.push(room);
    if (h.radio) parts.push((h.radio.freq_hz / 1e6).toFixed(3) + " MHz, SF" + h.radio.sf + ", " + h.radio.bw_hz / 1000 + " kHz");
  }
  $("server-info").textContent = parts.join(" · ");
}

function navButton(key, label, extra) {
  const n = app.unread[key] || 0;
  return el("button", {
    type: "button", class: key === app.active ? "on" : "", onclick: () => select(key),
    "aria-current": key === app.active ? "true" : null,
  }, el("span", { class: "ch-name" }, label), extra || null, n ? el("span", { class: "badge" }, String(n)) : null);
}

function renderSidebar() {
  if (!app.node) return;
  $("channel-list").replaceChildren(...app.channels.map((ch) =>
    navButton(ch.keyHex, ch.name, ch.kind === "private" ? el("span", { class: "ch-kind" }, "private") : null)));
  $("dm-list").replaceChildren(...app.dms.map((pub) => navButton("dm:" + pub, contactName(app.node.contact(pub)))));
  const rooms = [...app.node.contacts.values()].filter((c) => c.room);
  $("room-list").replaceChildren(...rooms.map((c) => navButton("room:" + c.pubHex, contactName(c),
    c.room.loggedIn ? null : el("span", { class: "ch-kind" }, "offline"))));
  if (conv()) {
    $("room-name").textContent = conv().title;
    $("room-sub").textContent = conv().sub;
  }
}

function select(key) {
  if (!conv(key)) return;
  if (key !== app.active) setReply(null);
  app.active = key;
  delete app.unread[key];
  $("sidebar").classList.remove("open");
  renderSidebar();
  renderConversation();
  updateTitle();
  scheduleSave();
  $("text").focus();
}

function renderConversation() {
  let cv = conv();
  if (!cv) {
    app.active = app.channels[0].keyHex;
    cv = conv();
  }
  $("room-name").textContent = cv.title;
  $("room-sub").textContent = cv.sub;
  const box = $("messages");
  const msgs = app.history[cv.key] || [];
  box.replaceChildren();
  if (!msgs.length) {
    box.append(el("p", { class: "empty" }, {
      channel: "No messages yet. Messages heard from now on show up here.",
      dm: "No messages yet. Only the two of you can read a direct message.",
      room: "No posts yet. The room sends the posts you missed when you log in.",
    }[cv.kind]));
  }
  lastDay = null;
  for (const m of msgs) appendMessage(m, false);
  box.scrollTop = box.scrollHeight;
  updateComposer();
}

let lastDay = null;

function shownTime(m) {
  // the sender's clock, unless it is far off from when we got it
  const sent = m.ts * 1000;
  return Math.abs(sent - m.at) > 12 * 3600 * 1000 ? m.at : sent;
}

function appendMessage(m, scroll = true) {
  const box = $("messages");
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  box.querySelector(".empty")?.remove();
  const when = new Date(shownTime(m));
  const day = when.toDateString();
  if (day !== lastDay) {
    lastDay = day;
    box.append(el("div", { class: "day" }, when.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" })));
  }
  box.append(messageNode(m));
  if (scroll && (nearBottom || m.mine)) box.scrollTop = box.scrollHeight;
}

function messageNode(m) {
  const when = new Date(shownTime(m));
  if (m.reaction) {
    return el("div", { class: "reaction-note", dataset: { id: m.id }, title: when.toLocaleString() +
      (m.reaction.hash ? " · message hash " + m.reaction.hash : "") + (m.reaction.why ? "\n" + m.reaction.why : "") },
      el("b", {}, m.sender || "(no name)"), " reacted ", el("span", { class: "emoji" }, m.reaction.emoji),
      m.reaction.to ? " to a message from " + m.reaction.to : " to a message", " not shown here",
      m.reaction.hash ? el("button", { type: "button", class: "linkish small", onclick: (ev) => lookHarder(m, ev.currentTarget) },
        m.reaction.why ? "why?" : "Look for it") : null);
  }
  const reply = parseReply(m.text);
  const reactions = Object.entries(m.reactions || {}).filter(([, who]) => who.length);
  const route = [];
  if (m.hops != null) route.push(m.hops === 0 ? "direct" : m.hops + (m.hops === 1 ? " hop" : " hops"));
  if (m.snr != null) route.push("SNR " + Number(m.snr).toFixed(1));
  if (m.dir === "tx" && !m.mine) route.push("via this radio");
  if (m.dir === "mqtt") route.push("via MQTT");
  if (m.old) route.push("while you were away");
  return el("div", { class: "msg" + (m.mine ? " mine" : ""), dataset: { id: m.id } },
    el("div", { class: "meta" },
      el("span", { class: "sender", title: m.author ? "key " + m.author + "…" : null }, m.sender || "(no name)"),
      el("time", { datetime: when.toISOString(), title: when.toLocaleString() },
        when.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })),
      route.length ? el("span", {}, route.join(" · ")) : null),
    reply ? quoteNode(reply) : null,
    el("div", { class: "text" + (emojiOnly(reply ? reply.body : m.text) ? " big" : "") }, ...richText(reply ? reply.body : m.text)),
    reactions.length ? el("div", { class: "reactions" }, ...reactions.map(([e, who]) => el("button", {
      type: "button", class: "chip" + (who.includes(app.name) ? " me" : ""), title: who.join(", "),
      "aria-label": e + " from " + who.join(", "), onclick: () => react(m, e),
    }, e + (who.length > 1 ? " " + who.length : "")))) : null,
    el("div", { class: "msg-acts" },
      el("button", { type: "button", class: "reply-btn", title: "Reply", "aria-label": "Reply to this message",
        onclick: () => setReply(m) }, "↩"),
      el("button", { type: "button", class: "react-btn", title: "React", "aria-label": "React to this message",
        onclick: (ev) => openReactPicker(m, ev.currentTarget) }, "☺+")),
    m.mine ? statusNode(m) : null);
}

// A reply's quote: the message it answers when it's here (click to see it), else what it quoted.
function quoteNode(r) {
  const since = Date.now() - 48 * 3600 * 1000;
  const orig = r.quote ? (app.history[app.active] || []).filter((x) => !x.reaction && (x.at || x.ts * 1000) >= since)
    .reverse().find((x) => (x.sender === r.name || (x.mine && r.name === app.name)) &&
      quoteMatches(parseReply(x.text)?.body ?? x.text, r.quote)) : null;
  const shown = orig ? parseReply(orig.text)?.body ?? orig.text : r.quote + (r.partial ? "…" : "");
  return el("div", { class: "quote" + (orig ? " found" : ""), title: orig ? "Show the message" : null,
    onclick: orig ? () => {
      const node = $("messages").querySelector(`[data-id="${CSS.escape(orig.id)}"]`);
      node?.scrollIntoView({ block: "center", behavior: "smooth" });
      node?.classList.add("flash");
      setTimeout(() => node?.classList.remove("flash"), 1200);
    } : null }, el("b", {}, r.name), shown ? " " + shown : "");
}

// A reaction that matched nothing: search harder (each recent message's text forms, with every stamp ±5 minutes).
// Found: it goes onto that message, and says how far off it was (worth reporting: the usual forms should find it).
async function lookHarder(note, button) {
  if (note.reaction.why) return toast(note.reaction.why);
  button.disabled = true;
  button.textContent = "Looking…";
  const key = Object.keys(app.history).find((k) => app.history[k].includes(note));
  const cv = conv(key);
  const msgs = (app.history[key] || []).filter((x) => !x.reaction && x !== note).slice(-40).reverse();
  let hit = null;
  for (const m of msgs) {
    const texts = [...hashTexts(m.text), ...(cv?.kind === "channel" ? [(m.sender || "") + ": " + m.text] : [])];
    const stamps = [m.ts, ...(m.tsAlt || [])];
    for (let d = 0; d <= 300 && !hit; d++) {
      for (const base of stamps) for (const sign of d ? [1, -1] : [1]) for (const [i, t] of texts.entries())
        if (!hit && messageHash(t, base + sign * d) === note.reaction.hash) hit = { m, d: sign * d, named: i >= hashTexts(m.text).length };
    }
    if (hit) break;
    await new Promise((r) => setTimeout(r, 0));          // (a message at a time: the page stays responsive)
  }
  if (hit) {
    addReaction(hit.m, note.reaction.emoji, note.sender);
    app.history[key] = app.history[key].filter((x) => x !== note);
    scheduleSave();
    renderConversation();
    toast("Found it: a reaction to " + (hit.m.sender || "a message") + "'s \"" + Array.from(hit.m.text).slice(0, 30).join("") +
      "\" (its time off by " + hit.d + " s" + (hit.named ? ", hashed with the sender's name" : "") + "). Worth reporting: it should have matched.");
    return;
  }
  note.reaction.why = "No message from the last " + msgs.length + " here matches, even ±5 minutes off: it was for a message " +
    "this page never received (one sent or received by another device with your key, say, or before you joined).";
  scheduleSave();
  updateMessage(note);
  toast(note.reaction.why);
}

function statusNode(m) {
  const text = {
    sending: "Sending…", waiting: "Waiting for the rate limit…", sent: "Sent", local: "Delivered on the radio",
    delivered: "Delivered" + (m.via ? " via " + m.via : ""), retrying: "No answer yet, trying again" + (m.reason ? " " + m.reason : "") + "…",
    unconfirmed: "Not delivered: no ACK", failed: "Not sent" + (m.reason ? ": " + m.reason : ""), unknown: "Not confirmed",
  }[m.status] || m.status;
  const bad = ["failed", "unknown", "unconfirmed"].includes(m.status);
  return el("div", { class: "status" + (bad ? " bad" : "") }, text,
    bad ? el("button", { type: "button", class: "ghost", onclick: () => retry(m) }, "Retry") : null);
}

function updateMessage(m) {
  const node = $("messages").querySelector(`[data-id="${CSS.escape(m.id)}"]`);
  if (node) node.replaceWith(messageNode(m));
}

// A message's text: Giphy links become the GIF (unless GIFs are off), @[name] mentions stand out.
function richText(text) {
  const out = [];
  let i = 0;
  for (const g of findGifs(text)) {
    if (g.start > i) out.push(...withMentions(text.slice(i, g.start)));
    out.push(gifsOn() ? gifNode(g.id) : el("span", { class: "gif-link" }, text.slice(g.start, g.end)));
    i = g.end;
  }
  if (i < text.length) out.push(...withMentions(text.slice(i)));
  return out;
}

function gifNode(id) {
  const img = el("img", { src: gifUrl(id), alt: "GIF", loading: "lazy", referrerpolicy: "no-referrer" });
  img.addEventListener("error", () => {
    if (img.src !== gifFallbackUrl(id)) img.src = gifFallbackUrl(id);
    else img.replaceWith(el("span", { class: "gif-link" }, gifPageUrl(id)));
  });
  return el("a", { class: "gif", href: gifPageUrl(id), target: "_blank", rel: "noopener noreferrer", title: "Open on Giphy" }, img);
}

function gifsOn() {
  return loadSettings().gifs !== false;
}

function updateGifPreview() {
  const box = $("gif-preview");
  const gifs = gifsOn() ? findGifs($("text").value) : [];
  box.replaceChildren(...gifs.slice(0, 3).map((g) => el("img", { src: gifUrl(g.id), alt: "GIF preview", referrerpolicy: "no-referrer" })));
  box.hidden = !gifs.length;
}

// @[name] mentions, as the MeshCore apps write them; the reader's own name stands out.
function withMentions(text) {
  const out = [];
  const re = /@\[([^\]]+)\]/g;
  let i = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > i) out.push(text.slice(i, m.index));
    const me = m[1].toLowerCase() === app.name.toLowerCase();
    out.push(el("span", { class: "mention" + (me ? " me" : "") }, "@" + m[1]));
    i = m.index + m[0].length;
  }
  if (i < text.length) out.push(text.slice(i));
  return out;
}

// What a message goes out as: with the reply markup when replying (MeshCore One's format; null if it can't fit).
function composed(cv, text) {
  const r = app.reply;
  if (!r || r.key !== cv.key || !text) return text;
  return buildReply(r.msg.sender || "", parseReply(r.msg.text)?.body ?? r.msg.text, text, budget(cv), app.name);
}

function setReply(m) {
  app.reply = m ? { key: app.active, msg: m } : null;
  $("reply-bar").hidden = !m;
  if (m) {
    const shown = parseReply(m.text)?.body ?? m.text;
    $("reply-name").textContent = m.sender || "(no name)";
    $("reply-quote").textContent = Array.from(shown).length > 60 ? Array.from(shown).slice(0, 60).join("") + "…" : shown;
    $("text").focus();
  }
  updateComposer();
}

function updateComposer() {
  if (!app.identity) return;
  const typed = $("text").value.trim(), cv = conv();
  const wire = cv ? composed(cv, typed) : typed;
  const left = budget() - (wire === null ? budget() + 1 : utf8Encode(wire).length);
  const count = $("count");
  count.textContent = String(left);
  count.className = "count" + (left < 0 ? " over" : "");
  const ok = canSend();
  $("send").disabled = !ok || left < 0 || !typed;
  $("text").placeholder = ok ? "Message " + (conv()?.title || "") : "Can't send right now";
  $("gif-btn").hidden = !gifsOn() || !giphyKey();
  $("advert").disabled = !ok;
}

function updateTitle() {
  const n = Object.values(app.unread).reduce((a, b) => a + b, 0);
  document.title = (n ? "(" + n + ") " : "") + "MeshCore Web";
}

// ---------------------------------------------------------------- emoji and GIF pickers

let picker = null;              // {kind: "emoji" | "gif", react?: message to react to, tab?, seq?}

const giphyKey = () => app.client?.hello?.giphy_key || "";

// Text into the message box at the caret, with a space between it and words either side.
function insertText(t, spaced = false) {
  const ta = $("text");
  const a = ta.selectionStart ?? ta.value.length, b = ta.selectionEnd ?? a;
  const before = ta.value.slice(0, a), after = ta.value.slice(b);
  const pre = spaced && before && !/\s$/.test(before) ? " " : "", post = spaced && !/^\s/.test(after) ? " " : "";
  ta.value = before + pre + t + post + after;
  const caret = (before + pre + t + post).length;
  ta.setSelectionRange(caret, caret);
  autosize();
  updateComposer();
  updateGifPreview();
}

function openPicker(kind, anchor, react = null) {
  if (picker && picker.kind === kind && !picker.react === !react && !$("pick-pop").hidden) return closePicker();
  closeReactPicker();
  picker = { kind, react, tab: loadRecentEmoji().length ? -1 : 0, seq: 0 };
  const pop = $("pick-pop");
  pop.hidden = false;
  $("gif-q").hidden = kind !== "gif";
  $("pick-tabs").hidden = kind !== "emoji";
  if (kind === "emoji") renderEmojiTab();
  else {
    $("gif-q").value = "";
    searchGifs();
    if (matchMedia("(hover: hover)").matches) $("gif-q").focus();   // (on a phone, not the keyboard at once)
  }
  placePicker(anchor);
}

function placePicker(anchor) {
  const pop = $("pick-pop"), r = anchor.getBoundingClientRect(), w = pop.offsetWidth, h = pop.offsetHeight;
  pop.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, r.left)) + "px";
  pop.style.top = (r.top - h - 6 >= 8 ? r.top - h - 6 : Math.min(window.innerHeight - h - 8, r.bottom + 6)) + "px";
}

function closePicker() {
  picker = null;
  $("pick-pop").hidden = true;
}

function renderEmojiTab() {
  const recent = loadRecentEmoji();
  const tabs = [...(recent.length ? [["🕘", "Recent", recent]] : []), ...EMOJI_CATEGORIES];
  const at = Math.max(0, Math.min(tabs.length - 1, picker.tab + (recent.length ? 1 : 0)));
  $("pick-tabs").replaceChildren(...tabs.map(([icon, name], i) => el("button", {
    type: "button", role: "tab", title: name, "aria-label": name, class: i === at ? "on" : "", "aria-selected": String(i === at),
    onclick: () => { picker.tab = i - (recent.length ? 1 : 0); renderEmojiTab(); $("pick-grid").scrollTop = 0; },
  }, icon)));
  const grid = $("pick-grid");
  grid.className = "pick-grid";
  grid.replaceChildren(...tabs[at][2].map((e) => el("button", { type: "button", "aria-label": e, onclick: () => pickEmoji(e) }, e)));
  $("pick-foot").textContent = "";
}

function pickEmoji(e) {
  saveRecentEmoji([e, ...loadRecentEmoji().filter((x) => x !== e)].slice(0, RECENT_MAX));
  if (picker?.react) {
    const m = picker.react;
    closePicker();
    return react(m, e);
  }
  insertText(e);
}

let gifTimer = null;
async function searchGifs() {
  const q = $("gif-q").value.trim(), seq = ++picker.seq, grid = $("pick-grid");
  grid.className = "pick-grid gifs";
  $("pick-foot").textContent = "Powered by GIPHY";
  if (!grid.children.length) grid.replaceChildren(el("div", { class: "pick-msg" }, "Loading…"));
  const url = "https://api.giphy.com/v1/gifs/" + (q ? "search" : "trending") + "?api_key=" + encodeURIComponent(giphyKey()) +
    "&limit=24&rating=pg-13" + (q ? "&q=" + encodeURIComponent(q) : "");
  let ids;
  try {
    const r = await fetch(url, { cache: "no-store", referrerPolicy: "no-referrer" });
    if (!r.ok) throw new Error(r.status === 401 || r.status === 403 ? "Giphy refused this server's API key." : "Giphy answered " + r.status + ".");
    ids = ((await r.json()).data || []).map((g) => String(g.id || "")).filter((id) => /^[A-Za-z0-9]{6,40}$/.test(id));
  } catch (e) {
    if (picker?.seq === seq) grid.replaceChildren(el("div", { class: "pick-msg" }, e.message.startsWith("Giphy") ? e.message : "Can't reach Giphy."));
    return;
  }
  if (picker?.kind !== "gif" || picker.seq !== seq) return;
  grid.replaceChildren(...(ids.length ? ids.map((id) => el("button", {
    type: "button", "aria-label": "GIF", onclick: () => { closePicker(); insertText(gifPageUrl(id), true); $("text").focus(); },
  }, el("img", { src: gifThumbUrl(id), alt: "", loading: "lazy" }))) : [el("div", { class: "pick-msg" }, "No GIFs found.")]));
}

function autosize() {
  const ta = $("text");
  ta.style.height = "auto";
  ta.style.height = Math.min(ta.scrollHeight, 140) + "px";
}

// ---------------------------------------------------------------- @mention autocomplete

let mention = null;             // {start, items, index} while the list is open

// Names to offer for "@pre": people who wrote here lately first, then contacts, matching anywhere in the name.
function mentionNames(pre) {
  const score = new Map();
  const add = (name, s) => {
    if (!name || name === app.name || /[\]\n]/.test(name)) return;
    score.set(name, Math.max(score.get(name) || 0, s));
  };
  const msgs = app.history[app.active] || [];
  for (let i = msgs.length - 1, n = 0; i >= 0 && n < 200; i--, n++) if (!msgs[i].mine) add(msgs[i].sender, 3 + i / msgs.length);
  for (const c of app.node.contacts.values()) if (c.type === "chat") add(c.name, c.lastHeard ? 1 + c.lastHeard / 1e10 : 1);
  const p = pre.toLowerCase();
  return [...score.entries()].filter(([n]) => n.toLowerCase().includes(p))
    .sort((a, b) => (b[0].toLowerCase().startsWith(p) - a[0].toLowerCase().startsWith(p)) || b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 8).map(([n]) => n);
}

function updateMentions() {
  const ta = $("text");
  const before = ta.value.slice(0, ta.selectionStart);
  const m = before.match(/(?:^|\s)@(\[?)([^\]\n@]*)$/);
  const items = m && app.node ? mentionNames(m[2]) : [];
  if (!items.length) return closeMentions();
  mention = { start: before.length - m[2].length - m[1].length - 1, items, index: 0 };
  renderMentions();
}

function renderMentions() {
  const box = $("mentions");
  box.replaceChildren(...mention.items.map((n, i) => el("button", {
    type: "button", role: "option", class: i === mention.index ? "on" : "", "aria-selected": i === mention.index ? "true" : "false",
    onmousedown: (e) => { e.preventDefault(); pickMention(i); },
  }, "@" + n)));
  box.hidden = false;
}

function pickMention(i) {
  const ta = $("text");
  const insert = "@[" + mention.items[i] + "] ";
  ta.value = ta.value.slice(0, mention.start) + insert + ta.value.slice(ta.selectionStart);
  const caret = mention.start + insert.length;
  ta.setSelectionRange(caret, caret);
  closeMentions();
  updateComposer();
  ta.focus();
}

function closeMentions() {
  mention = null;
  $("mentions").hidden = true;
}

function mentionKeys(e) {
  if (!mention) return false;
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    mention.index = (mention.index + (e.key === "ArrowDown" ? 1 : -1) + mention.items.length) % mention.items.length;
    renderMentions();
  } else if (e.key === "Enter" || e.key === "Tab") pickMention(mention.index);
  else if (e.key === "Escape") closeMentions();
  else return false;
  e.preventDefault();
  return true;
}

// ---------------------------------------------------------------- channels: join, details, leave

let addKind = "hashtag";

function openAdd() {
  setAddKind("hashtag");
  $("a-tag").value = "";
  $("a-name").value = "";
  $("a-secret").value = "";
  showError("add-error", "");
  $("dlg-add").showModal();
  $("a-tag").focus();
}

function setAddKind(kind) {
  addKind = kind;
  for (const t of document.querySelectorAll("#dlg-add .tab")) t.classList.toggle("on", t.dataset.kind === kind);
  for (const p of document.querySelectorAll("#dlg-add [data-pane]")) p.hidden = p.dataset.pane !== kind;
}

function addChannel(ev) {
  ev.preventDefault();
  let ch;
  try {
    if (addKind === "hashtag") {
      let tag = $("a-tag").value.trim().replace(/\s+/g, "");
      if (!tag.replace(/^#/, "")) throw new Error("Enter a hashtag.");
      if (!tag.startsWith("#")) tag = "#" + tag;
      ch = makeChannel(tag, "hashtag");
    } else {
      const name = $("a-name").value.trim();
      if (!name) throw new Error("Give the channel a name.");
      ch = makeChannel(name, "private", parseSecret($("a-secret").value));
    }
  } catch (e) {
    return showError("add-error", e.message === "not hex" ? "The secret isn't hex." : e.message);
  }
  const existing = app.channels.find((c) => c.keyHex === ch.keyHex);
  $("dlg-add").close();
  if (existing) {
    toast("You're already in " + existing.name + ".");
    return select(existing.keyHex);
  }
  app.channels.push(ch);
  persistChannels();
  select(ch.keyHex);
}

// 32 hex characters, or base64 of 16 bytes
function parseSecret(s) {
  s = s.trim();
  if (/^[0-9a-f\s]+$/i.test(s)) return s.replace(/\s+/g, "");
  try {
    const bin = atob(s);
    if (bin.length === 16) return bytesToHex(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  } catch {
    // not base64 either
  }
  throw new Error("A secret is 32 hex characters.");
}

function openInfo() {
  const cv = conv();
  $("i-name").textContent = cv.title;
  $("i-kind").textContent = cv.sub + ".";
  const shown = cv.kind === "channel" ? (cv.channel.kind === "private" ? cv.channel.keyHex : "") : cv.contact.pubHex;
  $("i-secret-box").hidden = !shown;
  $("i-secret").value = shown;
  $("i-secret-label").textContent = cv.kind === "channel" ? "Secret" : "Public key";
  $("i-secret-hint").textContent = cv.kind === "channel" ? "Anyone with this secret can read and send on the channel."
    : "Compare it with the one in their app to be sure who you're talking to.";
  $("i-leave").hidden = cv.kind === "channel" && cv.channel.kind === "public";
  $("i-leave").textContent = { channel: "Leave channel", dm: "Close conversation", room: "Leave room" }[cv.kind];
  $("i-relogin").hidden = cv.kind !== "room";
  const routed = cv.kind === "dm" || (cv.kind === "room" && !isLocalRoom(cv.contact.pubHex));
  $("i-route-box").hidden = !routed;
  if (routed) renderRouteBox(cv.contact, true);
  $("dlg-info").showModal();
}

// Details: how to reach this contact or room. Automatic, a path set by hand, or flood; with the server's suggestions.
async function renderRouteBox(c, fetch = false) {
  const mode = c.routeMode === "manual" && c.manual ? "manual" : c.routeMode === "flood" ? "flood" : "auto";
  for (const r of document.querySelectorAll('input[name="i-route"]')) r.checked = r.value === mode;
  $("i-manual").value = c.manual ? pathText(c.manual).replace(/ › /g, ",") : "";
  $("i-manual").disabled = mode !== "manual";
  $("i-learned").textContent = c.outLen == null ? "No path learned yet: the next message tries the server's suggestions, then floods."
    : "Learned from their answers: " + pathText({ plen: c.outLen, path: c.outPath }) + ".";
  $("i-forget").hidden = c.outLen == null;
  const list = $("i-suggested");
  if (fetch) list.replaceChildren(el("li", { class: "dim" }, "Asking the server…"));
  const paths = fetch ? await suggestPaths(c, true) : c.suggested?.paths || [];
  if (conv()?.contact !== c) return;
  list.replaceChildren(...(paths.length ? paths.map((p) => el("li", {},
    el("span", { class: "mono" }, pathText(p)),
    el("span", { class: "dim" }, " · " + Math.round(p.score * 100) + "% · " + ({ measured: "delivered on before", map: "from the map",
      shortcut: "a shortcut", direct: "heard directly" }[p.source] || p.source) + (p.names?.some(Boolean) ? " · " + p.names.map((n) => n || "?").join(" › ") : "")),
    " ", el("button", { type: "button", class: "ghost small", onclick: () => setRoute(c, "manual", p) }, "Use"))) :
    [el("li", { class: "dim" }, "The server knows no path to them (it hasn't heard them flood lately).")]));
}

// Parse "a1,b2,c3" (or with spaces / ›): 1-, 2- or 3-byte repeater ids, all the same size. -> {plen, path} | null
function parsePath(text) {
  const ids = text.split(/[\s,›>]+/).filter(Boolean);
  if (!ids.length || ids.length > 63 || !ids.every((x) => /^([0-9a-f]{2}){1,3}$/i.test(x))) return null;
  const sz = ids[0].length / 2;
  if (!ids.every((x) => x.length === sz * 2)) return null;
  return { plen: ((sz - 1) << 6) | ids.length, path: hexToBytes(ids.join("").toLowerCase()) };
}

function setRoute(c, mode, manual = null) {
  if (manual) c.manual = { plen: manual.plen, path: manual.path };
  if (mode === "manual" && !c.manual) return toast("Enter a path first, like a1,b2,c3.");
  c.routeMode = mode;
  scheduleSave();
  renderRouteBox(c);
  $("room-sub").textContent = conv().sub;
}

function leaveConversation() {
  const cv = conv();
  if (!cv || (cv.kind === "channel" && cv.channel.kind === "public")) return;
  if (!confirm(cv.kind === "room" ? "Leave " + cv.title + "? Its posts and saved password on this device are deleted too."
    : (cv.kind === "dm" ? "Close the conversation with " : "Leave ") + cv.title + "? Its messages on this device are deleted too.")) return;
  if (cv.kind === "channel") {
    app.channels = app.channels.filter((c) => c !== cv.channel);
    persistChannels();
  } else if (cv.kind === "dm") app.dms = app.dms.filter((p) => p !== cv.contact.pubHex);
  else cv.contact.room = null;
  delete app.history[cv.key];
  delete app.unread[cv.key];
  flushSave();
  $("dlg-info").close();
  select(app.channels[0].keyHex);
}

function clearHistory() {
  app.history[app.active] = [];
  flushSave();
  $("dlg-info").close();
  renderConversation();
}

// ---------------------------------------------------------------- contacts, rooms, map

let contactTab = "chat";

function openContacts(tab = contactTab) {
  contactTab = tab;
  $("c-search").value = "";
  renderContacts();
  $("dlg-contacts").showModal();
  $("c-search").focus();
}

function renderContacts() {
  for (const t of document.querySelectorAll("#dlg-contacts .tab")) t.classList.toggle("on", t.dataset.ctab === contactTab);
  const q = $("c-search").value.trim().toLowerCase();
  const list = [...app.node.contacts.values()]
    .filter((c) => (contactTab === "chat" ? c.type === "chat" || c.type === "sensor" : c.type === contactTab))
    .filter((c) => !q || c.name.toLowerCase().includes(q) || c.pubHex.startsWith(q))
    .sort((a, b) => (b.lastHeard || 0) - (a.lastHeard || 0) || contactName(a).localeCompare(contactName(b)));
  $("c-list").replaceChildren(...(list.length ? list.slice(0, 300).map(contactRow)
    : [el("p", { class: "empty" }, q ? "No match." : "None heard yet.")]));
  const noun = { chat: "people", room: "rooms", repeater: "repeaters" }[contactTab];
  $("c-note").textContent = list.length + " " + noun + (list.length > 300 ? " (the 300 heard most recently shown)" : "") + ". " +
    (app.directoryError ? "The server's directory isn't available (" + app.directoryError + "): only adverts heard while you're here."
      : "From the server's directory of the last " + DIRECTORY_DAYS + " days, refreshed every 15 minutes, and adverts heard while you're here.");
}

function contactRow(c) {
  const acts = [];
  if (c.type === "chat" && !c.partial) acts.push(el("button", { type: "button", class: "primary", onclick: () => { $("dlg-contacts").close(); openDm(c); } }, "Message"));
  if (c.type === "room") acts.push(el("button", { type: "button", class: "primary", onclick: () => { $("dlg-contacts").close(); openRoom(c); } }, c.room ? "Open" : "Join"));
  if (c.lat != null) acts.push(el("button", { type: "button", class: "ghost", onclick: () => { $("dlg-contacts").close(); openMap(c); } }, "Map"));
  return el("div", { class: "contact" },
    el("div", { class: "who" }, el("b", {}, contactName(c)),
      el("span", { class: "mono" }, c.pubHex.slice(0, 8)), el("span", {}, " · heard " + ago(c.lastHeard)),
      c.partial ? el("span", { title: "The server knows only part of this key. You can message them once their app adverts within range." },
        " · can't DM yet") : null),
    el("div", { class: "acts" }, ...acts));
}

function openDm(c) {
  if (!app.dms.includes(c.pubHex)) app.dms = [c.pubHex, ...app.dms];
  select("dm:" + c.pubHex);
}

let roomTarget = null;          // the room being joined from the dialog, when it was picked from a list

function openRoom(c) {
  if (c?.room) return select("room:" + c.pubHex);
  roomTarget = c || null;
  $("r-title").textContent = c ? "Join " + contactName(c) : "Join a room";
  $("r-pick").hidden = !!c;
  $("r-key").value = "";
  $("r-pass").value = "";
  showError("r-error", "");
  $("r-known").replaceChildren(...[...app.node.contacts.values()].filter((x) => x.type === "room" && x.name)
    .map((x) => el("option", { value: x.name })));
  $("dlg-room").showModal();
  (c ? $("r-pass") : $("r-key")).focus();
}

async function joinRoomFromDialog(ev) {
  ev.preventDefault();
  showError("r-error", "");
  let c = roomTarget;
  if (!c) {
    const v = $("r-key").value.trim();
    const byName = [...app.node.contacts.values()].filter((x) => x.type === "room" && x.name.toLowerCase() === v.toLowerCase());
    if (/^[0-9a-f]{64}$/i.test(v)) c = app.node.contact(v.toLowerCase(), { type: "room" });
    else if (byName.length === 1) c = byName[0];
    else return showError("r-error", byName.length ? "Several rooms have that name: use its public key." :
      "No room by that name has been heard. Give its public key (64 hex characters).");
  }
  if (!canSend()) return showError("r-error", "You can't send yet, so you can't log in to a room.");
  $("r-go").disabled = true;
  $("r-go").textContent = "Logging in…";
  try {
    await roomLogin(c, $("r-pass").value);
    $("dlg-room").close();
    select("room:" + c.pubHex);
  } catch (e) {
    c.room = null;
    showError("r-error", e instanceof LoginFailed ? "Couldn't log in: " + e.message + "." : e.message);
  } finally {
    $("r-go").disabled = false;
    $("r-go").textContent = "Join";
  }
}

async function openMap(focus = null) {
  $("dlg-map").showModal();
  const nodes = [...app.node.contacts.values()];
  $("map-note").textContent = "Loading the map…";
  try {
    const n = await showMap($("map-box"), nodes, {
      serverBase: servedBy(), center: focus && focus.lat != null ? focus : null,
      popup: (c) => el("div", { class: "map-pop" }, el("b", {}, contactName(c)),
        el("span", {}, ({ chat: "Person", repeater: "Repeater", room: "Room", sensor: "Sensor" }[c.type] || c.type) +
          " · " + c.pubHex.slice(0, 8) + " · heard " + ago(c.lastHeard)),
        c.type === "chat" ? el("button", { type: "button", onclick: () => { $("dlg-map").close(); openDm(c); } }, "Message") : null,
        c.type === "room" ? el("button", { type: "button", onclick: () => { $("dlg-map").close(); openRoom(c); } }, c.room ? "Open" : "Join") : null),
    });
    $("map-note").textContent = n + " of " + nodes.length + " known nodes have shared a position. Repeaters are blue, rooms purple, people green.";
  } catch (e) {
    $("map-note").textContent = "The map couldn't load: " + e.message + " (it needs the internet for the map tiles).";
  }
}

// ---------------------------------------------------------------- wiring

function wire() {
  $("login-form").addEventListener("submit", login);
  $("f-priv").addEventListener("input", updatePubPreview);
  $("f-priv-gen").addEventListener("click", () => {
    if ($("f-priv").value.trim() && !confirm("Replace this private key with a new one? A new key is a new node.")) return;
    $("f-priv").value = Identity.generate().privateHex;
    $("f-priv").type = "text";
    $("f-priv-show").textContent = "Hide";
    updatePubPreview();
  });
  $("f-priv-show").addEventListener("click", () => {
    const shown = $("f-priv").type === "text";
    $("f-priv").type = shown ? "password" : "text";
    $("f-priv-show").textContent = shown ? "Show" : "Hide";
  });
  $("f-remember").addEventListener("change", () => { $("pass-box").hidden = !$("f-remember").checked; });
  $("unlock-other").addEventListener("click", () => { setUnlockMode(false); $("f-priv").focus(); });
  $("url-change").addEventListener("click", () => {
    $("url-auto").hidden = true;
    $("url-box").hidden = false;
    $("f-url").value = "";
    $("f-url").focus();
  });
  $("path-hash").value = String(pathHashSize());
  $("path-hash").addEventListener("change", () => {
    saveSettings({ ...loadSettings(), pathHash: Number($("path-hash").value) });
    if (app.node) app.node.hashSize = pathHashSize();
  });
  $("theme").addEventListener("change", () => {
    saveSettings({ ...loadSettings(), theme: $("theme").value });
    applyTheme();
  });
  matchMedia("(prefers-color-scheme: light)").addEventListener?.("change", () => applyTheme());
  $("show-gifs").checked = gifsOn();
  $("show-gifs").addEventListener("change", () => {
    saveSettings({ ...loadSettings(), gifs: $("show-gifs").checked });
    if (app.identity) renderConversation();
    updateGifPreview();
  });
  $("composer").addEventListener("submit", sendMessage);
  $("send").addEventListener("mousedown", (e) => e.preventDefault());   // (a tap on Send leaves the keyboard up)
  $("text").addEventListener("input", () => { autosize(); updateComposer(); updateGifPreview(); updateMentions(); });
  $("text").addEventListener("click", updateMentions);
  $("text").addEventListener("blur", () => setTimeout(closeMentions, 150));
  $("text").addEventListener("keydown", (e) => {
    if (mentionKeys(e)) return;
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) sendMessage(e);
  });
  $("add-channel").addEventListener("click", openAdd);
  $("add-form").addEventListener("submit", addChannel);
  for (const t of document.querySelectorAll("#dlg-add .tab")) t.addEventListener("click", () => setAddKind(t.dataset.kind));
  $("a-gen").addEventListener("click", () => { $("a-secret").value = bytesToHex(randomBytes(16)); });
  $("new-dm").addEventListener("click", () => openContacts("chat"));
  $("join-room").addEventListener("click", () => openRoom(null));
  $("room-form").addEventListener("submit", joinRoomFromDialog);
  $("open-contacts").addEventListener("click", () => openContacts());
  for (const t of document.querySelectorAll("#dlg-contacts .tab")) t.addEventListener("click", () => { contactTab = t.dataset.ctab; renderContacts(); });
  $("c-search").addEventListener("input", renderContacts);
  $("open-map").addEventListener("click", () => openMap());
  $("channel-info").addEventListener("click", openInfo);
  for (const r of document.querySelectorAll('input[name="i-route"]')) r.addEventListener("change", () => {
    const c = conv()?.contact;
    if (!c) return;
    if (r.value === "manual" && !c.manual) {
      $("i-manual").disabled = false;
      return $("i-manual").focus();
    }
    setRoute(c, r.value);
  });
  $("i-manual-set").addEventListener("click", () => {
    const c = conv()?.contact, p = parsePath($("i-manual").value);
    if (!c) return;
    if (!p) return toast("A path is repeater ids, all the same length: like a1,b2,c3 or a1b2,c3d4.");
    setRoute(c, "manual", p);
  });
  $("i-forget").addEventListener("click", () => {
    const c = conv()?.contact;
    if (!c) return;
    [c.outPath, c.outLen] = [new Uint8Array(0), null];
    scheduleSave();
    renderRouteBox(c);
    $("room-sub").textContent = conv().sub;
  });
  $("i-leave").addEventListener("click", leaveConversation);
  $("i-clear").addEventListener("click", clearHistory);
  $("i-relogin").addEventListener("click", async () => {
    const c = conv()?.contact;
    $("dlg-info").close();
    if (!c) return;
    toast("Logging in to " + contactName(c) + "…");
    try {
      await roomLogin(c, c.room.password || "");
    } catch (e) {
      toast("Couldn't log in: " + e.message);
    }
  });
  $("i-copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("i-secret").value);
      toast("Copied.");
    } catch {
      $("i-secret").select();
    }
  });
  $("advert").addEventListener("click", () => $("dlg-advert").showModal());
  for (const b of document.querySelectorAll("[data-advert]")) b.addEventListener("click", () => advertise(b.dataset.advert));
  for (const b of document.querySelectorAll("[data-close]")) b.addEventListener("click", () => b.closest("dialog").close());
  $("logout").addEventListener("click", () => {
    const s = loadSettings();
    const forget = s.remember && confirm("Also forget your saved key on this device? (Your channels and messages are kept.)");
    if (forget) {
      const { url, name, gifs, theme, otherServer, pathHash } = s;
      saveSettings({ url, name, gifs, theme, otherServer, pathHash, remember: false });
    }
    logout();
  });
  $("toggle-side").addEventListener("click", () => $("sidebar").classList.toggle("open"));
  document.addEventListener("click", (e) => {
    if (!$("react-pop").hidden && !e.target.closest("#react-pop, .react-btn")) closeReactPicker();
    // (by the path the click took: a tab redraws itself, so its button may have left the page by now)
    const inside = e.composedPath().some((n) => ["pick-pop", "emoji-btn", "gif-btn", "react-pop"].includes(n.id));
    if (picker && !inside) closePicker();
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && picker) { closePicker(); $("text").focus(); } });
  for (const [id, kind] of [["emoji-btn", "emoji"], ["gif-btn", "gif"]]) {
    $(id).addEventListener("mousedown", (e) => e.preventDefault());    // (the message box keeps focus, and the keyboard)
    $(id).addEventListener("click", () => openPicker(kind, $("composer")));
  }
  $("gif-q").addEventListener("input", () => { clearTimeout(gifTimer); gifTimer = setTimeout(searchGifs, 350); });
  $("pick-pop").addEventListener("mousedown", (e) => { if (e.target.closest("button")) e.preventDefault(); });
  $("messages").addEventListener("scroll", closeReactPicker);
  $("reply-cancel").addEventListener("click", () => setReply(null));
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && app.active && app.unread[app.active]) {
      delete app.unread[app.active];
      renderSidebar();
      updateTitle();
    }
  });
  window.addEventListener("pagehide", flushSave);
}

wire();
applyTheme();
fitToKeyboard();
initLogin();
