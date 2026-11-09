// The KaaS connection: log in for a one-time ticket over HTTPS by signing with the node's private key, open the
// websocket with it, stream packets in, and send raw packets out within the server's per-key rate
// limit. Reconnects by itself, logging in again each time.
import { bytesToHex, hexToBytes, utf8Encode } from "./bytes.js";

export const KAAS_PATH = "/api/v1/kaas";
export const WEB_PATH = "/api/v1/web";
// Signed first, always from here and never from the server, so a login signature can't be anything but a login.
export const WEB_LOGIN_LABEL = "meshcore-web login v1";

export class AuthError extends Error {}

// The server's MeshCore Web has a page password, and this login didn't give it (or gave a wrong one).
export class PagePasswordNeeded extends AuthError {}

// "https://host[/prefix]" (or with /api/v1/kaas on the end, or ws(s)://) -> {challenge, login, ticket: https URLs, ws}
export function kaasEndpoints(input) {
  let s = String(input || "").trim();
  if (!s) throw new Error("Enter the pyMeshRoom URL.");
  if (!/^[a-z]+:\/\//i.test(s)) s = "https://" + s;
  const u = new URL(s);
  const secure = { https: true, wss: true, http: false, ws: false }[u.protocol.slice(0, -1)];
  if (secure === undefined) throw new Error("The URL must start with https://.");
  let base = u.pathname.replace(/\/+$/, "");
  if (base.endsWith(KAAS_PATH)) base = base.slice(0, -KAAS_PATH.length);
  const host = u.host + base;
  const http = (secure ? "https://" : "http://") + host;
  return {
    challenge: http + WEB_PATH + "/challenge",
    login: http + WEB_PATH + "/login",
    ticket: http + WEB_PATH + "/ticket",
    ws: (secure ? "wss://" : "ws://") + host + KAAS_PATH,
    host: u.host,
    secure,
  };
}

// What a web login signs: the label, the server's host as we reach it, the server's challenge, our public key.
export function webLoginMessage(host, challenge, pubHex) {
  return utf8Encode([WEB_LOGIN_LABEL, host, challenge, pubHex].join("\n"));
}

// Why a websocket didn't open, from what the server says became of its ticket (POST /api/v1/web/ticket).
const TICKET_OUTCOMES = {
  waiting: "the login worked, but the websocket never reached pyMeshRoom. If a reverse proxy is in front of it, the " +
    "proxy has to pass websockets on (nginx: proxy_http_version 1.1, and set the Upgrade and Connection headers); " +
    "otherwise a browser extension or firewall may be blocking websockets",
  unused: null,                                         // (the same as waiting)
  no_upgrade: "the websocket reached pyMeshRoom without its Upgrade header: a reverse proxy in front of it is " +
    "dropping it (nginx: proxy_http_version 1.1, and set the Upgrade and Connection headers)",
  bad_version: "the websocket reached pyMeshRoom in a version it doesn't speak (a proxy may be changing it)",
  busy: "the server was too busy",
  full: "all of this server's web sessions are in use",
  too_many: "too many sessions or connections from your address: close another tab, or wait a minute",
  expired: "the login expired before the websocket opened",
  refused: "the server refused the session (web logins were turned off, or this key was banned)",
};
TICKET_OUTCOMES.unused = TICKET_OUTCOMES.waiting;

// Reconnecting: after 1 s, then twice as long each time, up to 15 s (a server restart is back within a few tries).
const RETRY_FIRST_MS = 1000;
const RETRY_MAX_MS = 15000;

const CLOSE_REASONS = {
  4003: "this key is banned from this server",
  4004: "web logins were turned off on this server",
  4005: "the admin disconnected this session",
  1001: "the server is shutting down",
};

// Events: "state" {state: "connecting" | "open" | "closed" | "failed", reason}, "hello" (the hello message),
// "packet" ({dir, raw: Uint8Array, snr, rssi, ts, hash}), "dropped" (count), "send" ({id, status, reason}),
// "access" ({send, state}): a web login may now send, or may not anymore.
// auth: {identity, name, pagePassword?}: logs in by signing with the identity's private key.
export class KaasClient extends EventTarget {
  constructor(url, auth) {
    super();
    this.endpoints = kaasEndpoints(url);
    this.identity = auth.identity || null;
    this.name = auth.name || "";
    this.pagePassword = auth.pagePassword || "";        // (a page served by the server itself has its cookie instead)
    this.ws = null;
    this.hello = null;
    this.state = "closed";
    this.stopped = true;
    this.retryMs = RETRY_FIRST_MS;
    this.timer = null;
    this.nextId = 1;
    this.waiting = new Map();             // send id -> {resolve, packet}
    this.queries = new Map();             // request id -> {resolve, reject}: nodes, near, routes, route
    this.queue = [];                      // {raw, resolve}: sends waiting for the rate limit
    this.recent = [];                     // when our sends went (performance.now()), for the rolling window
    this.pumping = false;
  }

  emit(type, detail) {
    this.dispatchEvent(new CustomEvent(type, { detail }));
  }

  setState(state, reason = "") {
    this.state = state;
    this.emit("state", { state, reason });
  }

  // Resolves with hello on the first connection; rejects (AuthError for a bad key) if that one fails.
  start() {
    this.stopped = false;
    if (!this.wake && typeof window !== "undefined") {
      this.wake = () => this.retryNow();
      window.addEventListener("online", this.wake);
      document.addEventListener("visibilitychange", () => document.visibilityState === "visible" && this.wake());
    }
    return this.connect();
  }

  // Waiting to reconnect: try now (the network came back, or the tab was shown again).
  retryNow() {
    if (this.stopped || !this.timer || this.state !== "closed") return;
    this.retryMs = RETRY_FIRST_MS;
    this.connect().catch(() => {});
  }

  stop() {
    this.stopped = true;
    clearTimeout(this.timer);
    if (this.ws) this.ws.close(1000);
    this.ws = null;
    this.failAll("disconnected");
    for (const item of this.queue.splice(0)) item.resolve({ status: "dropped", reason: "disconnected" });
    this.setState("closed");
  }

  async post(url, headers, body) {
    let r;
    try {
      r = await fetch(url, {
        method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body || {}),
        cache: "no-store",
      });
    } catch (e) {
      throw new Error("Can't reach " + this.endpoints.host + " (offline, a wrong URL, or a pyMeshRoom too old for browser logins).");
    }
    const answer = await r.json().catch(() => ({}));
    if (r.status === 401 && answer.page_password) throw new PagePasswordNeeded(answer.error || "this server needs a page password");
    if (r.status === 401 || r.status === 403) throw new AuthError(answer.error || "the server refused the login");
    if (!r.ok) throw new Error(answer.error || "The server answered " + r.status + ".");
    return answer;
  }

  async getTicket() {
    const page = this.pagePassword ? { page_password: this.pagePassword } : {};
    const { challenge } = await this.post(this.endpoints.challenge, {}, page);
    if (!/^wc_[\w-]{8,100}$/.test(String(challenge))) throw new Error("The server sent a malformed challenge.");
    const pub = this.identity.pubHex;
    const signature = bytesToHex(this.identity.sign(webLoginMessage(this.endpoints.host, challenge, pub)));
    const r = await this.post(this.endpoints.login, {}, { pub, signature, challenge, host: this.endpoints.host, name: this.name, ...page });
    if (!r.ticket) throw new Error("The server sent no ticket.");
    return r.ticket;
  }

  connect() {
    clearTimeout(this.timer);
    this.setState("connecting");
    return new Promise((resolve, reject) => {
      let opened = false;
      this.getTicket().then((ticket) => {
        if (this.stopped) return;
        const ws = new WebSocket(this.endpoints.ws + "?ticket=" + encodeURIComponent(ticket));
        this.ws = ws;
        ws.onmessage = (e) => {
          let msg;
          try {
            msg = JSON.parse(e.data);
          } catch {
            return;
          }
          if (!opened) {
            if (msg.type !== "hello") return;
            opened = true;
            this.hello = msg;
            this.retryMs = RETRY_FIRST_MS;
            this.setState("open");
            this.emit("hello", msg);
            resolve(msg);
            this.pump();
            return;
          }
          this.onMessage(msg);
        };
        ws.onclose = (e) => {
          if (this.ws !== ws) return;
          this.ws = null;
          this.failAll("connection closed");
          const reason = CLOSE_REASONS[e.code] || e.reason || (opened ? "connection lost" : "");
          if (reason) {
            if (!opened) reject(new Error(reason));
            if (e.code >= 4001 && e.code <= 4005) return this.fail(reason);
            return this.retry(reason);
          }
          this.whyNotOpen(ticket).then((why) => {        // (a browser isn't told why a websocket didn't open: ask)
            reject(new Error(why));
            this.retry(why);
          });
        };
      }).catch((e) => {
        if (e instanceof AuthError) {
          this.fail(e.message);
          reject(e);
          return;
        }
        reject(e);
        this.retry(e.message);
      });
    });
  }

  async whyNotOpen(ticket) {
    try {
      const { outcome } = await this.post(this.endpoints.ticket, {}, { ticket });
      if (TICKET_OUTCOMES[outcome]) return "The websocket didn't open: " + TICKET_OUTCOMES[outcome];
    } catch {}
    return "The websocket didn't open";
  }

  fail(reason) {
    this.stopped = true;
    this.setState("failed", reason);
  }

  retry(reason) {
    if (this.stopped) return;
    const wait = this.retryMs;
    this.retryMs = Math.min(this.retryMs * 2, RETRY_MAX_MS);
    this.setState("closed", reason + "; retrying in " + Math.round(wait / 1000) + " s");
    this.timer = setTimeout(() => this.connect().catch(() => {}), wait);
  }

  onMessage(msg) {
    if (msg.type === "packet") {
      let raw;
      try {
        raw = hexToBytes(msg.raw);
      } catch {
        return;
      }
      this.emit("packet", { dir: msg.dir, raw, snr: msg.snr, rssi: msg.rssi, ts: msg.ts, hash: msg.hash, seq: msg.seq });
    } else if (msg.type === "replay_batch") {
      this.emit("replay", msg.packets || []);
    } else if (msg.type === "send_result") {
      const w = this.waiting.get(msg.id);
      this.emit("send", msg);
      if (w && msg.status !== "queued") {
        this.waiting.delete(msg.id);
        w.resolve(msg);
      }
    } else if ((/_result$|^replay_done$/.test(msg.type) || msg.type === "error") && this.queries.has(msg.id)) {
      const q = this.queries.get(msg.id);
      this.queries.delete(msg.id);
      if (msg.type === "error") q.reject(new Error(msg.error || "the server couldn't answer"));
      else q.resolve(msg);
    } else if (msg.type === "room_post") {
      this.emit("room_post", msg);
    } else if (msg.type === "dropped") {
      this.emit("dropped", msg.count);
    } else if (msg.type === "access" && this.hello?.key) {
      this.hello.key.send = !!msg.send;
      this.hello.key.state = msg.state;
      this.emit("access", msg);
      this.pump();
    }
  }

  failAll(reason) {
    for (const w of this.waiting.values()) w.resolve({ status: "dropped", reason });
    this.waiting.clear();
    for (const q of this.queries.values()) q.reject(new Error(reason));
    this.queries.clear();
  }

  // A question for the server ({type: "nodes", days: 7}, ...) -> its answer, or throws with the server's error.
  request(type, fields = {}, timeoutMs = 15000) {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return reject(new Error("not connected"));
      const id = "q" + this.nextId++;
      const timer = setTimeout(() => { this.queries.delete(id); reject(new Error("no answer from the server")); }, timeoutMs);
      this.queries.set(id, {
        resolve: (m) => { clearTimeout(timer); resolve(m); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      });
      this.ws.send(JSON.stringify({ ...fields, type, id }));
    });
  }

  // One packet straight to the server -> the final send_result.
  sendNow(raw) {
    return new Promise((resolve) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return resolve({ status: "dropped", reason: "not connected" });
      const id = this.nextId++;
      this.waiting.set(id, { resolve });
      this.ws.send(JSON.stringify({ type: "send", id, raw: bytesToHex(raw) }));
    });
  }

  // A packet through the queue: waits its turn under send_burst per send_window_s, and retries once if the server
  // still says rate limit (another client on the same key). Resolves with the final send_result.
  send(raw) {
    return new Promise((resolve) => {
      this.queue.push({ raw, resolve, tries: 0 });
      this.pump();
    });
  }

  async pump() {
    if (this.pumping) return;
    this.pumping = true;
    try {
      while (this.queue.length && this.state === "open") {
        const burst = Number(this.hello?.send_burst ?? 3);
        const windowMs = Number(this.hello?.send_window_s ?? 20) * 1000;
        const now = performance.now();
        this.recent = this.recent.filter((t) => now - t < windowMs);
        if (this.recent.length >= burst) {
          await sleep(this.recent[0] + windowMs - now + 50);
          continue;
        }
        const item = this.queue[0];
        this.recent.push(performance.now());
        const res = await this.sendNow(item.raw);
        if (res.status === "dropped" && /rate limit/.test(res.reason || "") && item.tries++ < 2) {
          await sleep(1000 * Number(res.retry_after || 1));
          continue;
        }
        this.queue.shift();
        item.resolve(res);
      }
    } finally {
      this.pumping = false;
    }
  }

  // Sends still waiting for the rate limit (shown as "waiting" in the UI).
  get backlog() {
    return this.queue.length;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, Math.max(0, ms)));
