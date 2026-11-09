"""The KaaS connection: every packet the radio hears and sends comes in; your raw packets go out."""
import itertools
import json
import logging
import queue
import threading

from .packet import Packet
from .ws import Closed, OP_TEXT, WebSocket

log = logging.getLogger("meshroom_kaas")

FINAL = ("sent", "local", "dropped")


def _hex(x):
    x = getattr(x, "pub", x)                # (a Contact)
    return x.hex() if isinstance(x, (bytes, bytearray)) else str(x)


def _is_key(s):
    """A public key (or at least its first 8 bytes) in hex, rather than a name."""
    try:
        return 8 <= len(bytes.fromhex(s)) <= 32
    except ValueError:
        return False


class RequestError(Exception):
    """The server couldn't answer a request (the message says why)."""


class SendResult(dict):
    """{"status": "queued" | "sent" | "local" | "dropped", "reason": ..., "retry_after": ...}.
    sent: it went on the air. local: it was only for a node on the server's radio (a room there, say), which
    got it without it going on the air. dropped: refused (reason says why; retry_after, when given, is in seconds)."""

    status = property(lambda s: s.get("status"))
    ok = property(lambda s: s.get("status") in ("sent", "local"))


class KaasClient:
    """KaasClient("wss://host/api/v1/kaas", "kaas_...").

    connect() opens the websocket; a reader thread then delivers each packet to every on_packet callback (on that
    thread: keep them quick) and to packets(). send() transmits a raw packet and waits for the server's verdict."""

    def __init__(self, url, key, ssl_context=None):
        self.url, self.key, self.ssl_context = url, key, ssl_context
        self.ws = None
        self.hello = None
        self.callbacks = []
        self.waiting = {}
        self.queries = {}                   # request id -> (Event, box): near / routes
        self.ids = itertools.count(1)
        self.lock = threading.Lock()
        self.inbox = None
        self.closed = threading.Event()
        self.close_reason = None
        self.dropped = 0                    # packets the server dropped because this client fell behind

    def connect(self, timeout=10.0):
        self.ws = WebSocket.connect(self.url, {"Authorization": "Bearer " + self.key}, timeout, self.ssl_context)
        op, data = self.ws.recv()
        self.hello = json.loads(data)
        if self.hello.get("type") != "hello":
            raise RuntimeError("expected a hello from the server, got %r" % self.hello)
        self.closed.clear()
        threading.Thread(target=self._reader, name="kaas-reader", daemon=True).start()
        return self.hello

    def on_packet(self, fn):
        """fn(packet): called for every packet (packet.dir is "rx" or "tx"). Usable as a decorator."""
        self.callbacks.append(fn)
        return fn

    def packets(self, maxsize=1000):
        """Iterate over packets as they come (until the connection closes)."""
        with self.lock:
            if self.inbox is None:
                self.inbox = queue.Queue(maxsize)
        while True:
            p = self.inbox.get()
            if p is None:
                return
            yield p

    def send(self, packet, wait=True, timeout=60.0):
        """Send a raw packet (a Packet or bytes). wait=True: block until it's sent, handed to a local node or dropped
        (a SendResult); wait=False: return right away with {"status": "queued"} or None."""
        raw = packet.encode() if isinstance(packet, Packet) else bytes(packet)
        rid = next(self.ids)
        ev = threading.Event()
        box = {}
        with self.lock:
            self.waiting[rid] = (ev, box, wait)
        self.ws.send_text(json.dumps({"type": "send", "id": rid, "raw": raw.hex()}))
        if not wait:
            return None
        if not ev.wait(timeout):
            with self.lock:
                self.waiting.pop(rid, None)
            return SendResult(box.get("last") or {"status": "queued"})
        return SendResult(box["final"])

    def near(self, node, limit=4, timeout=10.0):
        """The repeaters that hear a node (its first hop into the mesh), most first: a list of
        {"id": hex, "name", "share": 0..1}, with "direct": True when the server's radio hears it directly (id and name are then its virtual repeater, or the room).
        node: its public key (bytes or hex; the first 8 bytes are enough), or its advertised name, plain or as a
        mention like "@[platinum]" (ignoring case). Up to 4 are known per node."""
        return self.lookup(node, limit, timeout)["repeaters"]

    def lookup(self, node, limit=4, timeout=10.0):
        """near(), with the node too: {"node": hex (as given, or its first 8 bytes when asked by name),
        "name": its advertised name or None, "repeaters": [...]}."""
        node = _hex(node)
        field = "node" if _is_key(node) else "name"
        msg = self._request("near", timeout, limit=limit, **{field: node})
        return {"node": msg.get("node"), "name": msg.get("name"), "repeaters": msg["repeaters"]}

    def routes(self, repeater, limit=3, timeout=10.0):
        """The server's best routes to a repeater, best first: a list of {"path_len", "path" (hex), "hops", "names",
        "confidence": 0..1}. path_len and path go straight into Packet.direct(..., bytes.fromhex(path), path_len);
        the repeater is the last hop. repeater: its public key or id (bytes or hex; the first 2 bytes are enough)."""
        return self._request("routes", timeout, repeater=_hex(repeater), limit=limit)["routes"]

    def route(self, src, dst, limit=3, timeout=10.0):
        """Suggested routes from one node to another through the repeaters the server has seen linked, best first:
        {"from", "to", "routes": [{"path_len", "path" (hex), "hops", "names", "score": 0..1}]}. path_len and path go
        straight into Packet.direct(...) for a packet from src to dst. src, dst: a node's public key (bytes or hex,
        at least 8 bytes), its advertised name or "@[name]", or a repeater's 2-byte id in hex. limit: 1 to 5."""
        msg = self._request("route", timeout, limit=limit, **{"from": _hex(src), "to": _hex(dst)})
        return {"from": msg["from"], "to": msg["to"], "routes": msg["routes"]}

    def paths(self, node, limit=4, timeout=10.0):
        """Direct paths from the server's radio to a node, best first, as its room plans its own deliveries: a list of
        {"path_len", "path" (hex), "hops", "names", "score": 0..1, "source": "measured" (delivered on before), "map"
        (built from the repeaters that hear it), "shortcut" or "direct" (heard with no hops)}. path_len and path go
        straight into Packet.direct(...). node: its public key (bytes or hex, all 32 bytes). limit: 1 to 8."""
        return self._request("paths", timeout, node=_hex(node), limit=limit)["paths"]

    def nodes(self, days=7, timeout=10.0):
        """The server's node directory: every node heard advertising in the last `days`, most recent first, as
        {"pub", "type": "chat" | "repeater" | "room" | "sensor", "name", "lat", "lon", "last_heard", "rf", "obs"}."""
        return self._request("nodes", timeout, days=days)["nodes"]

    def _request(self, t, timeout, **fields):
        rid = "q%d" % next(self.ids)
        ev, box = threading.Event(), {}
        with self.lock:
            self.queries[rid] = (ev, box)
        self.ws.send_text(json.dumps(dict(type=t, id=rid, **fields)))
        if not ev.wait(timeout):
            with self.lock:
                self.queries.pop(rid, None)
            raise RequestError("no answer from the server")
        if box["msg"].get("type") == "error":
            raise RequestError(box["msg"].get("error"))
        return box["msg"]

    def close(self):
        if self.ws is not None:
            self.ws.close()
        self.closed.wait(5)

    def wait(self, timeout=None):
        """Block until the connection closes. Returns its close reason."""
        self.closed.wait(timeout)
        return self.close_reason

    def _reader(self):
        try:
            while True:
                op, data = self.ws.recv()
                if op != OP_TEXT:
                    continue
                msg = json.loads(data)
                t = msg.get("type")
                if t == "packet":
                    p = Packet.parse(bytes.fromhex(msg["raw"]))
                    if p is None:
                        continue
                    p.dir, p.snr, p.rssi, p.ts = msg.get("dir"), msg.get("snr"), msg.get("rssi"), msg.get("ts")
                    for fn in list(self.callbacks):
                        try:
                            fn(p)
                        except Exception:
                            log.exception("on_packet callback")
                    if self.inbox is not None:
                        try:
                            self.inbox.put_nowait(p)
                        except queue.Full:
                            pass
                elif t == "send_result":
                    with self.lock:
                        w = self.waiting.get(msg.get("id"))
                        if w and msg.get("status") in FINAL:
                            del self.waiting[msg.get("id")]
                    if w:
                        w[1]["last"] = msg
                        if msg.get("status") in FINAL:
                            w[1]["final"] = msg
                            w[0].set()
                elif t in ("near_result", "routes_result", "route_result", "paths_result", "nodes_result", "error") \
                        and msg.get("id") in self.queries:
                    with self.lock:
                        q = self.queries.pop(msg.get("id"), None)
                    if q:
                        q[1]["msg"] = msg
                        q[0].set()
                elif t == "dropped":
                    self.dropped += msg.get("count", 0)
                    log.warning("the server dropped %s packets: this client is reading too slowly", msg.get("count"))
                elif t == "error":
                    log.warning("server: %s", msg.get("error"))
        except Closed as e:
            self.close_reason = e
        except Exception as e:
            log.exception("reader")
            self.close_reason = e
        finally:
            with self.lock:
                waiting, self.waiting = self.waiting, {}
                queries, self.queries = self.queries, {}
            for ev, box in queries.values():
                box["msg"] = {"type": "error", "error": "connection closed"}
                ev.set()
            for ev, box, _ in waiting.values():
                box["final"] = {"status": "dropped", "reason": "connection closed"}
                ev.set()
            if self.inbox is not None:
                try:
                    self.inbox.put_nowait(None)
                except queue.Full:
                    pass
            self.closed.set()
