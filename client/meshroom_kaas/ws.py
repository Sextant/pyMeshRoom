"""A small websocket client (RFC 6455) on the standard library: enough for the KaaS API, no dependency."""
import base64
import hashlib
import os
import socket
import ssl
import struct
import threading
from urllib.parse import urlsplit

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 1, 2, 8, 9, 10


class HandshakeError(Exception):
    """The server refused the connection (e.g. 401: unknown, revoked or expired key)."""

    def __init__(self, status, body):
        super().__init__("HTTP %s: %s" % (status, body))
        self.status, self.body = status, body


class Closed(Exception):
    """The connection ended. code/reason are from the server's close frame, if it sent one."""

    def __init__(self, code=None, reason=""):
        super().__init__("connection closed%s" % (" (%s %s)" % (code, reason) if code else ""))
        self.code, self.reason = code, reason


def frame(opcode, data=b""):
    """A whole, masked (client) frame."""
    n = len(data)
    head = bytearray([0x80 | opcode])
    if n < 126:
        head.append(0x80 | n)
    elif n < 65536:
        head.append(0x80 | 126)
        head += struct.pack(">H", n)
    else:
        head.append(0x80 | 127)
        head += struct.pack(">Q", n)
    k = os.urandom(4)
    return bytes(head) + k + bytes(b ^ k[i & 3] for i, b in enumerate(data))


class WebSocket:
    def __init__(self, sock, rfile):
        self.sock, self.rfile = sock, rfile
        self.lock = threading.Lock()
        self.closed = False

    @classmethod
    def connect(cls, url, headers=None, timeout=10.0, ssl_context=None):
        u = urlsplit(url)
        if u.scheme not in ("ws", "wss"):
            raise ValueError("the URL must start with ws:// or wss://")
        port = u.port or (443 if u.scheme == "wss" else 80)
        sock = socket.create_connection((u.hostname, port), timeout=timeout)
        if u.scheme == "wss":
            sock = (ssl_context or ssl.create_default_context()).wrap_socket(sock, server_hostname=u.hostname)
        key = base64.b64encode(os.urandom(16)).decode()
        host = u.hostname if u.port is None else "%s:%d" % (u.hostname, u.port)
        lines = ["GET %s HTTP/1.1" % ((u.path or "/") + ("?" + u.query if u.query else "")), "Host: " + host,
                 "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Key: " + key, "Sec-WebSocket-Version: 13"]
        lines += ["%s: %s" % kv for kv in (headers or {}).items()]
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        rfile = sock.makefile("rb")
        status = rfile.readline().decode(errors="replace").split(" ", 2)
        hdrs = {}
        while True:
            line = rfile.readline().decode(errors="replace").strip()
            if not line:
                break
            k, _, v = line.partition(":")
            hdrs[k.strip().lower()] = v.strip()
        code = status[1] if len(status) > 1 else "?"
        if code != "101":
            n = int(hdrs.get("content-length") or 0)
            body = rfile.read(n).decode(errors="replace") if n else ""
            sock.close()
            raise HandshakeError(code, body)
        want = base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()
        if hdrs.get("sec-websocket-accept") != want:
            sock.close()
            raise HandshakeError(code, "bad Sec-WebSocket-Accept")
        sock.settimeout(None)
        return cls(sock, rfile)

    def _exact(self, n):
        b = self.rfile.read(n) if n else b""
        if len(b) < n:
            raise Closed()
        return b

    def send(self, opcode, data):
        with self.lock:
            if self.closed:
                raise Closed()
            self.sock.sendall(frame(opcode, data))

    def send_text(self, text):
        self.send(OP_TEXT, text.encode())

    def recv(self):
        """The next data message: (opcode, payload). Answers pings; raises Closed when the connection ends."""
        parts, first = [], None
        while True:
            try:
                h = self._exact(2)
                op, n = h[0] & 0x0F, h[1] & 0x7F
                if n == 126:
                    n = struct.unpack(">H", self._exact(2))[0]
                elif n == 127:
                    n = struct.unpack(">Q", self._exact(8))[0]
                data = self._exact(n)
            except OSError:
                raise Closed()
            if op == OP_PING:
                try:
                    self.send(OP_PONG, data)
                except (OSError, Closed):
                    pass
                continue
            if op == OP_PONG:
                continue
            if op == OP_CLOSE:
                code = struct.unpack(">H", data[:2])[0] if len(data) >= 2 else None
                self.close()
                raise Closed(code, data[2:].decode(errors="replace"))
            if op != 0:
                first = op
            parts.append(data)
            if h[0] & 0x80:
                return first, b"".join(parts)

    def close(self, code=1000):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            try:
                self.sock.sendall(frame(OP_CLOSE, struct.pack(">H", code)))
            except OSError:
                pass
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
