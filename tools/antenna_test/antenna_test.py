#!/usr/bin/env python3
"""Antenna test: score how well this radio's antenna reaches the repeaters around it.

Talks to a MeshCore KISS modem directly over serial (stop the room first: the port can only be open once).

  1. Discovery (10 min): a zero-hop repeater discovery every minute; every repeater that answers goes on the list.
  2. Traces: 20 rounds, 10 s apart. Each round traces every listed repeater once, one at a time.
     A trace that comes back scores 0.05, so each repeater scores 0.0 - 1.0 and the final score is their sum.

The web page (default http://<this machine>:8095/) has the Start button, the console and the results table.

    python3 tools/antenna_test/antenna_test.py                       # serial + radio settings from meshroom.json
    python3 tools/antenna_test/antenna_test.py --serial /dev/ttyUSB0 --freq 910.525 --bw 62.5 --sf 7 --cr 5

Requires: python3 >= 3.9, pyserial, cryptography (the same as the room).
"""
import argparse
import collections
import http.server
import json
import logging
import os
import queue
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "meshroom"))
import meshroom as mr  # noqa: E402

log = logging.getLogger("antenna_test")

DISCOVER_S = 600            # discovery phase length
DISCOVER_EVERY_S = 60       # a discovery request this often during it
ROUNDS = 20                 # traces per repeater
ROUND_INTERVAL_S = 10       # rounds start this far apart (later, if a round takes longer)
TRACE_TIMEOUT_S = 5         # a trace not back by then is lost
DISC_REPLY_GRACE_S = 20     # discovery replies still count this long after the last request


def discovery_packet(tag):
    """Zero-hop repeater discovery (as MeshCore repeaters send it): REQ, repeaters only, tag, since=0."""
    pkt = mr.Packet(mr.PT_CONTROL, bytes([0x80, 1 << mr.ADV_TYPE_REPEATER]) + tag + struct.pack("<I", 0))
    pkt.header = (pkt.header & ~0x03) | mr.ROUTE_DIRECT
    return pkt.encode()


def trace_packet(tag, h):
    """A trace whose route is just repeater h (2-byte id): it appends the SNR it heard us at and sends it back."""
    pkt = mr.Packet(mr.PT_TRACE, tag + bytes(4) + bytes([1]) + h)
    pkt.header = (pkt.header & ~0x03) | mr.ROUTE_DIRECT
    return pkt.encode()


def avg(xs):
    return round(sum(xs) / len(xs), 2) if xs else None


class KissRadio:
    """The KISS modem: radio settings pushed at open, raw packets out, (raw, snr, rssi) in."""

    def __init__(self, port, baud, freq_mhz, bw_khz, sf, cr, tx_power=None, txdelay=1, persistence=128, slottime=5):
        self.events = queue.Queue()
        self.modem = mr.KissModem(port, baud, self.events)
        for _ in range(10):                                 # a modem that just reset needs time to boot
            if self.modem.command(0x17, timeout=1.5) is not None:
                break
        else:
            self.modem.close()
            raise RuntimeError("no reply from a KISS modem on %s (right port? is the room still running on it?)" % port)
        self.modem.set_param(0x01, txdelay)
        self.modem.set_param(0x02, persistence)
        self.modem.set_param(0x03, slottime)
        self.modem.command(0x19, b"\x01")                  # RxMeta (SNR/RSSI) on
        want = (int(round(freq_mhz * 1e6)), int(round(bw_khz * 1e3)), int(sf), int(cr))
        self.modem.command(0x09, struct.pack("<IIBB", *want), timeout=3)
        if tx_power is not None:
            self.modem.command(0x0A, bytes([int(tx_power) & 0xFF]), timeout=3)
        r = self.modem.command(0x0B)
        got = struct.unpack("<IIBB", r[:10]) if r and len(r) >= 10 else None
        if got != want:
            raise RuntimeError("modem did not accept radio settings %s (reports %s)" % (want, got))
        self.settings = "%.3f MHz, BW %g kHz, SF%d, CR4/%d" % (freq_mhz, bw_khz, sf, cr)

    def send(self, raw):
        self.modem.send_packet(raw)

    def recv(self, timeout):
        """(raw, snr, rssi) or None. Raises on a serial error."""
        try:
            ev = self.events.get(timeout=timeout)
        except queue.Empty:
            return None
        if ev[0] == "serial_error":
            raise RuntimeError("serial link to the modem failed")
        return (ev[1], ev[2], ev[3]) if ev[0] == "rx" else None


class AntennaTest:
    """One test run at a time. start() runs discovery then the trace rounds on a worker thread; state() is what
    the web page shows."""

    def __init__(self, radio, discover_s=DISCOVER_S, discover_every_s=DISCOVER_EVERY_S, rounds=ROUNDS,
                 interval_s=ROUND_INTERVAL_S, trace_timeout_s=TRACE_TIMEOUT_S, grace_s=DISC_REPLY_GRACE_S,
                 results_dir=None):
        self.radio = radio
        self.discover_s, self.discover_every_s, self.grace_s = discover_s, discover_every_s, grace_s
        self.rounds, self.interval_s, self.trace_timeout_s = rounds, interval_s, trace_timeout_s
        self.results_dir = results_dir
        self.lock = threading.Lock()
        self.console = collections.deque(maxlen=1000)
        self.seq = 0
        self.phase = "idle"
        self.progress = ""
        self.repeaters = {}                                 # 2-byte id -> dict
        self.names = {}                                     # 2-byte id -> name, from adverts heard
        self.disc_tags = set()
        self.disc_open = False
        self.pending = None                                 # (tag, id, sent, threading.Event, [reply])
        self.worker = None
        threading.Thread(target=self._pump, name="rx", daemon=True).start()

    # ------------------------------------------------------------------ console

    def say(self, text):
        log.info("%s", text)
        with self.lock:
            self.seq += 1
            self.console.append(dict(n=self.seq, t=time.strftime("%H:%M:%S"), text=text))

    # ------------------------------------------------------------------ receiving

    def _pump(self):
        while True:
            try:
                got = self.radio.recv(0.5)
            except Exception as e:
                self.say("ERROR: %s" % e)
                with self.lock:
                    self.phase = "error"
                    self.radio_failed = True
                return
            if got:
                try:
                    self.on_rx(*got)
                except Exception:
                    log.exception("bad packet")

    def on_rx(self, raw, snr, rssi):
        pkt = mr.Packet.parse(raw)
        if pkt is None:
            return
        pkt.snr, pkt.rssi = snr, rssi
        if pkt.ptype == mr.PT_CONTROL:
            self.on_discovery_reply(pkt)
        elif pkt.ptype == mr.PT_TRACE:
            self.on_trace(pkt)
        elif pkt.ptype == mr.PT_ADVERT:
            a = mr.RoomServer.parse_advert(pkt)
            if a and a["name"]:
                with self.lock:
                    self.names[a["pub"][:2]] = a["name"]

    def on_discovery_reply(self, pkt):
        p = pkt.payload
        if len(p) < 6 + mr.PUB_KEY_SIZE or (p[0] & 0xF0) != 0x90 or (p[0] & 0x0F) != mr.ADV_TYPE_REPEATER:
            return
        with self.lock:
            if not self.disc_open or p[2:6] not in self.disc_tags:
                return                                      # not an answer to this run's discovery
            pub = p[6:6 + mr.PUB_KEY_SIZE]
            h = pub[:2]
            tx_snr = struct.unpack("b", p[1:2])[0] / 4.0   # how well it heard us
            new = h not in self.repeaters
            if new:
                self.repeaters[h] = dict(id=h.hex(), pub=pub.hex(), disc=0, ok=0, sent=0, tx=[], rx=[])
            r = self.repeaters[h]
            r["disc"] += 1
            count = len(self.repeaters)
        if new:
            self.say("found repeater %s%s: hears us at %.1f dB, we hear it at %.1f dB (%d so far)"
                     % (h.hex(), self._name_suffix(h), tx_snr, pkt.snr, count))

    def on_trace(self, pkt):
        p = pkt.payload
        with self.lock:
            pend = self.pending
            if not pend or len(p) < 9 or p[:4] != pend[0] or pkt.hop_count < 1:
                return
            self.pending = None
        tx_snr = struct.unpack("b", pkt.path[:1])[0] / 4.0
        pend[4].append((tx_snr, pkt.snr, time.monotonic() - pend[2]))
        pend[3].set()

    def _name_suffix(self, h):
        n = self.names.get(h)
        return " (%s)" % n if n else ""

    # ------------------------------------------------------------------ the run

    def start(self):
        with self.lock:
            if self.worker and self.worker.is_alive():
                return False
            if getattr(self, "radio_failed", False):
                return False
            self.repeaters = {}
            self.disc_tags = set()
            self.phase, self.progress = "discovering", ""
            self.started_at = time.time()
            self.worker = threading.Thread(target=self._run, name="test", daemon=True)
            self.worker.start()
        return True

    def _run(self):
        try:
            self._discover()
            if self.repeaters:
                self._trace_rounds()
            self._finish()
        except Exception as e:
            log.exception("test failed")
            self.say("ERROR: %s" % e)
            with self.lock:
                self.phase = "error"

    def _discover(self):
        self.say("discovering repeaters for %s" % fmt_dur(self.discover_s))
        end = time.monotonic() + self.discover_s
        with self.lock:
            self.disc_open = True
        n = 0
        while True:
            now = time.monotonic()
            if now >= end:
                break
            n += 1
            tag = os.urandom(4)
            with self.lock:
                self.disc_tags.add(tag)
                self.progress = "discovery request %d, %s left" % (n, fmt_dur(end - now))
            self.radio.send(discovery_packet(tag))
            self.say("sent discovery request %d" % n)
            time.sleep(max(0.0, min(self.discover_every_s, end - time.monotonic())))
        if self.grace_s:
            with self.lock:
                self.progress = "waiting for late discovery replies"
            time.sleep(self.grace_s)
        with self.lock:
            self.disc_open = False
            ids = sorted(self.repeaters)
        if ids:
            self.say("discovery done: %d repeater(s): %s" % (len(ids), ", ".join(h.hex() + self._name_suffix(h) for h in ids)))
        else:
            self.say("discovery done: no repeater answered")

    def _trace_rounds(self):
        ids = sorted(self.repeaters)
        self.say("tracing each repeater %d times, rounds %s apart" % (self.rounds, fmt_dur(self.interval_s)))
        with self.lock:
            self.phase = "tracing"
        for rnd in range(1, self.rounds + 1):
            round_start = time.monotonic()
            got = 0
            for i, h in enumerate(ids, 1):
                with self.lock:
                    self.progress = "round %d of %d, repeater %d of %d" % (rnd, self.rounds, i, len(ids))
                if self._trace(h):
                    got += 1
            self.say("round %d of %d: %d of %d came back, score so far %.2f"
                     % (rnd, self.rounds, got, len(ids), self.total()))
            if rnd < self.rounds:
                time.sleep(max(0.0, round_start + self.interval_s - time.monotonic()))

    def _trace(self, h):
        tag = os.urandom(4)
        evt, reply = threading.Event(), []
        with self.lock:
            self.pending = (tag, h, time.monotonic(), evt, reply)
            self.repeaters[h]["sent"] += 1
        self.radio.send(trace_packet(tag, h))
        evt.wait(self.trace_timeout_s)
        with self.lock:
            if self.pending and self.pending[0] == tag:
                self.pending = None
            r = self.repeaters[h]
            if not reply:
                lost = True
            else:
                lost = False
                tx, rx, rtt = reply[0]
                r["ok"] += 1
                r["tx"].append(tx)
                r["rx"].append(rx)
        if lost:
            self.say("trace %s%s: lost" % (h.hex(), self._name_suffix(h)))
        else:
            self.say("trace %s%s: TX %.1f dB, RX %.1f dB, %d ms" % (h.hex(), self._name_suffix(h), tx, rx, rtt * 1000))
        return not lost

    def _finish(self):
        st = self.state()
        with self.lock:
            self.phase, self.progress = "done", ""
        self.say("FINAL SCORE %.2f (%d repeater(s) answered at least one trace)" % (st["total"], len(st["repeaters"])))
        if self.results_dir:
            os.makedirs(self.results_dir, exist_ok=True)
            path = os.path.join(self.results_dir, "antenna_test_%s.json" % time.strftime("%Y%m%d_%H%M%S", time.localtime(self.started_at)))
            with open(path, "w") as f:
                json.dump(dict(started=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started_at)),
                               radio=getattr(self.radio, "settings", None), total=st["total"],
                               repeaters=st["repeaters"]), f, indent=2)
            self.say("results saved to %s" % path)

    # ------------------------------------------------------------------ results

    def score(self, r):
        return r["ok"] / float(self.rounds)

    def total(self):
        with self.lock:
            return round(sum(self.score(r) for r in self.repeaters.values()), 2)

    def state(self, since=0):
        with self.lock:
            rows = []
            for h, r in self.repeaters.items():
                if not r["ok"]:
                    continue                                # only repeaters that answered a trace at least once
                rows.append(dict(id=r["id"], name=self.names.get(h), tx_snr=avg(r["tx"]), rx_snr=avg(r["rx"]),
                                 ok=r["ok"], sent=r["sent"], success=round(r["ok"] / r["sent"], 3) if r["sent"] else None,
                                 score=round(self.score(r), 2)))
            rows.sort(key=lambda x: (-x["score"], x["id"]))
            return dict(phase=self.phase, progress=self.progress, discovered=len(self.repeaters),
                        running=bool(self.worker and self.worker.is_alive()),
                        total=round(sum(x["score"] for x in rows), 2), repeaters=rows,
                        console=[c for c in self.console if c["n"] > since], seq=self.seq,
                        plan=dict(discover_s=self.discover_s, rounds=self.rounds, interval_s=self.interval_s),
                        radio=getattr(self.radio, "settings", None))


def fmt_dur(s):
    s = int(round(s))
    return "%d min %d s" % (s // 60, s % 60) if s >= 60 and s % 60 else "%d min" % (s // 60) if s >= 60 else "%d s" % s


# ============================================================================
# Web UI
# ============================================================================

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Antenna test</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;padding:16px;background:#f6f7f9;color:#1d232b}
h1{font-size:20px;margin:0 0 12px}
.bar{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
button{font-size:16px;padding:8px 22px;border:0;border-radius:6px;background:#2563eb;color:#fff;cursor:pointer}
button:disabled{background:#9aa5b5;cursor:default}
.total{font-size:22px;font-weight:600}
.muted{color:#5b6573}
table{border-collapse:collapse;width:100%;background:#fff;margin-bottom:12px}
th,td{padding:6px 10px;border-bottom:1px solid #e3e6ea;text-align:right;white-space:nowrap}
th:first-child,td:first-child{text-align:left}
th{background:#eef1f4;font-weight:600}
#console{background:#11161d;color:#cfe3cf;font:13px/1.4 ui-monospace,Menlo,Consolas,monospace;height:320px;overflow:auto;
 padding:8px 10px;border-radius:6px;white-space:pre-wrap}
@media (prefers-color-scheme:dark){body{background:#12161c;color:#e3e7ec}table{background:#1a2029}th{background:#232b36}
 th,td{border-color:#2c3542}.muted{color:#97a2b0}}
</style></head><body>
<h1>Antenna test</h1>
<div class="bar"><button id="start" onclick="start()">Start</button>
<span class="total">Score: <span id="total">0.00</span></span>
<span id="status" class="muted"></span></div>
<div class="muted" id="plan" style="margin-bottom:10px"></div>
<table><thead><tr><th>Repeater</th><th>Avg TX SNR</th><th>Avg RX SNR</th><th>Success rate</th><th>Score</th></tr></thead>
<tbody id="rows"></tbody></table>
<div id="console"></div>
<script>
let seq=0;
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const db=v=>v==null?"\\u2014":v.toFixed(1)+" dB";
async function start(){$("start").disabled=true;const r=await fetch("api/start",{method:"POST"});
 if(!r.ok){const j=await r.json().catch(()=>({}));alert(j.error||"could not start")}poll()}
async function poll(){
 let s;try{s=await (await fetch("api/state?since="+seq)).json()}catch(e){$("status").textContent="(no connection)";return}
 $("start").disabled=s.running||s.phase==="error";
 $("total").textContent=s.total.toFixed(2);
 const ph={idle:"Ready",discovering:"Discovering repeaters",tracing:"Tracing",done:"Done",error:"Error"}[s.phase]||s.phase;
 $("status").textContent=ph+(s.progress?" \\u2014 "+s.progress:"")+(s.discovered?" \\u2014 "+s.discovered+" repeater(s) found":"");
 $("plan").textContent=(s.radio?s.radio+" \\u00b7 ":"")+"discovery "+Math.round(s.plan.discover_s/60*10)/10+" min, then "+
  s.plan.rounds+" trace rounds "+s.plan.interval_s+" s apart; each trace that comes back scores "+(1/s.plan.rounds).toFixed(2);
 $("rows").innerHTML=s.repeaters.map(r=>"<tr><td>"+esc(r.id)+(r.name?" "+esc(r.name):"")+"</td><td>"+db(r.tx_snr)+"</td><td>"+db(r.rx_snr)+
  "</td><td>"+Math.round(r.success*100)+"% ("+r.ok+"/"+r.sent+")</td><td>"+r.score.toFixed(2)+"</td></tr>").join("")||
  "<tr><td colspan=5 class=muted>No repeater has answered a trace yet</td></tr>";
 if(s.console.length){const c=$("console"),atEnd=c.scrollTop+c.clientHeight>=c.scrollHeight-4;
  for(const l of s.console){c.appendChild(document.createTextNode(l.t+"  "+l.text+"\\n"))}
  seq=s.seq;if(atEnd)c.scrollTop=c.scrollHeight}
}
poll();setInterval(poll,1000);
</script></body></html>
"""


def make_handler(test):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path, _, qs = self.path.partition("?")
            if path in ("/", "/index.html"):
                self._send(200, PAGE, "text/html; charset=utf-8")
            elif path == "/api/state":
                since = 0
                for part in qs.split("&"):
                    k, _, v = part.partition("=")
                    if k == "since" and v.isdigit():
                        since = int(v)
                self._send(200, json.dumps(test.state(since)))
            else:
                self._send(404, json.dumps(dict(error="not found")))

        def do_POST(self):
            if self.path.partition("?")[0] != "/api/start":
                self._send(404, json.dumps(dict(error="not found")))
            elif test.start():
                self._send(200, json.dumps(dict(ok=True)))
            else:
                self._send(409, json.dumps(dict(error="a test is already running (or the modem link failed)")))
    return Handler


def serve(test, host, port):
    srv = http.server.ThreadingHTTPServer((host, port), make_handler(test))
    srv.daemon_threads = True
    return srv


# ============================================================================
# main
# ============================================================================

def main(argv=None):
    ap = argparse.ArgumentParser(description="MeshCore antenna test (KISS modem + web UI)")
    ap.add_argument("--config", default=os.path.join(HERE, "..", "..", "meshroom", "meshroom.json"),
                    help="room config to take the serial port and radio settings from, if it exists (default: the room's)")
    ap.add_argument("--serial", help="modem serial port (default: from the config, else /dev/ttyACM0)")
    ap.add_argument("--baud", type=int)
    ap.add_argument("--freq", type=float, help="MHz")
    ap.add_argument("--bw", type=float, help="kHz")
    ap.add_argument("--sf", type=int)
    ap.add_argument("--cr", type=int)
    ap.add_argument("--tx-power", type=int, help="dBm (default: the config's, else the modem's own)")
    ap.add_argument("--host", default="127.0.0.1", help="web UI address (default this machine only: the UI has no "
                    "login and makes the radio transmit; 0.0.0.0 for every interface)")
    ap.add_argument("--port", type=int, default=8095, help="web UI port (default 8095)")
    ap.add_argument("--discover-minutes", type=float, default=DISCOVER_S / 60.0)
    ap.add_argument("--rounds", type=int, default=ROUNDS)
    ap.add_argument("--interval", type=float, default=ROUND_INTERVAL_S, help="seconds between trace rounds")
    ap.add_argument("--trace-timeout", type=float, default=TRACE_TIMEOUT_S, help="seconds to wait for a trace to come back")
    ap.add_argument("--results-dir", default=os.path.join(HERE, "results"), help="where each run's JSON results go")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")

    d = dict(mr.DEFAULT_CONFIG)
    if a.config and os.path.exists(a.config):
        d.update(mr.Config(a.config).data)
        log.info("using serial/radio settings from %s", os.path.abspath(a.config))
    pick = lambda v, k: v if v is not None else d[k]   # noqa: E731
    try:
        radio = KissRadio(pick(a.serial, "serial"), pick(a.baud, "baud"), pick(a.freq, "radio_freq_mhz"),
                          pick(a.bw, "radio_bw_khz"), pick(a.sf, "radio_sf"), pick(a.cr, "radio_cr"),
                          pick(a.tx_power, "radio_tx_power_dbm"), d["kiss_txdelay"], d["kiss_persistence"], d["kiss_slottime"])
    except Exception as e:
        sys.exit("modem: %s" % e)
    log.info("modem ready: %s", radio.settings)
    test = AntennaTest(radio, discover_s=a.discover_minutes * 60, rounds=a.rounds, interval_s=a.interval,
                       trace_timeout_s=a.trace_timeout, results_dir=a.results_dir)
    test.say("modem ready on %s (%s). Press Start." % (pick(a.serial, "serial"), radio.settings))
    srv = serve(test, a.host, a.port)
    log.info("web UI on http://%s:%d/", "localhost" if a.host in ("0.0.0.0", "") else a.host, a.port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        radio.modem.close()


if __name__ == "__main__":
    main()
