"""Optional MQTT observer bridge for MeshRoom.

The observer receives copies of KISS RX packets from MeshRoom.  It never opens
or owns the serial port, so observer/network failures cannot block radio I/O.

Broker support and publishing are implemented separately from meshroom.py.
"""

import logging
import queue
import threading
import time

log = logging.getLogger("meshroom.observer")


class ObserverBridge:
    """Non-blocking handoff between MeshRoom RX and MQTT observer workers."""

    def __init__(self, cfg, identity):
        self.cfg = cfg
        self.identity = identity
        self.public_key = identity.pub_key.hex().upper()
        self.iata = str(getattr(cfg, "observer_iata", "SJC")).upper()
        self.q = queue.Queue(maxsize=max(10, int(getattr(cfg, "observer_queue_max", 1000))))
        self.dropped = 0
        self.started = time.time()
        self.running = True
        self.thread = threading.Thread(
            target=self._run, name="mqtt-observer", daemon=True
        )
        self.thread.start()

    def submit_rx(self, raw, snr, rssi):
        """Queue an RX observation without ever waiting on network I/O."""
        item = (bytes(raw), float(snr), int(rssi), time.time())
        try:
            self.q.put_nowait(item)
        except queue.Full:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 100 == 0:
                log.warning("observer queue full; dropped %d packet(s)", self.dropped)

    def close(self):
        self.running = False
        try:
            self.q.put_nowait(None)
        except queue.Full:
            pass
        self.thread.join(timeout=5)

    def _run(self):
        """MQTT worker. Broker implementation is added in the next commit."""
        while self.running:
            try:
                item = self.q.get(timeout=1.0)
            except queue.Empty:
                continue
            if item is None:
                break
