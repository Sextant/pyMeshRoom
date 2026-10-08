import collections
import json
import pathlib
import queue
import sys
import threading
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "meshroom"))
from meshroom import ObserverFeed, PT_ACK, Packet


class IngestionTests(unittest.TestCase):
    def feed(self, queue_max=2):
        room = SimpleNamespace(
            cfg=SimpleNamespace(mqtt_advert_ingest=True, mqtt_activity=True,
                                mqtt_topo_ingest=True, mqtt_queue_max=queue_max),
            id=SimpleNamespace(pub_key=b"R" * 32), self_hash=0,
            channel_hashes=lambda: set())
        feed = ObserverFeed.__new__(ObserverFeed)
        feed.room, feed.lock = room, threading.Lock()
        feed.seen, feed.recent = collections.OrderedDict(), collections.deque()
        feed.ingress, feed.dropped, feed.bad = queue.Queue(queue_max), 0, 0
        return feed

    @staticmethod
    def ack_raw():
        return Packet(PT_ACK, b"ABCD").encode()

    def test_self_origin_is_not_ingested(self):
        feed = self.feed()
        feed._on_message("meshcore/SJC/test/packets", json.dumps({
            "raw": self.ack_raw().hex(), "origin_id": (b"R" * 32).hex()}).encode(), False)
        self.assertEqual(feed.depth(), 0)

    def test_ingress_queue_is_fifo_and_drops_newest(self):
        feed = self.feed(queue_max=1)
        one = self.ack_raw()
        two = Packet(PT_ACK, b"EFGH").encode()
        feed._on_message("meshcore/SJC/a/packets", json.dumps({"raw": one.hex()}).encode(), False)
        feed._on_message("meshcore/SJC/b/packets", json.dumps({"raw": two.hex()}).encode(), False)
        self.assertEqual(feed.pop(), ("obs", "ack", b"ABCD"))
        self.assertEqual(feed.dropped, 1)

    def test_retained_packet_is_not_ingested(self):
        feed = self.feed()
        feed._on_message("meshcore/SJC/a/packets", json.dumps({"raw": self.ack_raw().hex()}).encode(), True)
        self.assertEqual(feed.depth(), 0)

