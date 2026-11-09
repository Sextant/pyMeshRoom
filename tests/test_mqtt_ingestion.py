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
from meshroom import ObserverFeed, PT_ACK, Packet, mqtt_changes, topic_regions


class IngestionTests(unittest.TestCase):
    def feed(self, queue_max=2):
        room = SimpleNamespace(
            cfg=SimpleNamespace(mqtt_advert_ingest=True, mqtt_activity=True, web_backlog_mqtt=False, web_backlog_days=0,
                                mqtt_topo_ingest=True, mqtt_queue_max=queue_max),
            id=SimpleNamespace(pub_key=b"R" * 32), self_hash=0,
            channel_hashes=lambda: set())
        feed = ObserverFeed.__new__(ObserverFeed)
        feed.room, feed.lock = room, threading.Lock()
        feed.seen, feed.recent, feed.diag = collections.OrderedDict(), collections.deque(), collections.Counter()
        feed.subscriptions, feed.subscription_error = {}, ""
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

    def test_topic_regions(self):
        self.assertEqual(topic_regions(["meshcore/SJC/+/packets", "meshcore/sfo/#"]), {"SJC", "SFO"})
        self.assertIsNone(topic_regions(["meshcore/#"]))                       # every region: no filtering
        self.assertIsNone(topic_regions([]))
        self.assertIsNone(topic_regions(["meshcore/SJC/+/packets", "private/#"]))   # custom filters: left alone

    def test_other_regions_are_ignored_when_regions_are_set(self):
        feed = self.feed(queue_max=10)
        feed.room.cfg.mqtt_topics = ["meshcore/SJC/+/packets", "meshcore/MRY/+/packets"]
        msg = lambda b: json.dumps({"raw": Packet(PT_ACK, b).encode().hex()}).encode()
        feed._on_message("meshcore/SFO/obs1/packets", msg(b"AAAA"), False)      # another region: dropped
        feed._on_message("meshcore/SJC/obs2/packets", msg(b"BBBB"), False)
        feed._on_message("meshcore/mry/obs3/packets", msg(b"CCCC"), False)      # case doesn't matter
        self.assertEqual(feed.diag["other_region"], 1)
        self.assertEqual([feed.pop(), feed.pop(), feed.pop()],
                         [("obs", "ack", b"BBBB"), ("obs", "ack", b"CCCC"), None])

    def test_every_region_when_no_regions_are_set(self):
        feed = self.feed(queue_max=10)
        feed.room.cfg.mqtt_topics = ["meshcore/#"]
        feed._on_message("meshcore/SFO/obs1/packets", json.dumps({"raw": self.ack_raw().hex()}).encode(), False)
        self.assertEqual(feed.diag["other_region"], 0)
        self.assertEqual(feed.depth(), 1)

    def test_retained_packet_is_not_ingested(self):
        feed = self.feed()
        feed._on_message("meshcore/SJC/a/packets", json.dumps({"raw": self.ack_raw().hex()}).encode(), True)
        self.assertEqual(feed.depth(), 0)

    def test_subscription_ack_distinguishes_connected_from_authorized(self):
        feed = self.feed()
        topics = {7: "meshcore/#", 8: "private/#"}
        feed.subscriptions = {topic: {"state": "pending", "codes": []} for topic in topics.values()}
        feed.record_suback(topics, 7, [0])
        feed.record_suback(topics, 8, [0x80])
        state = feed.subscription_state()
        self.assertEqual(state["meshcore/#"]["state"], "granted")
        self.assertEqual(state["private/#"]["state"], "denied")
        self.assertIn("private/#", feed.subscription_error)

    def test_subscriber_credentials_require_both_values(self):
        changes = mqtt_changes({"username": "viewer", "password": "secret"})
        self.assertEqual(changes["mqtt_username"], "viewer")
        self.assertEqual(changes["mqtt_password"], "secret")
        with self.assertRaises(ValueError):
            mqtt_changes({"username": "viewer"})

    def test_broker_and_packet_filter_are_configurable(self):
        changes = mqtt_changes({"host": "mqtt.example.org", "port": 8883, "transport": "websockets",
                                "ws_path": "/mqtt", "tls": True, "tls_verify": True,
                                "topics": "meshcore/SJC/+/packets, meshcore/SFO/+/packets"})
        self.assertEqual(changes["mqtt_topics"], ["meshcore/SJC/+/packets", "meshcore/SFO/+/packets"])
        self.assertEqual(changes["mqtt_port"], 8883)
        with self.assertRaises(ValueError):
            mqtt_changes({"topics": "meshcore/#/packets"})

