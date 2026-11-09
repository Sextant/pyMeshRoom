"""WhereBot (bots/where_bot): parsing !where, fitting replies into a channel message, and a real lookup end to end."""
import os
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "bots" / "where_bot"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
try:
    import where_bot as wb
except ImportError:                                        # needs pyyaml
    wb = None
from test_kaas import WebTestCase, kc, mr

NEAR = [{"id": "44c3", "name": "Seaside", "share": 0.62}, {"id": "55b2", "name": None, "share": 0.25},
        {"direct": True, "id": "9a1f", "name": "pyMeshRoom Virtual Repeater", "share": 0.13}]
BUDGET = 160 - len("WhereBot: ")


@unittest.skipIf(wb is None, "needs pyyaml")
class ReplyTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(wb.parse("!where @[platinum]"), ("mention", "platinum"))
        self.assertEqual(wb.parse("!WHERE @[Jeff T 2]"), ("mention", "Jeff T 2"))
        self.assertEqual(wb.parse("!where A1B2C3D4E5F60718"), ("key", "a1b2c3d4e5f60718"))
        self.assertEqual(wb.parse("!where platinum"), ("name", "platinum"))
        self.assertEqual(wb.parse("!where")[0], "bad")
        self.assertIsNone(wb.parse("where is everyone"))
        self.assertIsNone(wb.parse("!whereabouts"))

    def test_answers(self):
        self.assertEqual(wb.answer("mention", "platinum", {"name": "platinum", "repeaters": NEAR}, BUDGET),
                         "platinum: recently active near:\n44c3 Seaside 62%\n55b2 25%\n9a1f pyMeshRoom Virtual Repeater 13%")
        self.assertEqual(wb.answer("key", "a1b2c3d4e5f60718", {"name": "platinum", "repeaters": NEAR[:1]}, BUDGET),
                         "a1b2c3d4 (aka platinum): recently active near:\n44c3 Seaside 62%")
        self.assertEqual(wb.answer("key", "a1b2c3d4e5f60718", {"name": None, "repeaters": NEAR[:1]}, BUDGET),
                         "a1b2c3d4: recently active near:\n44c3 Seaside 62%")
        self.assertEqual(wb.answer("key", "a1b2c3d4e5f60718", {"name": None, "repeaters": []}, BUDGET), wb.UNKNOWN_KEY)
        self.assertIn("hasn't been heard", wb.answer("mention", "platinum", {"name": "platinum", "repeaters": []}, BUDGET))

    def test_long_names_fit(self):
        rpts = [{"id": "%02x%02x" % (i, i), "name": "A Very Long Repeater Name Number %d" % i, "share": s}
                for i, s in enumerate((0.4, 0.3, 0.2, 0.1))]
        who = "Somebody With A Thirty Char Nm"
        text = wb.answer("mention", who, {"name": who, "repeaters": rpts}, BUDGET)
        self.assertLessEqual(len(text.encode()), BUDGET)
        self.assertEqual(text.split("\n")[0], who + ": recently active near:")
        lines = text.split("\n")[1:]
        self.assertEqual([x.split()[0] for x in lines], ["0000", "0101", "0202", "0303"], "every repeater stays")
        self.assertTrue(all("~" in x for x in lines), "names are cut")
        self.assertEqual(wb.answer("mention", who, {"name": who, "repeaters": rpts}, 95).split("\n")[1:],
                         ["0000 40%", "0101 30%", "0202 20%", "0303 10%"], "then names go, the ids stay")
        self.assertEqual(wb.answer("mention", who, {"name": who, "repeaters": rpts}, 75).split("\n")[1:],
                         ["0000 40%", "0101 30%"], "then the least heard repeaters go")


@unittest.skipIf(wb is None, "needs pyyaml")
class AdvertTests(unittest.TestCase):
    def test_flood_advert_when_due(self):
        sent = []

        class FakeNode:
            def advert(self, flood=False):
                sent.append(flood)
        node, day = FakeNode(), 12 * 3600
        last = wb.advertise(node, day, 0.0)
        self.assertEqual(sent, [True], "at startup")
        self.assertEqual(wb.advertise(node, day, last), last, "not again before 12 hours")
        self.assertGreater(wb.advertise(node, day, last - day), last - day)
        self.assertEqual(sent, [True, True])
        self.assertEqual(wb.advertise(node, 0, 0.0), 0.0, "advert_hours 0 never adverts")
        self.assertEqual(len(sent), 2)


@unittest.skipIf(wb is None, "needs pyyaml")
class SuggestTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(wb.parse_suggest("!suggest 5B98 to ec43"), ("5b98", "ec43"))
        for text in ("!suggest 5b98 ec43", "!suggest 5b9 to ec43", "!suggest @[a] to ec43", "!where 5b98"):
            self.assertIsNone(wb.parse_suggest(text))

    def test_answers(self):
        ends = {"from": {"repeater": "5b98", "name": "Seaside"}, "to": {"repeater": "ec43", "name": None}}
        routes = [{"hops": ["5b98", "ec43"], "score": 0.87}, {"hops": ["5b98", "beef", "ec43"], "score": 0.391}]
        self.assertEqual(wb.suggest_answer(dict(ends, routes=routes), BUDGET),
                         "Suggested routes: Seaside to ec43\n5b98,ec43 (.87)\n5b98,beef,ec43 (.39)")
        self.assertEqual(wb.suggest_answer(dict(ends, routes=[]), BUDGET), "No known route from Seaside to ec43 yet")
        many = [{"hops": ["5b98"] + ["%04x" % (i * 7 + j) for j in range(4)] + ["ec43"], "score": 0.5} for i in range(5)]
        text = wb.suggest_answer(dict(ends, routes=many), BUDGET)
        self.assertLessEqual(len(text.encode()), BUDGET)
        self.assertTrue(text.startswith("Suggested routes: Seaside to ec43\n"), text)
        self.assertLess(text.count("\n"), 5, "the weakest routes go")


@unittest.skipIf(wb is None, "needs pyyaml")
class WhereBotEndToEnd(WebTestCase):
    def test_where_on_a_hashtag_channel(self):
        room = self.h.room
        node = os.urandom(32)
        for _ in range(3):
            room.observe_near(node, bytes.fromhex("44c3"))
        room.learn_name(node, 10, "platinum")
        self.http("POST", "/api/login", {"password": "adminpw"})
        token = self.make_key()
        bot_c, user_c = kc.KaasClient(self.url, token), kc.KaasClient(self.url, token)
        self.h.run_client(bot_c.connect)
        self.h.run_client(user_c.connect)
        bot = kc.Node(bot_c, kc.Identity.generate(), "WhereBot")
        user = kc.Node(user_c, kc.Identity.generate(), "Jeff")
        bot_ch = bot.add_channel("#where")
        bot.on_channel(lambda ch, sender, text, ts: wb.handle(bot_c, bot, ch, sender, text))
        heard = []
        user.on_channel(lambda ch, sender, text, ts: heard.append((sender, text)))
        ch = user.add_channel("#where")
        room.observe_near(node, b"")
        here = room.id.pub_key[:2].hex()                    # no virtual repeater here: heard directly by the room
        for ask, want in (("!where @[Platinum]", "platinum: recently active near:\n44c3 75%%\n%s %s 25%%" % (here, room.cfg.name)),
                          ("!where " + node.hex(),
                           "%s (aka platinum): recently active near:\n44c3 75%%\n%s %s 25%%" % (node[:4].hex(), here, room.cfg.name)),
                          ("!where @[nobody]", wb.UNKNOWN_NAME),
                          ("!where " + os.urandom(8).hex(), wb.UNKNOWN_KEY)):
            heard.clear()
            self.h.run_client(lambda: user.send_channel(ch, ask))
            self.assertTrue(self.h.pump(lambda: heard, 15), ask)
            self.assertEqual(heard, [("WhereBot", want)])
        now = mr.now_s()
        room.edges[(bytes.fromhex("5b98"), bytes.fromhex("ec43"))] = [3.0, now, None]
        heard.clear()
        self.h.run_client(lambda: user.send_channel(ch, "!suggest 5b98 to ec43"))
        self.assertTrue(self.h.pump(lambda: heard, 15))
        self.assertEqual(heard, [("WhereBot", "Suggested routes: 5b98 to ec43\n5b98,ec43 (.83)")])
        self.assertTrue(bot_ch)
        bot_c.close()
        user_c.close()


@unittest.skipIf(wb is None, "needs pyyaml")
class WhereBotRoomTests(WebTestCase):
    def test_where_in_a_room(self):
        room = self.h.add_room()
        node = os.urandom(32)
        for _ in range(3):
            self.h.room.observe_near(node, bytes.fromhex("44c3"))           # (the map is the host's)
        self.h.room.learn_name(node, 10, "platinum")
        self.http("POST", "/api/login", {"password": "adminpw"})
        token = self.make_key()
        bot_c, user_c = kc.KaasClient(self.url, token), kc.KaasClient(self.url, token)
        self.h.run_client(bot_c.connect)
        self.h.run_client(user_c.connect)
        bot = kc.Node(bot_c, kc.Identity.generate(), "WhereBot")
        user = kc.Node(user_c, kc.Identity.generate(), "Jeff")
        twice = [{"password": "hello"}, {"key": room.id.pub_key.hex(), "password": "hello"},   # no key: skipped
                 {"key": room.id.pub_key.hex().upper(), "password": "hello"}]                # the same room, listed twice
        joined = self.h.run_client(lambda: wb.join_rooms(bot_c, bot, twice))
        self.assertEqual(len(joined), 1)
        self.assertEqual(joined[0].name, room.cfg.name, "named from hello")
        user_room = self.h.run_client(lambda: user.join_room(room.id.pub_key, "hello"))
        posts = []
        user_room.on_post(lambda r, author, text, ts: posts.append((bytes(author), text)))
        self.assertTrue(self.h.run_client(lambda: user_room.post("!where @[platinum]")))
        want = (bot.id.pub[:4], "platinum: recently active near:\n44c3 100%")
        self.assertTrue(self.h.pump(lambda: want in posts, 30), posts)
        self.h.pump(lambda: posts.count(want) > 1, 3)
        self.assertEqual(posts.count(want), 1)                     # answered once
        bot_c.close()
        user_c.close()


if __name__ == "__main__":
    unittest.main()
