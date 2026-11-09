#!/usr/bin/env python3
"""A bot that answers DMs and a hashtag channel, and posts what it hears in a room to stdout.

    KAAS_URL=ws://meshroom.local:8081/api/v1/kaas KAAS_KEY=kaas_... python3 echo_bot.py
"""
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from meshroom_kaas import Identity, KaasClient, LoginFailed, Node

logging.basicConfig(level=logging.INFO)
client = KaasClient(os.environ["KAAS_URL"], os.environ["KAAS_KEY"])
hello = client.connect()
print("connected; the room on this radio is", hello["nodes"]["room"])

node = Node(client, Identity.load_or_create("echo_bot.key"), "EchoBot")
node.advert(flood=True)
bots = node.add_channel("#bots")


@node.on_dm
def dm(contact, text, ts):
    print("DM from %s: %s" % (contact.name or contact.pub[:4].hex(), text))
    node.send_dm(contact, "echo: " + text)


@node.on_channel
def channel(ch, sender, text, ts):
    if ch is bots and text.lower().startswith("!ping"):
        node.send_channel(bots, "pong, %s" % sender)


try:
    room = node.join_room(hello["nodes"]["room"], os.environ.get("ROOM_PASSWORD", ""))
    room.on_post(lambda r, author, text, ts: print("room post:", text))
except LoginFailed as e:
    print("couldn't join the room:", e)

print("closed:", client.wait())
