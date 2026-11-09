"""A pyMeshRoom room on a fake radio, its dashboard on PORT (admin password "adminpw", web logins on), a KaaS key
printed, and the main loop pumped forever.
Everything the radio transmits is printed as "TX <hex>". Lines appended to WORK/rx.txt:
    RX <hex>       the radio hears this packet
    SAY <text>     the room posts this (to its members)
    BOT_ADVERT     EchoBot (a meshroom_kaas Node on its own KaaS key, answering every DM) adverts
    BOT_DM <pub hex> <text>   EchoBot sends a DM (to a contact it has heard advert)
    MEMBER_POST <pub hex> <text>   a post to the room by that member, as if from their radio (a companion app)

    python3 devserver.py PYMESHROOM_CHECKOUT PORT WORK_DIR"""
import os, sys, threading, time
REPO = sys.argv[1]
sys.path.insert(0, os.path.join(REPO, "meshroom")); sys.path.insert(0, os.path.join(REPO, "tests"))
sys.path.insert(0, os.path.join(REPO, "client"))
import meshroom_kaas as kc
import meshroom as mr
from test_virtual_companion import Harness
port, work = int(sys.argv[2]), sys.argv[3]
h = Harness(web_password="adminpw", room_password="hello", kaas_send_window_s=2, push_quiet_ms=0)
h.cfg.set("web_port", port); h.cfg.set("web_bind", "127.0.0.1"); h.cfg.set("web_login", True)
h.cfg.set("web_giphy_key", "e2etestkey")                  # (the test answers api.giphy.com itself)
room = h.add_room("Pi Room")                              # the room on this radio (the server itself is the host)
web = mr.WebUI(h.room, h.events)
token, entry = h.room.kaas.new_key(dict(receive=True, send=True, description="dev", expires=None))
h.events.put(("kaas_key_add", entry))
h.pump(lambda: h.room.kaas.find(token) is not None, 5)
print("TOKEN", token, flush=True)
bot_token, bot_entry = h.room.kaas.new_key(dict(receive=True, send=True, description="EchoBot", expires=None))
h.events.put(("kaas_key_add", bot_entry))
h.pump(lambda: h.room.kaas.find(bot_token) is not None, 5)
bot = {}


def run_bot():
    client = kc.KaasClient("ws://127.0.0.1:%d/api/v1/kaas" % port, bot_token)
    client.connect()
    node = kc.Node(client, kc.Identity.generate(), "EchoBot")
    node.on_dm(lambda contact, text, ts: node.send_dm(contact, "echo: " + text))
    bot["node"] = node
    print("BOT", node.id.pub.hex(), flush=True)
    client.wait()


threading.Thread(target=run_bot, daemon=True).start()
def reader():
    rx = os.path.join(work, "rx.txt")
    open(rx, "w").close()
    done = 0
    while True:
        lines = open(rx).read().splitlines()
        for line in lines[done:]:
            if line.startswith("RX "):
                h.events.put(("rxraw", bytes.fromhex(line[3:].strip())))
            elif line.startswith("SAY "):
                h.events.put(("t_say", room.key, line[4:]))
            elif line.startswith("BOT_DM ") and "node" in bot:
                _, pub, text = line.split(" ", 2)
                threading.Thread(target=lambda: bot["node"].send_dm(bot["node"].contact(pub), text), daemon=True).start()
            elif line.startswith("MEMBER_POST "):
                _, pub, text = line.split(" ", 2)
                main_jobs.append(lambda pub=pub, text=text: room.store_post(bytes.fromhex(pub), text))
            elif line.strip() == "BOT_ADVERT" and "node" in bot:
                threading.Thread(target=lambda: bot["node"].advert(flood=True), daemon=True).start()
        done = len(lines)
        time.sleep(0.1)
main_jobs = []
threading.Thread(target=reader, daemon=True).start()
seen = 0
while True:
    h.pump(lambda: False, 0.2)
    while main_jobs:
        main_jobs.pop(0)()                                  # (the room is the main loop's)
    sent = getattr(h.modem, "sent", None)
    if sent is not None:
        while seen < len(sent):
            print("TX", bytes(sent[seen]).hex(), flush=True)
            seen += 1
