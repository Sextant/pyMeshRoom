#!/usr/bin/env python3
"""WhereBot: answers "!where @[name]" or "!where <public key>" on hashtag channels with the repeaters that usually
hear that node, from the room's KaaS API.

    pip install cryptography pyyaml
    python3 where_bot.py [where_bot.yaml]       # default: where_bot.yaml in the current directory, else next to this file
"""
import logging
import os
import re
import sys
import threading
import time

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "client"))
from meshroom_kaas import Identity, KaasClient, Node, RequestError  # noqa: E402

log = logging.getLogger("where_bot")

MAX_TEXT_LEN = 160          # a channel message, "BotName: " included
MAX_ROOM_POST_LEN = 151     # a room post (rooms keep 9 bytes of a message for the author and timestamp)
NAME_CUTS = (None, 20, 16, 12, 8, 0)   # if a reply is too long, repeater names are cut to these lengths in turn
MIN_SHARE = 0.05            # repeaters heard less than this are left out
KEY_SHOWN = 8               # hex characters of a public key in replies

UNKNOWN_KEY = "I am not familiar with that public key"
UNKNOWN_NAME = "I am not familiar with that name. You can try lookup by public key"
SHORT_KEY = "Give at least the first 16 hex characters of the public key"
USAGE = "Usage: !where @[name] or !where <public key>"


def parse(text):
    """The node asked about in "!where ...": ("mention", name), ("name", plain text), ("key", hex), ("bad", reply),
    or None if the text isn't a !where."""
    m = re.match(r"\s*!where\b\s*(.*)$", text, re.I | re.S)
    if not m:
        return None
    arg = m.group(1).strip()
    mention = re.fullmatch(r"@\[(.+)\]", arg, re.S)
    if mention:
        return "mention", mention.group(1).strip()
    if re.fullmatch(r"[0-9a-fA-F]{16,64}", arg) and len(arg) % 2 == 0:
        return "key", arg.lower()
    return ("name", arg) if arg else ("bad", USAGE)


def parse_suggest(text):
    """("5b98", "ec43") from "!suggest 5b98 to ec43" (two repeaters' 2-byte ids), else None."""
    m = re.fullmatch(r"\s*!suggest\s+([0-9a-fA-F]{4})\s+to\s+([0-9a-fA-F]{4})\s*", text, re.I)
    return (m.group(1).lower(), m.group(2).lower()) if m else None


def suggest_answer(result, budget):
    """The reply to a !suggest, at most budget bytes. result: KaasClient.route()'s answer."""
    ends = [(r.get("repeater") or r.get("node") or "?", r.get("name") or "") for r in (result["from"], result["to"])]

    def label(rid, name, cut):
        if cut is not None and len(name) > cut:
            name = name[:cut - 1].rstrip() + "~" if cut > 1 else ""
        return name or rid

    def head(cut):
        return "Suggested routes: %s to %s" % tuple(label(rid, name, cut) for rid, name in ends)
    lines = ["%s (%s)" % (",".join(rt["hops"]), ("%.2f" % rt["score"]).lstrip("0")) for rt in result["routes"]]
    if not lines:
        return fit("No known route from %s to %s yet" % tuple(label(rid, name, 20) for rid, name in ends), budget)
    for n in range(len(lines), 0, -1):      # names down to 12 characters first, then the weakest routes go
        for cut in (None, 20, 16, 12):
            text = "\n".join([head(cut)] + lines[:n])
            if len(text.encode()) <= budget:
                return text
    return fit("\n".join([head(0)] + lines[:1]), budget)


def fit(text, limit):
    """At most limit bytes of UTF-8."""
    b = text.encode()[:limit]
    return b.decode(errors="ignore")


def describe(rpt, cut=None):
    """ "44c3 Seaside 62%": the repeater's 2-byte id, its name (cut to cut characters; 0 leaves it out) and share."""
    rid = rpt.get("id") or "direct"         # (a server too old to name what hears a node directly)
    name = rpt.get("name") or ""
    if cut is not None and len(name) > cut:
        name = name[:cut - 1].rstrip() + "~" if cut > 1 else ""
    return " ".join(x for x in (rid, name, "%d%%" % round(rpt["share"] * 100)) if x)


def answer(kind, asked, result, budget):
    """The reply to a !where, at most budget bytes. result: KaasClient.lookup()'s answer."""
    if kind == "key":
        who = asked[:KEY_SHOWN]
        if result.get("name"):
            who += " (aka %s)" % result["name"]
    else:
        who = result.get("name") or asked
    rpts = [r for r in result["repeaters"] if r["share"] >= MIN_SHARE] or result["repeaters"][:1]
    if not rpts:
        if kind == "key" and not result.get("name"):
            return UNKNOWN_KEY
        return fit("%s hasn't been heard through a repeater lately" % who, budget)
    head = "%s: recently active near:" % who
    while True:
        for cut in NAME_CUTS:               # shorten the repeater names first, then leave out the least heard
            text = "\n".join([head] + [describe(r, cut) for r in rpts])
            if len(text.encode()) <= budget:
                return text
        if len(rpts) == 1:
            return fit(text, budget)
        rpts = rpts[:-1]                    # they come most heard first


def respond(client, text, budget):
    """The reply to a !where or !suggest, at most budget bytes, or None if the text is neither."""
    ends = parse_suggest(text)
    q = parse(text)
    if ends is not None:
        try:
            return suggest_answer(client.route(*ends, limit=5), budget)
        except RequestError as e:
            log.warning("route %s -> %s failed: %s", ends[0], ends[1], e)
            return "Sorry, I couldn't look that up just now"
    if q is None:
        return None
    kind, arg = q
    if kind == "bad":
        return arg
    try:
        return answer(kind, arg, client.lookup(arg), budget)
    except RequestError as e:
        if kind != "key" and "no node named" in str(e):
            return SHORT_KEY if kind == "name" and re.fullmatch(r"[0-9a-fA-F]+", arg) else UNKNOWN_NAME
        log.warning("lookup %r failed: %s", arg, e)
        return "Sorry, I couldn't look that up just now"


def handle(client, node, channel, sender, text):
    """A channel message: answered on the same channel ("BotName: " counts toward the message's length)."""
    if sender == node.name:
        return
    reply = respond(client, text, MAX_TEXT_LEN - len((node.name + ": ").encode()))
    if reply is not None:
        log.info("%s %s: %s -> %s", channel.name, sender, text, reply)
        node.send_channel(channel, reply)


def handle_room(client, node, room, author, text):
    """A room post: answered with a post in the same room. author: the first 4 bytes of the poster's key."""
    if bytes(author) == node.id.pub[:4]:
        return
    reply = respond(client, text, MAX_ROOM_POST_LEN)
    if reply is not None:
        log.info("room %s %s: %s -> %s", room.name or room.pub[:4].hex(), bytes(author).hex(), text, reply)
        if not room.post(reply):
            log.warning("room %s didn't ACK the reply", room.name or room.pub[:4].hex())


def room_name(client, key):
    """A room's name: from hello when it runs on the KaaS radio, else from the adverts the server has heard."""
    name = {k.lower(): v for k, v in (client.hello.get("names") or {}).items()}.get(key.lower())
    if name:
        return name
    try:
        return client.lookup(key).get("name") or ""
    except Exception:
        return ""


def join_rooms(client, node, rooms):
    """Log in to each room listed in the config (by its public key); its posts then go to handle_room."""
    joined, keys = [], set()
    for spec in rooms:
        key = str(spec.get("key") or "").strip().lower()
        if not key:
            log.warning("a room in the config has no key: skipped (only rooms listed by key are joined)")
            continue
        if key in keys:                     # (listed twice: one answer each post)
            log.warning("room %s is listed more than once in the config: joined once", key[:8])
            continue
        keys.add(key)
        try:
            room = node.join_room(key, str(spec.get("password", "")))
        except Exception as e:
            log.warning("couldn't join room %s: %s", key[:8], e)
            continue
        if not room.name:                   # (until its next advert: the server's name for it, if it has one)
            room.name = room_name(client, key)
        room.on_post(lambda r, author, text, ts: handle_room(client, node, r, author, text))
        joined.append(room)
        log.info("joined room %s (%s)", room.name or "?", key[:8])
    return joined


def advertise(node, every_s, last):
    """A flood advert if one is due (every_s after the last; 0 = never). Returns when the last one went."""
    if every_s <= 0 or time.time() - last < every_s:
        return last
    try:
        res = node.advert(flood=True)
        log.info("flood advert: %s", res.status if res is not None else "sent")
    except Exception as e:
        log.warning("flood advert failed: %s", e)
    return time.time()


def run(cfg):
    ident = Identity(cfg["private_key"])
    every_s = float(cfg.get("advert_hours", 12)) * 3600
    last_advert = 0.0                       # (kept across reconnects, so a reconnect doesn't advert again)
    while True:
        client = KaasClient(cfg["api_endpoint"], cfg["api_key"])
        try:
            client.connect()
        except Exception as e:
            log.warning("can't connect to %s: %s", cfg["api_endpoint"], e)
            time.sleep(30)
            continue
        node = Node(client, ident, cfg["name"])
        channels = [node.add_channel(c if c.startswith("#") else "#" + c) for c in cfg["channels"]]
        log.info("connected as %s (%s), listening on %s", cfg["name"], ident.pub[:4].hex(),
                 ", ".join(c.name for c in channels))
        node.on_channel(lambda ch, sender, text, ts: handle(client, node, ch, sender, text))
        if cfg.get("rooms"):
            threading.Thread(target=join_rooms, args=(client, node, cfg["rooms"]), daemon=True).start()
        while True:                         # a flood advert now, then every advert_hours, while connected
            last_advert = advertise(node, every_s, last_advert)
            wait = every_s - (time.time() - last_advert) if every_s > 0 else None
            if client.closed.wait(max(wait, 60) if wait is not None else None):
                break
        log.info("connection closed: %s", client.wait())
        time.sleep(10)


def load_config(path):
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    missing = [k for k in ("name", "private_key", "api_endpoint", "api_key") if not cfg.get(k)]
    if not cfg.get("channels") and not cfg.get("rooms"):
        missing.append("channels or rooms")
    if missing:
        raise SystemExit("%s: missing %s" % (path, ", ".join(missing)))
    if isinstance(cfg.get("channels"), str):
        cfg["channels"] = [cfg["channels"]]
    cfg["channels"] = cfg.get("channels") or []
    cfg["rooms"] = [r if isinstance(r, dict) else {"key": str(r)} for r in (cfg.get("rooms") or [])]
    return cfg


def default_config_path():
    """where_bot.yaml in the current directory if there is one, else the one next to this file."""
    if os.path.exists("where_bot.yaml"):
        return "where_bot.yaml"
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "where_bot.yaml")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run(load_config(sys.argv[1] if len(sys.argv) > 1 else default_config_path()))
