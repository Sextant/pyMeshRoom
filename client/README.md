# meshroom-kaas

A Python client for pyMeshRoom's **KaaS** API (KISS radio as an API service). It connects to a pyMeshRoom server over a
websocket and receives every packet that server's radio hears and sends. With a key that may send, it can also send packets.
The server never decrypts anything for you, so all MeshCore crypto runs here: your bot is a node on the mesh with
its own identity.

It needs Python 3.9+ and `cryptography`. The websocket client is built in.

```bash
pip install ./client            # from the pyMeshRoom checkout; or put client/ on PYTHONPATH
```

Get a key from the main admin. It is made on the dashboard's **KaaS** card, with Receive and/or Send. The protocol is
described in [docs/api.md](../docs/api.md).

## Raw packets

```python
from meshroom_kaas import KaasClient, Packet

client = KaasClient("ws://meshroom.local:8081/api/v1/kaas", "kaas_...")
hello = client.connect()                     # radio settings, the nodes on this radio, your key's permissions

for pkt in client.packets():                 # every packet, heard ("rx") or sent ("tx") by the radio
    print(pkt.dir, pkt.type_name, pkt.snr, pkt.encode().hex())
```

`client.on_packet(fn)` calls `fn(packet)` for each packet instead, on the reader thread, so keep it quick.

`client.send(packet_or_bytes)` waits for the outcome and returns a `SendResult`:

* `sent`: it went on the air.
* `local`: it was only for a node on the server's radio, which got it without it going on the air.
* `dropped`: refused. `result["reason"]` says why, and `result.get("retry_after")` says how long to wait when waiting
  would help.

Each key may send 3 packets in any 20 s. ACKs and path returns are exempt. API clients share the KaaS
share of airtime (by weight on the dashboard's Airtime card: 3% by default), more when the channel is quiet. A client may send
20 messages a second (bursts of 40).

## Route questions

The server has learned which repeaters hear each node, and good routes from its radio to each repeater:

```python
client.near("@[platinum]")   # or by name (plain or mention); same answer as by key
client.near(pub)          # [{"id": "44c3", "name": "Seaside", "share": 0.62}, ..., {"direct": True, "id": "9a1f", "name": "...", "share": 0.13}]
client.route(pub, "@[platinum]")   # {"from", "to", "routes": [{"hops": [...], "path": ..., "score": 0.62}, ...]}
client.paths(pub)         # direct paths from the server's radio to a node: [{"path_len", "path", "hops", "score", "source"}]
client.routes("44c3")     # [{"path_len": 66, "path": "55b244c3", "hops": [...], "names": [...], "confidence": 0.81}]
client.nodes(days=7)      # the directory: [{"pub", "type": "chat" | "repeater" | "room" | "sensor", "name", "lat", "lon", "last_heard", ...}]

best = client.routes(client.near(pub)[0]["id"])[0]
pkt = Packet.direct(ptype, payload, bytes.fromhex(best["path"]), best["path_len"])
```

## A chat node: adverts, DMs, channels and rooms

`Node` does what a MeshCore companion does:

* signs adverts
* learns contacts from the adverts it hears
* encrypts and decrypts DMs, and ACKs what it receives
* sends and learns routes (path returns)
* retries DMs until they're ACKed
* reads and writes channels
* logs in to rooms and ACKs their posts

```python
from meshroom_kaas import Identity, KaasClient, Node

client = KaasClient(URL, KEY)
hello = client.connect()
node = Node(client, Identity.load_or_create("bot.key"), "WeatherBot", lat=36.6, lon=-121.9)

node.advert(flood=True)                      # announce it to the whole mesh (flood=False: direct neighbours only)

@node.on_dm
def on_dm(contact, text, ts):
    node.send_dm(contact, "forecast: fog, then more fog")    # True once they ACK it

# channels: "Public", "#hashtag" (the key comes from the name), or a private channel with its 16-byte secret
weather = node.add_channel("#weather")
private = node.add_channel("Ops", secret="00112233445566778899aabbccddeeff")

@node.on_channel
def on_channel(channel, sender, text, ts):
    if channel is weather and text == "!now":
        node.send_channel(weather, "14C, overcast")

# rooms: log in (raises LoginFailed), then receive posts and post
room = node.join_room(hello["nodes"]["room"], password="room password")
room.on_post(lambda room, author, text, ts: print(text))
room.post("hello from a bot")

client.wait()                                # until the connection closes
```

Some notes:

* Callbacks run one at a time on the node's own thread, so they can block. `send_dm` and `post` wait for the ACK.
* `Identity.load_or_create(path)` keeps the bot's key in a file (mode 600). Keep it: a new key is a new node.
  `Identity(hex)` also takes a 64-byte private key exported from a MeshCore app.
* DMs need the other node's public key. `node.find("name")` looks up contacts learned from adverts, and
  `node.contact(pub)` adds one by key.
* Sends that aren't ACKs or path returns wait their turn under the per-key rate limit. Use one key per bot.
* Nothing reconnects by itself. When `client.wait()` returns, connect again and create a new `Node`.

## Example

[examples/echo_bot.py](examples/echo_bot.py) answers DMs, answers `!ping` on `#bots`, and prints the room's posts.
