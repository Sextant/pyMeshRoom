# KaaS: the radio as an API

KaaS ("KISS radio as an API service") lets bots and other programs use pyMeshRoom's radio over a websocket. A client
with an API key can receive every packet the radio hears and sends, and can send raw MeshCore packets of its own.

The server never decrypts anything for a client. Clients do all MeshCore crypto themselves: they are nodes on the
mesh with their own identities. The [Python client](../client/README.md) does that work for you: adverts, contacts,
DMs, channels and joining rooms. The machine-readable description is [asyncapi.yaml](asyncapi.yaml).

## API keys

The main admin makes keys on the dashboard's **KaaS** card:

* **Receive**: stream every packet.
* **Send**: send packets.
* A description, and an optional expiry date. The key stops working at the end of that day, in the browser's time
  zone.

**Save** shows the key once. pyMeshRoom keeps only a SHA-256 hash of it, in `kaas_keys` in the config. A lost key
can't be recovered: revoke it and make a new one.

The list on the card shows each key's description, access, expiry, last use and current connections. The key itself
is never shown again. It also shows each key's counts, for the last 24 hours and in total:

* **Received**: packets streamed to it.
* **Sent**: packets it sent that were accepted.
* **Errors**: refused sends and bad requests.

The counts are kept in `kaas_stats.json` in `data_dir`, saved every 5 minutes and at shutdown. Revoking a key deletes
its counts. **Revoke** deletes the key and disconnects its clients at once. When a key expires, its clients are
disconnected within a second.

Admin endpoints use the dashboard's admin login cookie:

| Method | Path | Body | Answer |
|---|---|---|---|
| GET | `/api/v1/kaas/keys` | | `{"keys": [...], "path", "send_burst", "send_window_s", "airtime_pct", "stats"}` |
| POST | `/api/v1/kaas/keys` | `{"receive": bool, "send": bool, "description": str, "expires": epoch or null}` | `{"ok": true, "id", "token"}` |
| POST | `/api/v1/kaas/keys/<id>/revoke` | | `{"ok": true}` |

## Connecting

```
GET /api/v1/kaas HTTP/1.1
Upgrade: websocket
Authorization: Bearer kaas_...
```

Connect to `ws://<server>:<web_port>/api/v1/kaas`, on the dashboard's port. The dashboard serves plain HTTP. If
clients connect over the internet, put pyMeshRoom behind an HTTPS reverse proxy that passes websocket upgrades and
use `wss://`. Otherwise the key travels unencrypted.

A reverse proxy has to pass the upgrade on. With nginx:

```
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_read_timeout 1h;
```

Caddy and Traefik pass websockets on by themselves. Each refused upgrade is logged, with the reason (for instance
`websocket from 10.0.0.15 refused (426): no websocket upgrade in the request ...`, when a proxy drops the headers).

### Logging in with a node's private key (MeshCore Web)

Browsers can't put an `Authorization` header on a websocket, and API keys are for bots, so a browser logs in by
signing with its MeshCore node's private key. The key never leaves their
browser; only a signature does. The admin turns this on with **Allow web logins** on the dashboard's **Web users**
card (`web_login`, off by default).

1. `POST /api/v1/web/challenge` returns `{"challenge": "wc_...", "expires_in": 60, "label": "meshcore-web login v1"}`.
2. Sign these lines, joined with `\n`, using Ed25519 and the node's key:
   `meshcore-web login v1`, the server's host as the browser reached it (e.g. `mesh.example.com` or
   `10.0.0.5:8081`), the challenge, and the public key in lowercase hex.
3. `POST /api/v1/web/login` with
   `{"pub": "<64 hex>", "signature": "<128 hex>", "challenge": "wc_...", "host": "...", "name": "pl@web"}`.
   The answer is `{"ticket": "kt_...", "expires_in": 30, "send": true, "state": "allowed"}`, or
   `"send": false, "state": "pending"`.
4. Connect to `wss://<server>/api/v1/kaas?ticket=kt_...`, with no header. A ticket opens one connection, within 30
   seconds; log in again to reconnect.

A login answers 503 with `"full": true` while all `web_max_clients` web sessions are in use.

A browser isn't told why a websocket didn't open, so it can ask: `POST /api/v1/web/ticket` with `{"ticket": "kt_..."}`
answers `{"outcome": ...}`, kept for 5 minutes:

| outcome | |
|---|---|
| `waiting`, `unused` | The websocket never reached the server: a proxy, an extension or a firewall stopped it. |
| `no_upgrade` | It arrived without its `Upgrade` or `Connection` header: a proxy dropped them. |
| `bad_version` | Not a version 13 websocket. |
| `busy`, `full` | Too many requests, or all web sessions in use. |
| `expired` | It came after the ticket's 30 seconds. |
| `refused` | Web logins were turned off, or the key was banned, in between. |
| `connected` | It opened. |
| `unknown` | No such ticket (or the server restarted). |

A challenge works once and lasts 60 s; it's signed by the server rather than stored, so asking for any number of them
uses nothing up. A login makes a one-time ticket (at most 4 waiting per key). The host must be one of this server's
own names: its address as the connection reached it
(`ip:port`), or a name listed in `web_hosts`: a domain, or the name a reverse proxy serves it under. The request's
`Host` or `X-Forwarded-Host` header alone never counts, so another server can't pass its visitors' logins on to this
one. A login signed for any other name answers 401, and the name is listed on the **Web users** card (the last ten),
with **Allow** to add it to `web_hosts`. Behind a proxy, add the public name there (or press Allow after the first
login). The label means a login signature can never also be a valid MeshCore packet
signature.

Anyone may log in and receive. A key may **send** once this radio has heard it advertise, or once the admin presses
**Allow send** for it. An advert sent through this API doesn't count: it has to be heard on the air, by this radio
(an MQTT observer's report doesn't count either). Until then the session is **pending**: sends are refused, and so
are rooms on this server (reading too), and `{"type": "access", "send": true, "state": "allowed"}` arrives when that
changes (it also arrives with `false` if the admin takes it back). A pending session's hello carries the admin's
`"pending_message"` for its user (`web_unknown_key_message`, set on the Web users card).

A web session may only send what a chat client needs, and only as itself:

* adverts for its own key, and room logins (`anon_req`) from its own key;
* DMs, requests, responses and path returns whose sender hash is its own key's first byte;
* channel messages and ACKs, which carry no sender identity in MeshCore;
* nothing else: no traces, control or raw packets.

It shares the API's rate limit (per key, so per web user) and the web users' share of airtime. `hello` says it's a web login:
`"key": {"id": "w:<pub>", "receive": true, "send": false, "expires": null, "web": true, "pub": "<64 hex>",
"state": "pending"}`.

On the **Web users** card, the admin sees each key's name, public key, access, last activity, connections and packet
counts, and can:

* **Allow send**: let a key send without being heard;
* **Kick**: disconnect it, though it can log in again;
* **Ban**: disconnect it and refuse it from then on; a key can also be banned before it ever logs in. A popup asks
  whether to ban the **public key**, the **IP address** it last logged in from, or both. An address ban refuses every
  web login and connection from that address; the card warns when other users share it (behind a proxy that
  doesn't pass on `X-Forwarded-For`, everyone does).

A banned person can make a new key, but a new key can't send until it's heard on the air or allowed.

`POST /api/v1/web/users/<pub>/ban` takes `{"key": true, "ip": false}` (the defaults) to choose what is banned;
`POST /api/v1/web/ips/<ip>/ban` and `.../unban` ban or unban an address directly. Each user's last address shows
under their key on the card, and banned addresses are listed with the banned keys.

### Catching up (web logins only)

The server keeps a **backlog** of channel messages and DMs: what this radio hears and sends, and with
`web_backlog_mqtt`, what MQTT observers report.

* **Retention:** `web_backlog_days` days, 30 by default, with no maximum; older ones are pruned. 0 keeps none.
* **One copy each:** a packet is kept once, by its packet hash, however many repeaters or observers passed it on.
  Each is numbered in order.
* **Live packets** carry their number as `seq`. With `web_backlog_mqtt`, web users also get observer-reported
  packets as they come, with `"dir": "mqtt"`.

A web session catches up with:

```json
{"type": "replay", "id": "r1", "since": 48213, "channels": [17, 202], "me": 3}
```

* `since` is the last `seq` it has, or null on a first visit: nothing then, it starts from now.
* `channels` are the hash bytes of its channels, and `me` is its key's first byte.
* The server sends the kept packets after `since` that could be for it as `replay_batch` messages, each
  `{"packets": [{"seq", "raw", "ts", "dir", "snr"}]}`.
* Then it sends `{"type": "replay_done", "id": "r1", "last": 48990, "count": 12}`.
* An API key asking gets an error: bots don't answer old messages.

The client treats replayed and MQTT packets as read only, sending no ACKs or path returns for them.

On the Web users card, the admin sets the days and MQTT. Each user's **Missed** column counts the packets kept since
they were last connected. Its **Actions** menu adds:

* **Purge backlog:** count them as caught up to now. Nothing before that is replayed to them.
* **Delete:** disconnect and forget them, with their counts and "allow send". It isn't a ban.

The admin can also set a **page password** on the card (`web_page_password`, stored hashed). Then:

* `/meshcore-web/` shows a password form first. The right password gives that browser a page session (an `HttpOnly`
  cookie, 30 days). It's signed, not stored, so it outlives a restart.
* `/api/v1/web/challenge` and `/api/v1/web/login` need either that cookie or `"page_password"` in their JSON body.
  Without them they answer 401 with `{"error": ..., "page_password": true}`, after a one-second delay.
* A new password, or removing it, ends every page session.
* API keys aren't affected.

Failed handshakes return:

* 401: missing, unknown, revoked or expired key or ticket, after a one-second delay.
* 429: too many failed attempts from this address (20 wrong passwords, keys or tickets in 10 minutes); it lifts as
  they age. Behind a proxy on a private address, the address counted is the one in `X-Forwarded-For`. The dashboard's
  POSTs answer the same way.
* 429 also: more than 30 websockets a minute from one address, or a fifth web session open at once from one
  address (`too_many` in `/api/v1/web/ticket`). These per-address limits, and 10 web login challenges a minute
  (`/api/v1/web/challenge` answers 429 with `retry_after`), apply to visitors' addresses, not to the LAN
  (10/8, 172.16/12, 192.168/16, fc00::/7, loopback) nor to a proxy that doesn't pass on `X-Forwarded-For`.
* 426: not a websocket upgrade (a proxy may have dropped the `Upgrade` and `Connection` headers).
* 503: too many clients. The limit is 16 connections across all API keys, and `web_max_clients` (32) web sessions on
  top of that.

Every message in both directions is a JSON text frame. The server pings every 30 s. A connection that sends nothing
back for 90 s, not even a pong, is closed.

Close codes from the server:

* 4001: the key was revoked.
* 4002: the key expired.
* 4003: a web login's key was banned.
* 4004: web logins were turned off.
* 4005: the admin disconnected this web session (it may log in again).
* 1001: the server is shutting down.
* 1002: a protocol error (the reason says which).

## Server to client

**hello**, the first message:

```json
{"type": "hello", "api": 1, "server": "meshroom-py 4.9",
 "key": {"id": "3f2a9c1b", "receive": true, "send": true, "expires": null},
 "send_burst": 3, "send_window_s": 20, "airtime_pct": 10,
 "radio": {"freq_hz": 910525000, "bw_hz": 62500, "sf": 7, "cr": 5},
 "nodes": {"room": null, "tenants": ["<64 hex>"], "repeater": null, "companion": null},
 "names": {"<64 hex>": "My Room"}}
```

A web session's hello also has `"motd"`: the admin's message of the day (`web_motd`, when `web_motd_enabled`; set on the Web users card), or null.

A web session's hello also has `"giphy_key"`: the admin's Giphy API key for the GIF picker (`web_giphy_key`, set on
the Web users card), or null. Giphy API keys are meant for browsers; an API key's hello always has null.

`nodes` lists the public keys of the nodes running on this radio, and `names` gives each room's name by public key.
The server itself is only the host, with no room of its own, so `nodes.room` is always null and the rooms are in
`nodes.tenants`.

**packet**: one for every packet the radio hears (`"dir": "rx"`) or sends (`"dir": "tx"`). Keys that may receive only.

```json
{"type": "packet", "dir": "rx", "ts": 1760313600.123, "raw": "1500a1b2...",
 "ptype": "txt", "route": "flood", "hops": 2, "hash": "9f3c...", "snr": 7.25, "rssi": -96}
```

* `raw` is the whole packet in hex, exactly as on the air.
* `ptype`, `route`, `hops` and `hash` (the 8-byte id MeshCore de-duplicates on) save parsing. They are missing if the
  packet doesn't parse.
* `snr` and `rssi` come with rx packets only.

Floods are heard many times, once per repeater, so de-duplicate on `hash`.

The tx packets matter: the radio never hears its own transmissions. Replies from a room on this radio to your bot
arrive as tx packets.

**send_result**: the fate of each packet you send, matched by your `id`.

* `queued`: accepted, waiting for the air.
* `sent`: transmitted.
* `local`: the packet was only for a node on this radio (a room here, for example). That node got it directly, and
  it never went on the air.
* `dropped`: refused, with a `reason`. When waiting would help, `retry_after` says how many seconds. A packet can
  also be dropped after `queued`, if the airtime limits held it over 2 minutes (a busy channel).

```json
{"type": "send_result", "id": 7, "status": "dropped",
 "reason": "rate limit: 3 packets per 20 s per key (ACKs and paths excepted)", "retry_after": 6.2}
```

Other messages:

* `{"type": "dropped", "count": n}`: you read too slowly. Up to 512 messages wait for each client. Past that, the
  oldest are discarded and this tells you how many.
* `{"type": "pong", "id": ...}`: the answer to your ping.
* `{"type": "error", "error": "..."}`: a message the server couldn't use.
* `{"type": "access", "send": bool, "state": "allowed" | "pending"}`: a web login's permission to send changed.

## Client to server

**send**: needs a key that may send. `id` is optional, any string or number up to 64 characters, and is echoed in the results.

```json
{"type": "send", "id": 7, "raw": "1100a1b2..."}
```

**ping**: `{"type": "ping", "id": 1}`

### Rooms on this server (web logins only)

A web login reads and posts to this server's rooms through the server rather than over the
air. A room keeps one sync point and one route per key, and those belong to the member's radio: the same key on a
companion app would otherwise lose posts to the web page, or get them sent down the page's route.

**room**: `{"type": "room", "id": 1, "room": "<64 hex>", "since": 0, "password": ""}` answers `room_result`, with the
posts this key may see newer than `since` (its room's latest `catchup_max` when 0, at most 500), its own and
private ones included:

```json
{"type": "room_result", "id": 1, "room": "<64 hex>", "name": "Pi Room", "admin": false, "perms": 2, "can_post": true,
 "posts": [{"ts": 1761700000, "author": "<64 hex>", "name": "Alice", "text": "hi", "private": false}]}
```

From then on, each new post it may see comes as `{"type": "room_post", "room": ..., ...}` with the same fields, until
the connection closes; ask again after reconnecting. A member is known by their key, so no password is needed. A key
that isn't a member joins with the password, checked as a radio login is (admin password, room password, or a guest
when the room allows read-only), and an error has `"refused": true` when it's wrong. The member's over-the-air state
(sync point, route, last activity) is never changed, and a member who only ever joined here gets nothing pushed over
the air. A room not on this server answers an error with `"local": false`: log in over the air instead.

**room_post**: `{"type": "room_post", "id": 2, "room": "<64 hex>", "text": "hello"}` stores a post as this key's
(read-write or admin members; a key that may send). It answers `{"type": "room_post_result", "id": 2, "status":
"posted", "ts": ...}`, or `"status": "duplicate"` for the same text again within the room's dedupe window. The
room pushes it over the air to its other members as usual. (Not to this key's own radio: a room never sends anyone
their own posts.)

### Route questions

Any key may ask these. They come from what the room has learned of the mesh. The answers are routes from this
radio, which is where your packets go out. The radio's main loop answers them, so each key has a budget across its
connections: 4 `nodes` a minute, and 30 of the others (`near`, `routes`, `route`) a minute; past it, an error says
so. A web session's `nodes` reaches back at most 31 days. Route answers use a picture of the mesh's links up to 30 s
old.

**near**: which repeaters hear a node, meaning its first hop into the mesh, and each one's share. It is learned from
the floods the radio hears from that node, faded over hours. At most 4 repeaters are kept per node. `node` is its
public key in hex; the first 8 bytes are enough. Instead of `node` you can send `name`: the name the node
advertises, plain or as a mention like `@[platinum]`, ignoring case. If several nodes advertise that name, the one
with known repeaters wins, then the newest advert. An unheard name is an error. `limit` is 1 to 10, default 4.

```json
{"type": "near", "id": "q1", "node": "a1b2c3d4e5f60718"}
{"type": "near", "id": "q2", "name": "@[platinum]"}
{"type": "near_result", "id": "q1", "node": "a1b2c3d4e5f60718", "name": "platinum",
 "repeaters": [{"id": "44c3", "name": "Seaside", "share": 0.62}, {"id": "55b2", "name": null, "share": 0.25},
               {"direct": true, "id": "9a1f", "name": "pyMeshRoom Virtual Repeater", "share": 0.13}]}
```

`"direct": true` means this radio hears the node itself. Its `id` and `name` are then this radio's virtual repeater,
which is what relays for that node, or the room when the virtual repeater is off. An unknown node gets an empty list.

**routes**: the best known routes from this radio to a repeater, best first. They are learned from flood paths, and
scored by how often each was seen and whether the room's pushes over it were delivered. `repeater` is its public key
or id in hex; the first 2 bytes are enough. `limit` is 1 to 10, default 3.

```json
{"type": "routes", "id": "q2", "repeater": "44c3"}
{"type": "routes_result", "id": "q2", "repeater": "44c3", "name": "Seaside",
 "routes": [{"path_len": 66, "path": "55b244c3", "hops": ["55b2", "44c3"], "names": [null, "Seaside"],
             "confidence": 0.81}]}
```

The repeater is the last hop. `path_len` and `path` go straight into a direct packet's header and path. Together the
two answers give a route to a node you have no path for: send direct along the best route to the repeater that hears
it most. A first hop that is this radio's own virtual repeater is dropped when the packet is sent, as the room does.

**paths**: direct paths from this radio to a node, best first, as the room plans its own deliveries. `node` is the
node's full public key in hex; `limit` is 1 to 8, default 4. They come from routes the room has delivered on before
(when the node is a member here: `"source": "measured"`), from the repeaters that hear it (as in `near`) and this
radio's best route to each (`"map"`), from shortcuts that skip hops the radio doesn't need (`"shortcut"`), and
`"direct"` for a node this radio hears with no hops. Empty when the node hasn't flooded lately. `path_len` and `path`
go straight onto a direct packet.

```json
{"type": "paths", "id": 9, "node": "<64 hex>"}
{"type": "paths_result", "id": 9, "node": "<64 hex>", "name": "Platinum",
 "paths": [{"path_len": 66, "path": "55b244c3", "hops": ["55b2", "44c3"], "names": [null, "Seaside"],
            "score": 0.71, "source": "map"}]}
```

**route**: suggested routes between any two nodes, not just from this radio. `from` and `to` are each a node's public
key in hex (at least 8 bytes), its name or `@[name]`, or a repeater's 2-byte id. The room takes the repeaters near
each end (as in `near`) and finds the best chains between them through the repeater links it has seen: links in the
flood paths this radio heard, plus links the MQTT observers reported, faded over a day. `limit` is 1 to 5, default 3.

```json
{"type": "route", "id": "q3", "from": "a1b2c3d4e5f60718", "to": "@[platinum]"}
{"type": "route_result", "id": "q3", "from": {"node": "a1b2c3d4e5f60718", "name": "Jeff"},
 "to": {"node": "0f1e2d3c4b5a6978", "name": "platinum"},
 "routes": [{"path_len": 67, "path": "a1a1b2b2d4d4", "hops": ["a1a1", "b2b2", "d4d4"],
             "names": ["Hilltop", "Seaside", null], "score": 0.62},
            {"path_len": 67, "path": "a1a1c3c3d4d4", "hops": ["a1a1", "c3c3", "d4d4"],
             "names": ["Hilltop", "Ridge", null], "score": 0.19}]}
```

The path runs from the `from` end: its first hop is a repeater that hears the source, its last one a repeater the
destination hears. `score` (0 to 1) is how likely the ends use those repeaters times each link's confidence. A busy
link is seen hundreds of times, so a link counts by how it compares with its repeater's strongest link: the
strongest scores 1, one with a quarter of that traffic 0.5. A link seen only once counts half again. Weak links
(below 0 dB SNR, where known) count for less, down to half at -15 dB. A link seen only in the other direction counts
at half, and every hop costs 5%, so shorter routes win ties. Routes use 2-byte ids, at most 10 hops. This radio is a hop only while its
virtual repeater relays. A node with no recent location (it hasn't flood-adverted lately) is an error, and so is an
unknown name. An empty list means no chain of seen links joins the two ends.
**nodes**: everyone this server knows of, heard in the last `days` (default 7, at most 365), most recently heard first,
at most 2000. For contact lists and maps. It merges these sources:

* the node directory: adverts heard by this radio or by an MQTT observer;
* what the room kept before: the repeater map and neighbours, the members of the rooms, and the
  virtual companion's contacts;
* the name cache, which holds only the first 8 bytes of a key. Those come with `"partial": true`, a 16-hex-character
  `pub`, and no position. They can be shown and mentioned, but not sent a DM until their full key is known.

```json
{"type": "nodes", "id": "q4", "days": 7}
{"type": "nodes_result", "id": "q4", "nodes": [{"pub": "<64 hex>", "type": "chat", "name": "Alice", "lat": 36.6,
 "lon": -121.9, "last_heard": 1760313600, "rf": 1760313600, "obs": null}]}
```

`type` is `chat`, `repeater`, `room` or `sensor`. For directory entries, `rf` and `obs` say when this radio, or an
observer, last heard it; name and position come from its newest signed advert. Only the directory's `rf` counts as
"heard on the air" for web logins.

Bad input gets `{"type": "error", "id": ..., "error": ...}`. Questions share the 4-at-a-time limit with sends.

## Airtime

Everything the radio sends shares one **max transmit duty cycle**, `tx_duty_pct` (50% of the time). Each class of
traffic has a **weight**, any number; its **guaranteed share** is its weight divided by the total of the weights of
the classes that are on, times the max duty cycle. The virtual repeater and companion don't count while they're off.
A class spends its own share first and borrows what the others leave unused, up to the max, the way Linux's HTB
does: alone on the air a class may use the whole max, and when all are busy each still gets its share. Shares are
token buckets holding a minute's worth, so short bursts go out at once.

| Class | Setting | Default weight | What |
|---|---|---|---|
| Control | `tx_weight_control` | 10 | ACKs, replies, and path returns. These may go up to 10 s of airtime over the max before they wait, since a late ACK is useless. |
| Relays | `tx_weight_relay` | 15 | virtual repeater transmit (when enabled). A relay held over 20 s is dropped. |
| Room | `tx_weight_room` | 10 | message delivery to members (all rooms) |
| Web users | `tx_weight_web` | 5 | users connected to the web client |
| Virtual companion | `tx_weight_companion` | 2 | packets sent by the virtual companion (when enabled) |
| KaaS | `tx_weight_kaas` | 3 | API clients |
| Background | `tx_weight_background` | 5 | adverts and traces |

With the defaults and everything on, the weights total 50, so each weight is that many percent. Web, companion and
API packets held over 2 minutes are dropped, and the client is told. Within what the limits allow, packets still go
in the room's order: its own ACKs and replies, then relays, then pushes, then API packets. The dashboard's
**Airtime** card sets all of this and shows each class's guaranteed share and its use over the last 10 minutes;
`POST /api/airtime` takes `{"duty_pct": 50, "weight": {"relay": 15, ...}}`. `repeater_airtime_pct`,
`kaas_airtime_pct` and `tx_share_*_pct` from older versions are ignored.

## Sending rules

* **3 packets in any 20 s per key** (`kaas_send_burst`, `kaas_send_window_s`), a rolling window, so a bot can send a
  short burst. ACKs and path returns are exempt: a bot has to answer
  what it receives, or room joins and DMs fail. Path returns usually carry an ACK.
* **Airtime**: API keys share the **KaaS** class's share of the radio's airtime, and web logins the **Web users**
  class's (see [Airtime](#airtime)): guaranteed by weight, more when the channel is quiet, up to the max duty cycle.
  ACKs count. `airtime_pct` in `hello` is the guaranteed share. A packet held over 2 minutes is dropped.
* **Messages**: a client may send 20 messages a second, in bursts of up to 40. Past that each gets an error; 40
  beyond it, the connection is closed (1008).
* **Lowest priority**: the room's ACKs and replies go first, then the virtual repeater's relays, then room pushes,
  then API packets. Packets other than ACKs and path returns also wait for a quiet moment on the channel, as room
  pushes do.
* **Checks**: the packet must parse as MeshCore, with a payload of at most 184 bytes. Adverts and logins that claim the
  identity of a node on this radio are refused.
* **Shared with this radio**: a packet you send is offered to the rooms, virtual companion and virtual
  repeater here first, as if they heard it. A flood or zero-hop packet that one of them takes stays off the air
  (`local`). Everything else is transmitted and is never relayed back by the room's own repeater.

## Settings

| Setting | Default | |
|---|---|---|
| `kaas_keys` | `[]` | The keys, hashed. Managed from the dashboard. |
| `kaas_send_burst` | 3 | Per key: at most this many packets... |
| `kaas_send_window_s` | 20 | ...in any this many seconds. ACKs and path returns are excepted. |
| `web_login` | false | MeshCore Web: people may log in by signing with their node's key. |
| `web_max_clients` | 32 | Web sessions at once, apart from API keys' 16. |
| `web_approved` | `[]` | Public keys (hex) allowed to send without being heard. Managed from the dashboard. |
| `web_banned` | `[]` | `{"pub", "name", "ts"}` of banned keys. Managed from the dashboard. |
| `web_banned_ips` | `[]` | `{"ip", "name", "ts"}` of banned addresses. Managed from the dashboard. |
| `web_unknown_key_message` | "Your key must be heard on RF before you can send messages. Please send a flood advert." | What a web user whose key may not send yet is told. Set from the dashboard. |
| `web_hosts` | `[]` | The names MeshCore Web is reached by (a domain, a proxy's name), besides this server's own `ip:port`. Set from the dashboard. |
| `web_page_password` | `""` | A password for the MeshCore Web page and its logins, hashed. Set from the dashboard. |
| `web_giphy_key` | `""` | A Giphy API key for MeshCore Web's GIF picker (developers.giphy.com). Set from the dashboard. |
| `web_backlog_days` | 30 | Keep channel messages and DMs this many days, for web users to catch up (0 = none). |
| `web_backlog_mqtt` | false | Keep what MQTT observers report too (each packet once), and show it to web users live. |

## Writing your own client

Anything that speaks websockets and JSON works. In Python, use the [client](../client/README.md). Otherwise:

1. Connect with the `Authorization` header (or, from a browser, a ticket) and read `hello`.
2. For each `packet`, decode `raw` and de-duplicate on `hash`.
3. Send `{"type": "send", "raw": ...}` and match `send_result` by `id`.

The MeshCore packet format and crypto are described in the MeshCore firmware source. `client/meshroom_kaas/node.py`
is a compact, working reference for adverts, DMs (with their ACKs and path returns), channels and room logins.
