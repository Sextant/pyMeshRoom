# The-Platinum-Most-Excellent-MeshCore-Pi-Room
MeshCore Room firmware running on basic nodes is too limiting for active high traffic volume Rooms.  Meet the Platinum Most Excellent MeshCore Pi Room (PMEMPR)!

> **The Full Monty branch.** `feature/the-full-monty` is the complete, RF-first edition: Room Server, optional MQTT ingestion, optional MQTT observer publishing, and an optional Virtual Repeater sharing one KISS modem. Internet access is optional. With every optional subsystem disabled, it remains a normal persistent RF-only MeshCore Room Server.

See stats and what repeaters the room is well connected to
<img width="1553" height="597" alt="image" src="https://github.com/user-attachments/assets/b9add1ee-5f80-4d57-b767-3be9e5889e07" />
See a member list, with click-to-expand to get more details
<img width="1545" height="751" alt="image" src="https://github.com/user-attachments/assets/d5b9a928-7c31-4734-ae46-6621e5ea953e" />
<img width="1963" height="451" alt="image" src="https://github.com/user-attachments/assets/4acb3c5b-9c82-419c-8ba7-dea0a4bf5e2d" />
Users who don't respond get moved to a suspended category.  Once a packet from them is seen on the mesh the room will resume sync
<img width="1553" height="1132" alt="image" src="https://github.com/user-attachments/assets/c9083bcf-5094-44b0-b1b7-c1b87683e458" />
Repeater map with details populated from RF and mqtt data
<img width="1543" height="613" alt="image" src="https://github.com/user-attachments/assets/8cf0aa3e-9777-4337-95c7-0f4cecb20961" />
Repeater list with best percieved routes from the room
<img width="1540" height="976" alt="image" src="https://github.com/user-attachments/assets/5ce43bce-da67-4f1e-a192-bd8b29fab4ac" />
Admin console with mqtt/flood options and chat box that accepts input to speak to the room
<img width="1540" height="829" alt="image" src="https://github.com/user-attachments/assets/b1af98f4-c0c8-4b73-ae4b-7ab4f8d7a93f" />
Admin buttons to force resync, suggest path, kick, or ban.
<img width="1540" height="323" alt="image" src="https://github.com/user-attachments/assets/a1670503-ffc2-40e9-afb4-26361b68cd10" />


# Why current rooms suck
Microcontrollers running Meshcore have limited resources that cannot scale to rooms with more than a few members over small numbers of hops:
* Limited memory
   * One route per member, no map of the mesh.
   * One route, then flood
   * Fastest path wins, not best.
   * New members have no route data.
* Limited cpu
   * One loop for everything, grinds to a halt as members join
   * Packets lost if not read from the radio quickly enough
* No persistence - reboots are devastating.
   * Clock is reset
   * Message queue is lost
   * Users states lost, and users are logged out
Usability:
* No insight into what the room is doing
* No admin tools

# Why meshroom (Linux + KISS modem) is better
Core functionality fixed:
* Radio is a dedicated KISS modem, and can focus on sending and receiving packets
* Much better persistence using storage instead of memory
   * SQLite databases for members, posts, sync states, routes, and shared secrets
* More robust core functionality with passive mesh monitoring/mapping for better message delivery
   * Time via linux host (NTP)
   * A map of the mesh, learned from every packet heard (2/3-byte IDs only), so the room can build routes it was never told
   * Multiple routes per member with recency-weighted success rates, trying alternates before flood fallback
   * A planned attempt order: best route, alternate, best again, next, flood; then backoff and give-up, instead of fixed retries
   * Newcomers reached direct on the first push: the companion directory knows where they are before they join by passively monitoring the mesh
   * Route shortcuts: unneeded hops are skipped when the room reaches a repeater directly, confirmed both ways
   * Adaptive push gaps sized from each route's measured ACK time; the ACK itselfends the wait, and flood gaps end once the rebroadcast wave passes
   * Learned ACK timeouts per route, instead of a fixed formula.
   * Extra ACK over a second route, so a single repeater's miss can't lose it
   * Late ACKs still count, crediting the route and stopping retries
   * Rounds ordered by delivery score: reliable members aren't held up behind struggling ones
   * Radio is never blocked: dedicated reader, database, and web threads
   * Duplicate re-sends caught: a member re-sending the same text is sent an ACK, but the message not reposted.
   * Fair catch-up: new members get the last few posts, returning members get recently missed messages
   * Takes part in traces that name the room as a hop.
   * Radio settings enforced: re-applied automatically if the modem reboots and reverts.
* Optional MQTT integration
   *Passively listen to gomesh.dev to capture topology, ack, and incoming room messages to speed up message distribution, with RF fallback   

# Additional useful features:
* Web dashboard, public to view with an admin login, and isolated so it can't slow the radio.
   * Members table: delivery score, current TX/RX routes, and up to 5 alternates each way.
   * Repeater map with links, and a detail pane for every repeater (key, position, routes, neighbors with SNR).
   * Best-neighbor table: discovery every 15 minutes plus idle-time traces, ranked by packet loss, with SNR both ways.
   * Stats: CPU and memory (now and 10-minute average), modem voltage, noise floor, channel use, packets/min, and pushes/min with delivery %.
   * Admin tools: resync, route suggestions with autocomplete, kick, ban/unban, and a chat box that posts as the room.
   * Messages: configurable welcome (with an advert reminder), plus kick/ban notices.
   * Passively collects SNR and Route data from traces as they pass by.

# `feature/mqtt-unified`: additions compared with `main`

This branch keeps the normal MeshRoom RF/KISS room server as the authority for room state, routing, acknowledgements, and transmission.  It adds optional MQTT features around that RF path; it does not add a second owner for the serial modem.

## Outbound MQTT observer

When `observer_enabled` is true, the observer makes a non-blocking copy of locally received RF packets and publishes them independently to GoMesh and/or MeshMapper over TLS WebSockets.  It provides:

* modem-backed identity signing; the MeshCore private key stays in the modem;
* independent GoMesh and MeshMapper connections, diagnostics, retained online/offline status, and reconnect handling;
* admin-only controls for observer enablement, IATA, packet/status reporting, RX reporting, brokers, and queue size;
* a bounded outbound queue, dropped-observation count, and local-RF traffic statistics; and
* a dashboard section below the repeater map for observer settings and broker health.

Only packets physically received through the KISS modem count as local RF traffic.  MQTT data never changes the RF RX counters or borrows local RSSI/SNR values.

## Inbound MQTT ingestion

When `mqtt_enabled` is true, a separate native Python MQTT/WebSocket subscriber listens to the configured GoMesh topics.  It can supplement, but never replace, RF operation by ingesting:

* matching ACKs for delivery confirmation;
* direct room packets addressed to this room;
* repeater/companion adverts and map enrichment;
* observed topology links between already-known repeaters; and
* selected channel activity to wake an otherwise suspended member.

Remote ACKs can mark a matching delivery complete, but route scoring and pacing credit remain reserved for a subsequent local RF ACK.  Remote topology is not used as a transmission route.  Retained MQTT packets, malformed data, duplicates, and observations whose `origin_id` is this room's own public key are ignored.  That last rule prevents the room from consuming its own outbound observer publications as new inbound traffic.

## Why the newest ingress event is ignored when the queue is full

Inbound MQTT events first enter a FIFO queue controlled by `mqtt_queue_max`, which defaults to **1000**.  The queue protects the radio and the main RoomServer event loop from an MQTT burst.  Radio and dashboard events are processed before a bounded slice of queued MQTT events.

If all 1000 positions are occupied, the **newly arriving** MQTT event is ignored and the `dropped` counter is incremented.  The oldest queued event is deliberately retained: it was already accepted in order and may be an ACK or direct room packet.  Discarding the oldest event could preserve later observations while losing an earlier event they logically follow.  This chooses delivery-state correctness and FIFO ordering over retaining the most recent map/activity update.  The queue depth, configured limit, and ignored-event count are exposed through the MQTT dashboard/API state.

## Dashboard and configuration

Observer publishing and MQTT ingestion use distinct settings and state:

* `observer_*` controls outbound local-RF reporting to GoMesh/MeshMapper.
* `mqtt_*` controls inbound remote-MQTT ingestion, including `mqtt_queue_max`.

Both are disabled by default and are controlled from separate admin-only dashboard sections.  Welcome-DM controls and observer controls remain below the repeater map.

# Installation/usage
Install
* Clone repo to a linux machine that has a KISS meshcore modem connected via USB.
* Make a copy of meshroom.json.example to meshroom.json and edit:
   * system: Update data dir to reflect the data subpath from your git clone
   * room: Set name and coordinates
   * access: Set room join password and room admin password
   * radio: Set USB interface and params for your region
   * dashboard: Set web UI admin password
   * observer: Leave `observer_enabled` false unless MQTT observation is wanted. To enable it, install `python3-paho-mqtt`, use IATA `SJC` for this deployment, and keep `identity` set to `modem`; the modem signs the MQTT token and the private key is never copied to the Pi. `observer_status` controls retained online/offline status messages on `meshcore/<IATA>/<public-key>/status`. Packet observations publish to `meshcore/<IATA>/<public-key>/packets` only when both `observer_packets` and `observer_rx` are true; they are compatibility gates for the same RX-only packet path, not independent packet types.
* Usage
   * Run ```python3 meshroom.py --config meshroom.json```
* Updating:
   * Stop meshroom
   * Clone again
   * Start meshroom

# Full Monty: build your own instance

## What you need

* A Linux host (a Raspberry Pi 4 or newer is a practical choice), Python 3, Git, and a MeshCore KISS modem attached by USB.
* A modem serial device such as `/dev/ttyUSB0`; the service user needs read/write permission, normally through the `dialout` group.
* A stable storage directory for the SQLite room database.
* Optional internet access only if you enable MQTT features or host the dashboard remotely. RF Room Server and Virtual Repeater functions do not require internet.

Create a virtual environment and install the core packages:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pyserial cryptography
```

Add `paho-mqtt` only when enabling the outbound MQTT observer:

```bash
.venv/bin/python -m pip install --upgrade paho-mqtt
```

## First configuration

Copy `meshroom/meshroom.json.example` to a private `meshroom/meshroom.json`, set permissions to owner-only, and set the room name, coordinates, serial device, radio parameters, data directory, passwords, and dashboard bind address. Never commit that file: it can contain passwords and a locally generated Virtual Repeater key.

Start with every optional feature disabled:

```json
"mqtt_enabled": false,
"observer_enabled": false,
"repeater_enabled": false
```

This is the recommended initial installation. Confirm normal RF room operation before enabling any optional feature.

## Optional MQTT

`mqtt_enabled` activates inbound supplemental observations. It can improve ACK confirmation, activity awareness, advert/map data, and topology awareness, but it never replaces RF routing or makes the Room Server dependent on a broker. Broker loss is reported in dashboard status and the RF room keeps operating.

### GoMesh inbound subscriber access

Inbound MQTT is separate from outbound observer publishing. An observer can publish a modem-signed local-RF observation while inbound MQTT remains unavailable. For inbound access, the RoomServer opens a read-only MQTT/WebSocket connection and requests the configured topic filter. A successful connection is **not** proof that the topic was authorized: the broker must grant the MQTT `SUBACK` response before packets can arrive.

![GoMesh inbound authorization flow](docs/images/gomesh-inbound-authorization.svg)

Some GoMesh installations may permit a public topic filter; others require a broker operator to issue a read-only subscriber username and password or to name an approved topic filter. The MQTT Augmentation admin card makes the **broker host**, **port**, **transport**, **WebSocket path**, **TLS settings**, and one or more comma-separated **topic filters** configurable. Its **Subscriber username**, **Subscriber password**, and **Save subscriber credentials** controls handle read-only access without putting secrets in the browser-visible status.

1. Obtain the broker endpoint, transport/TLS requirements, read-only credentials if required, and approved topic filter(s) from the broker operator.
2. Log into the dashboard as an administrator and open **MQTT Augmentation**. Set and save the broker/topic controls first.
3. If required, enter both subscriber fields and select **Save subscriber credentials**. Each save reconnects the inbound client immediately; RF service and outbound observer publishing continue independently.
4. Check the card status. It reports **subscription granted**, **subscription awaiting broker acknowledgement**, or **subscription denied**. The received and accepted MQTT counts provide the next confirmation that inbound data is flowing.

The password is write-only: it is saved in the owner-protected local configuration and is never returned by the dashboard/API or shown after it is saved. Keep the configuration file mode at `0600`. The project does not ship GoMesh credentials.

`observer_enabled` copies locally received RF packets to GoMesh and/or MeshMapper. It uses the modem-backed Room identity for signing; the Room private key never leaves the modem. Its `observer_queue_max` limits asynchronous outgoing observations. MQTT ingestion has its own `mqtt_queue_max` ingress limit, default 1000. If it is full, the newest remote event is ignored rather than evicting an already accepted older ACK or direct packet; FIFO delivery-state ordering is safer than keeping a fresher topology update.

## Optional Virtual Repeater

`repeater_enabled` creates a second logical MeshCore identity using the existing RoomServer KISS reader/writer and TX scheduler. It does not open a second serial connection. On first enable, a random repeater key is generated and saved only to the private local configuration; use `chmod 600` on that file.

![Virtual repeater key lifecycle](docs/images/virtual-repeater-key-lifecycle.svg)

### Default key or imported vanity key

If `repeater_key` is empty, enabling the Virtual Repeater creates a cryptographically random 32-byte private seed, derives its public key, and saves the private seed in the local `meshroom.json`. This is the default identity; it is separate from the Room identity, and it is stable across restarts because it is saved after creation.

If you already generated a matching private key for a vanity public key elsewhere, import it through the **Virtual Repeater** admin card:

1. Disable the Virtual Repeater first. Key replacement is deliberately rejected while it is running.
2. Paste the private material into **Import private key** and select **Import key**. The accepted form is 64 hexadecimal characters (a 32-byte seed) or 128 hexadecimal characters (a 64-byte private-key representation).
3. The dashboard validates the material, saves it locally, clears the browser input, and leaves the repeater disabled. Review the derived public identity after re-enabling it.

The RoomServer does not search for vanity keys and never exports a private key through the dashboard or status API. Preserve an encrypted offline backup of the private configuration before replacing a key. `repeater_relay` remains a separate relay kill switch: a repeater may advertise while forwarding is off.

`repeater_relay` is an independent immediate relay kill switch. When false, the repeater may advertise but relays no packets. Configure its name, coordinates, scoped regions, advert intervals, airtime cap, and loop-detection mode through the admin dashboard. Keep it disabled until RF validation is explicitly planned.

## Operations, upgrades, and rollback

Run the included unit tests before touching a live modem:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Use a separate checkout and virtual environment for any upgrade test. Never run two MeshRoom processes against the same serial modem. Keep a known-good checkout and systemd override rollback path. If an optional MQTT component fails, disable it in the dashboard or configuration; core RF operation continues. If Virtual Repeater behavior is unwanted, set `repeater_relay` false or `repeater_enabled` false and restart cleanly.

# Dependencies

The core room server requires:

* Linux with Python 3, a KISS-capable MeshCore modem, and serial-device permission (normally membership in `dialout`);
* `pyserial` for the USB/KISS connection; and
* `cryptography` for MeshCore packet cryptography and identity operations.

The optional outbound MQTT observer additionally requires:

* `paho-mqtt` (tested here with version 2.1.0) for signed publishing to GoMesh and MeshMapper.

The optional inbound MQTT ingestion uses only Python's standard library for MQTT, TLS, and WebSockets; it does **not** require an additional MQTT package. It needs network access to the configured broker (the default is `mqtt.gomesh.dev:443` with TLS WebSockets). If the broker requires read-only subscriber authorization, configure it through the admin controls or the private `mqtt_username` and `mqtt_password` settings. The dashboard’s `SUBACK` status—not merely “connected”—confirms whether the broker accepted the topic filter.
