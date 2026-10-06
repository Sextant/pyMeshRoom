# The-Platinum-Most-Excellent-MeshCore-Pi-Room
MeshCore Room firmware running on basic nodes is too limiting for active high traffic volume Rooms.  Meet the Platinum Most Excellent MeshCore Pi Room (PMEMPR)!

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
   * Fair catch-up: new members get the last few posts, returning members get everything they missed
   * Takes part in traces that name the room as a hop.
   * Radio settings enforced: re-applied automatically if the modem reboots and reverts.
Additional useful features:
* Web dashboard, public to view with an admin login, and isolated so it can't slow the radio.
   * Members table: delivery score, current TX/RX routes, and up to 5 alternates each way.
   * Repeater map with links, and a detail pane for every repeater (key, position, routes, neighbors with SNR).
   * Best-neighbor table: discovery every 15 minutes plus idle-time traces, ranked by packet loss, with SNR both ways.
   * Stats: CPU and memory (now and 10-minute average), modem voltage, noise floor, channel use, packets/min, and pushes/min with delivery %.
   * Admin tools: resync, route suggestions with autocomplete, kick, ban/unban, and a chat box that posts as the room.
   * Messages: configurable welcome (with an advert reminder), plus kick/ban notices.
   * Passively collects SNR and Route data from traces as they pass by.

#Installation/usage
Install
* Clone repo to a linux machine that has a KISS meshcore modem connected via USB.
* Make a copy of meshroom.json.example to meshroom.json and edit:
   * room: Set name and coordinates
   * access: Set room join password and room admin password
   * radio: Set USB interface and params for your region
   * dashboard: Set web UI admin password
* Usage
   * Run ```python3 meshroom.py --config meshroom.json```
*Updating:
   * Stop meshroom
   * Clone again
   * Start meshroom
