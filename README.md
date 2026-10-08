# The-Platinum-Most-Excellent-MeshCore-Pi-Room
MeshCore Room firmware running on basic nodes is too limiting for active high traffic volume Rooms.  Meet the Platinum Most Excellent MeshCore Pi Room (PMEMPR)!

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

# Installation/usage
Install
* Clone repo to a linux machine that has a KISS meshcore modem connected via USB.
* Make a copy of meshroom.json.example to meshroom.json and edit:
   * system: Update data dir to reflect the data subpath from your git clone
   * room: Set name and coordinates
   * access: Set room join password and room admin password
   * radio: Set USB interface and params for your region
   * dashboard: Set web UI admin password
* Usage
   * Run ```python3 meshroom.py --config meshroom.json```
* Updating:
   * Stop meshroom
   * Clone again
   * Start meshroom
