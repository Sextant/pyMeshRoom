# WhereBot

Answers `!where` on hashtag channels with the repeaters that usually hear a node, from the room's KaaS API
(`near`, see [docs/api.md](../../docs/api.md)).

```
!where @[platinum]
platinum: recently active near:
44c3 Seaside 62%
55b2 25%
9a1f pyMeshRoom Virtual Repeater 13%

!where a1b2c3d4e5f60718
a1b2c3d4 (aka platinum): recently active near:
44c3 Seaside 62%
55b2 Williams Hill 25%
9a1f pyMeshRoom Virtual Repeater 13%

!where @[nobody]
I am not familiar with that name. You can try lookup by public key

!where ffeeddccbbaa9988
I am not familiar with that public key
```

`!suggest <id> to <id>` with two repeaters' 2-byte ids asks the room for up to 5 routes between them (the KaaS
`route` request), each scored 0 to 1:

```
!suggest 5b98 to ec43
Suggested routes: Seaside to Williams Hill
5b98,ec43 (.87)
5b98,beef,ec43 (.39)
```

A key needs at least its first 16 hex characters. Shares are how often each repeater carried the node's floods.
Each line is a repeater's 2-byte id, its name if known, and its share. When the room's own radio hears the node
directly, that line is the room's virtual repeater (or the room itself when the virtual repeater is off). A reply has
to fit one channel message (160 bytes, "WhereBot: " included), so long repeater names are shortened first, then
dropped, and only then are the least heard repeaters left out.

## Running it

```
pip install cryptography pyyaml
cp where_bot.example.yaml where_bot.yaml     # then fill it in
python3 where_bot.py                         # or: python3 where_bot.py some_other.yaml
```

With no argument it uses `where_bot.yaml` from the current directory, or else the one next to `where_bot.py`.

To run it in the background, `./start-wherebot.sh` starts it with nohup (logging to `where_bot.log`, its pid in
`where_bot.pid`, both in this directory) and `./stop-wherebot.sh` stops it. Both work from any directory, and
`start-wherebot.sh` also takes a config path.

It answers the same commands in rooms: list them under `rooms:` by public `key`, with their passwords. It joins
only the rooms listed there (an entry without a `key` is skipped). It logs in on every connect and replies with a post, at most 151 bytes.

The bot sends a flood advert when it starts and every 12 hours after that (`advert_hours`, 0 to turn it off), so
people's apps learn its name and key. The API key needs Receive and Send. The bot reconnects on its own if the connection drops.
