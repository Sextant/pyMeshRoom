# MeshCore Web

A MeshCore chat client that runs entirely in the browser. pyMeshRoom serves it at `/meshcore-web/` on the
dashboard's port, and it reaches the mesh through that radio over the KaaS API. This folder is its source.

* **Log in with your node's private key, which never leaves the browser.** The page signs a one-time challenge to
  prove you hold the key; no API key needed. Channel messages are encrypted and adverts signed in the page too, so the
  server only ever sees signatures and encrypted packets.
* **Self-contained.** It has no dependencies, no CDN and no backend of its own. The whole app is one file,
  [`meshroom/data/meshcore-web.html`](../meshroom/data/meshcore-web.html). pyMeshRoom serves it, and it also opens
  from disk or from any static web host.
* **Channels.** You join **Public** by default. You can also join **#hashtag** channels (the key comes from the name)
  and **private** channels (a 16-byte secret you share yourself).
* **Direct messages**, delivered and confirmed the way the MeshCore apps do it: three tries until the other node
  ACKs, the last by flood. **Routes** are automatic by default: the path learned from their answers, else the
  server's suggestions (its radio's best direct paths to them, as its room plans its own deliveries; used, like the room does, only when the best has at least a 35% chance, and then those with 20%), then a flood. A
  path that gets through is kept; the learned one failing is dropped. **Details** shows the route, the server's
  suggestions (**Use** one), and lets you set a path by hand (repeater ids, like `a1,b2,c3`) or always flood.
  Delivered messages say which way they went. Room logins and posts on other servers route the same way.
* **Rooms**: log in with the room's password, read the posts you missed, and post.
* **Contacts and a map**: everyone the server knows of from the last 30 days, refreshed every 15 minutes, plus any
  advert heard while you're here.
  * **Where they come from:** its node directory, repeater map, room members, its virtual companion's contacts and
    its name cache.
  * **Partial keys:** people known only from the name cache are listed and can be mentioned. They can't be sent a DM
    until their app adverts within range, because the cache holds only part of each key.
  * **The map** shows those that share a position.

## Logging in

| Field | |
|---|---|
| pyMeshRoom URL | The server, e.g. `https://meshroom.example.com`. A path prefix from a reverse proxy works too. Filled in by itself when pyMeshRoom serves the page (at `…/meshcore-web/`). A name other than the server's own `ip:port` (a domain, a proxy's) has to be listed under **Host names** on the server's Web users card, else logins are refused. |
| Private key | A 64-byte MeshCore private key in hex, as the apps export it, or a 32-byte seed. **New** makes one. Keep a copy: a new key is a new node. |
| Your name | Goes before your messages (`Name: text`) and into your adverts. |

**Remember me** (ticked to start with) keeps the private key in this browser's `localStorage`, and the page then connects by itself when it
opens. With a **passphrase**, the key is sealed instead: PBKDF2-HMAC-SHA256 with 50,000 rounds, AES-128-CTR and an
HMAC. You type the passphrase rather than the key each time. Leave Remember unticked on a shared computer: then only
the URL and your name are saved.

The server's admin turns web logins on (**Allow web logins** on the dashboard's **Web users** card). Anyone can then
log in and read. You can **send** (and use rooms) once the radio itself has heard your key advertise, for example in a
flood advert from your MeshCore app (an MQTT observer's report doesn't count), or once the admin allows your key.
Until then the page shows the admin's message (**Unknown key message** on the card), and it switches over by itself
when that happens. The admin can also disconnect or ban a key.

If the admin set a **page password**, the page pyMeshRoom serves asks for it before showing anything. A copy of the
page opened from elsewhere asks for it when logging in. With **Remember me**, it's saved like the key (sealed, with a
passphrase).

### How it authenticates

1. The page asks the server for a one-time challenge (`POST /api/v1/web/challenge`).
2. It signs `meshcore-web login v1`, the server's host, the challenge and your public key with your private key, and
   sends the signature back (`POST /api/v1/web/login`). The private key never leaves the browser.
3. It gets a one-time ticket for the websocket (`wss://…/api/v1/kaas?ticket=…`). Each reconnect signs a new challenge.

The label is always the page's own. It never signs anything the server chooses except the challenge, and a login
signature can never be mistaken for a packet signature. Naming the host means another site can't relay a login to
your server. 

## Using it

* **From pyMeshRoom:** open `https://<your server>/meshcore-web/`. The server URL is filled in by itself.
* **Single file:** download [`meshroom/data/meshcore-web.html`](../meshroom/data/meshcore-web.html) and open it, or
  host it anywhere, then type the server's URL. Nothing to install or build.
* **From source:** serve this folder over HTTP(S) and open `index.html`. ES modules don't load from `file://`, so
  use the single file for that.

`meshroom/data/meshcore-web.html` is built from `src/` by `node build.mjs`. A GitHub Action
(`.github/workflows/web.yml`) runs the tests and rebuilds and commits it whenever this folder changes on `main`.
On a pull request, it checks that the committed file matches the source.

If the page is served over HTTPS, the pyMeshRoom URL must be HTTPS as well, because browsers block mixed content.

What you get:

* Messages show the sender, the time, and the hops and SNR as the radio heard them. A flood heard through several
  repeaters shows once.
* `@[name]` mentions are highlighted, and mentions of you stand out. Typing `@` suggests names: people who wrote in this
  conversation lately first, then your contacts. Arrow keys or Tab pick one, which is inserted as `@[name]`.
* **Reactions**, in MeshCore One's format as the
  [MeshTrax message format](https://github.com/venamartin/meshtrax/blob/master/docs/message-format.md#reactions)
  describes it.
  * **On the wire:** `@[Author]👍` and a second line holding the message's hash: 8 Crockford Base32 characters of
    SHA-256(text + its timestamp). In a DM, just `👍` and the hash.
  * **Receiving:** a reaction is matched against the last 7 days of that conversation and shown as a chip on its
    message. It's tried against each form the text may have been hashed in (trimmed, as received, without leading
    mentions), and each timestamp the message may have carried: a retry's too (a retried message shows once), the
    next few seconds for our own, and the room server's own stamp for our room posts. One whose message isn't here
    shows as a short note, not as raw text, and moves onto its message if that turns up later (during a catch-up,
    say).
  * **Picking:** the quick row, or **＋** for any emoji.
  * **Look for it**, on a reaction that found nothing: searches the conversation's last 40 messages harder (each text
    form, every stamp up to 5 minutes off). Found, it goes on the message and says how far off it was (worth
    reporting); not found, it says so: the reaction was for a message this page never received, such as one sent from
    another device with your key.
* **Replies**, in MeshCore One's format as MeshTrax uses it: **↩** on a message, then type. It goes out as
  `@[Name]`, a line with `>` and the first 10 characters of theirs (`..` when there's more), then yours; the quote
  shrinks to 6 characters, or goes, when the reply is long. Replies show the message they answer when it's here (click
  to see it), else what they quoted. meshcore-open's `@[Name] re:quote…reply` is read too.
  * **Sending:** react from the button on any message, or press a chip to add yours.
  * **meshcore-open's older `r:HASH:INDEX`:** shown as a note. Its hash can't be reproduced outside Dart, so it can't
    be attached to a message.
* A message of nothing but emoji, up to 5, is shown large.
* **GIFs:** a Giphy link in a message (`https://giphy.com/gifs/…`, as Giphy's Share button copies it, with or without
  the `https://`), or meshcore-open's `g:ID`, shows as the GIF itself. To send one, paste the link, or pick one with
  **GIF** next to the message box (trending, or search Giphy; shown when the server's admin has set a Giphy API key).
  The GIF is previewed while you type. Other MeshCore apps see the link.
* **😊** next to the message box picks emoji, by category, with the ones you used lately first.
  **Show GIFs from Giphy** in the sidebar turns this off: loading a GIF lets Giphy see your IP address.
* Your own messages show **Sent**, **Waiting for the rate limit** or **Not sent: reason**, with **Retry**. DMs and
  room posts show **Delivered** once ACKed, or **Not delivered** after three tries. Sends are queued to fit the
  key's rate limit (3 packets per 20 s by default); ACKs and path returns don't count.
* A channel message holds 160 bytes, `Name: ` included; a DM 160; a room post 151. The counter shows what's left.
* **Advertise me** sends a signed advert, flood or zero-hop, so other people's apps learn your name and key.
* **Details** shows a private channel's secret, or a contact's or room's public key, to share or check. Channels,
  DMs, rooms (with their passwords and where their posts left off), contacts with their routes, and the last 300
  messages per conversation are kept in this browser, per identity, as is the conversation you had open. Room
  passwords are saved encrypted with a key derived from your private key, so they can't be read without it.
* A **message of the day**, when the server's admin sets one (**Message of the day** on the Web users card), pops up when you log in or open the page. **Don't show this again** hides that message on this browser until it changes.
* Rooms you've joined log you in again by themselves each time you connect.
* **The rooms on the server you're connected to** are read and posted to through the server, not
  over the air. So you can use the same key on a companion app at the same time: the room's sync point and route for
  your key stay your radio's, and posts you make from the companion show here too. (Posts you make here don't reach
  your companion: no room sends anyone their own posts.) Other rooms are logged in to over the air, which a companion
  using the same key will fight over.
* It reconnects by itself, logging in again each time: after 1 s, then twice as long each try up to 15 s, and at once
  when the network comes back or the tab is shown again. A server restart doesn't need the page password again (the
  page session is a signed cookie, not something the server has to remember). It stops if the admin disconnects or
  bans the key, or turns web logins off.
* If the login works but the websocket doesn't open, it asks the server what became of it and says why: most often a
  reverse proxy that doesn't pass websockets on (see [docs/api.md](../docs/api.md#connecting)).
* **Path ids** (sidebar): how many bytes of each repeater's id the floods you send collect in their path, MeshCore's path hash mode: 2 by default (1 or 3 too). Longer ids mix up fewer repeaters, so the routes learned from them are surer; very old repeater firmware only knows 1 byte.
* Dark (the dashboard's look), light, or following the system; it works on phones.

**Catching up.** pyMeshRoom keeps a backlog of channel messages and DMs, 30 days by default (the admin sets it).

* **On reconnect:** the page asks for what it missed since it was last here and works through it in chunks, so the
  page stays usable. Missed messages slot into each conversation by the time the server got them, marked "while you
  were away".
* **Read only:** nothing is answered for old messages. No ACKs go back, so a sender's app still shows a missed DM as
  undelivered.
* **First visit:** the page starts from now.
* **Per device:** each browser keeps its own place, so a phone and a laptop each catch up.

## Security notes

* All crypto runs in the page, in plain JS: SHA-256/512, HMAC, AES-128 and Ed25519 (`src/hash.js`, `src/aes.js`,
  `src/ed25519.js`). This doesn't depend on WebCrypto, which browsers offer only on secure origins and which can't
  sign with MeshCore's 64-byte expanded keys. The output is checked against pyMeshRoom's Python client
  (`test/vectors.json`).
* The built file has a Content-Security-Policy that allows only its own inline script and style, pinned by hash, so
  no other script can run next to your key. The map's Leaflet 1.9.4 may come only from the serving pyMeshRoom or that
  exact file on unpkg, and is pinned by hash too. Images may come only from Giphy's two image hosts (by GIF id), the
  OpenStreetMap tile servers and Leaflet's own.
  Message text is always added as text, never as HTML.
* Saved room passwords are sealed (AES-128-CTR and HMAC-SHA256) with a key derived one-way from your private key,
  under a label of its own: `HMAC-SHA256(private key, "meshcore-web local storage v1")`. That protects them while
  your key isn't saved, or is saved under a passphrase. A key saved without a passphrase sits in the same storage and
  could open them.

## Development

From this folder:

```
node build.mjs                     # ../meshroom/data/meshcore-web.html (CI also does this on main)
npm test                           # unit tests: crypto and packets against the Python client's vectors
test/e2e/run.sh                    # end to end: this pyMeshRoom (fake radio) + Chromium
test/e2e/run.sh built              # the same, against the built single file
python3 tools/make_vectors.py      # regenerate test/vectors.json from ../client
```

The end-to-end run starts pyMeshRoom's own test harness with a dashboard, web logins on and a KaaS key. It covers:

* logging in through the real UI with only a private key: pending until the radio hears the key's advert, then
  sending on Public, a hashtag channel and a private channel, including a burst past the rate limit;
* decrypting what the radio transmitted with the Python client, and checking the advert's signature;
* injecting packets for the page to receive, including Giphy links (Giphy itself is faked);
* contacts from the server's directory, a DM to and from a Python `meshroom_kaas` bot (delivered once ACKed), joining
  the radio's room with its password, posting, and receiving its posts;
* `@` autocomplete, the map (OpenStreetMap faked), the theme switch, and the saved login with and without a passphrase;
* persistence, kick and ban by the admin, a reverse proxy that drops websockets, a full server, the page served by pyMeshRoom at
  `/meshcore-web/`, and the phone layout.

It needs python3 with `cryptography` and `pyserial`, and node with Playwright.

Source layout:

| File | |
|---|---|
| `src/app.js` | The UI |
| `src/kaas.js` | Signed login, ticket, websocket, reconnects, rate-limited send queue |
| `src/node.js` | Contacts, DMs with ACKs and retries, path returns, rooms: a port of `client/meshroom_kaas/node.py` |
| `src/map.js` | The map (Leaflet, loaded when first opened) |
| `src/vault.js` | The passphrase-sealed saved key |
| `src/gif.js` | Giphy links |
| `src/emoji.js` | The emoji picker's emoji |
| `src/format.js` | Reactions and the message hash, from the MeshTrax message format |
| `src/meshcore.js` | Packets, identities, adverts, channel messages: a port of `client/meshroom_kaas` |
| `src/hash.js`, `src/aes.js`, `src/ed25519.js`, `src/bytes.js` | Crypto and byte helpers |
| `src/store.js` | `localStorage` |
| `build.mjs` | Bundles everything into `../meshroom/data/meshcore-web.html` |
