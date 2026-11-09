// End to end: the real app in Chromium against a real pyMeshRoom (fake radio).
// node e2e.cjs PAGE_URL WORK_DIR, with devserver.py running on port 9101 (see run.sh)
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const H = __dirname;
const SERVER = 'http://127.0.0.1:9101';
const [pageUrl, W] = process.argv.slice(2);
const shotPrefix = W + '/shot';
const token = fs.readFileSync(W + '/dev.log', 'utf8').match(/TOKEN (\S+)/)[1];
const ID = JSON.parse(fs.readFileSync(H + '/../vectors.json')).identities[0];
const PRIV = ID.private, PUB = ID.public;
const py = (...args) => execFileSync('python3', [H + '/mkpkt.py', ...args]).toString().trim();
const hear = (hex) => fs.appendFileSync(W + '/rx.txt', 'RX ' + hex + '\n');
const inject = (ch, sender, text, ts) => hear(py(ch, sender, text, ...(ts ? [String(ts)] : [])));
const ok = (cond, what) => { if (!cond) { console.log('FAIL', what); process.exitCode = 1; } else console.log('ok  ', what); };
const GIF_ID = 'JIX9t2j0ZTN9S';
const command = (line) => fs.appendFileSync(W + '/rx.txt', line + '\n');
const seed = () => require('crypto').randomBytes(32).toString('hex');
// MeshCore One's message hash (what a reaction names): Crockford base32 of SHA-256(text + u32 LE ts)[0..5]
function messageHash(text, ts) {
  const b = Buffer.alloc(4); b.writeUInt32LE(ts >>> 0);
  const d = require('crypto').createHash('sha256').update(Buffer.concat([Buffer.from(text, 'utf8'), b])).digest();
  let bits = 0n; for (let i = 0; i < 5; i++) bits = (bits << 8n) | BigInt(d[i]);
  let out = ''; for (let sh = 35n; sh >= 0n; sh -= 5n) out += '0123456789abcdefghjkmnpqrstvwxyz'[Number((bits >> sh) & 31n)];
  return out;
}
const LEAFLET_DIR = path.join(process.env.PYMESHROOM, 'meshroom', 'data', 'static');
const TINY_GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

let cookie = null;
const tileReferers = [];
async function admin(p, body) {
  if (!cookie) {
    const r = await fetch(SERVER + '/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"password":"adminpw"}' });
    cookie = r.headers.get('set-cookie').split(';')[0];
  }
  const r = await fetch(SERVER + p, { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: JSON.stringify(body || {}) });
  return r.status;
}

// A reverse proxy in front of the server that gets websockets wrong: "strip" passes them on without the Upgrade and
// Connection headers (nginx without proxy_http_version 1.1 and proxy_set_header Upgrade), "drop" hangs up on them.
function startProxy(mode) {
  const http = require('http');
  const target = new URL(SERVER);
  const forward = (req, headers, res) => {
    const up = http.request({ host: target.hostname, port: target.port, method: req.method, path: req.url, headers }, (r) => {
      res.writeHead(r.statusCode, { ...r.headers, 'access-control-allow-origin': r.headers['access-control-allow-origin'] || '' });
      r.pipe(res);
    });
    up.on('error', () => res.destroy());
    req.pipe(up);
  };
  const server = http.createServer((req, res) => forward(req, req.headers, res));
  server.on('upgrade', (req, socket) => {
    if (mode === 'drop') return socket.destroy();
    const { upgrade, connection, ...headers } = req.headers;
    const up = http.request({ host: target.hostname, port: target.port, method: 'GET', path: req.url, headers }, (r) => {
      socket.end('HTTP/1.1 ' + r.statusCode + ' X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
      r.resume();
    });
    up.on('error', () => socket.destroy());
    up.end();
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

async function newPage(b, opts = {}) {
  const ctx = await b.newContext({ viewport: { width: 1200, height: 760 }, ...opts });
  await ctx.route(/^https:\/\/api\.giphy\.com\/v1\/gifs\/(search|trending)\?/, (r) => {
    const u = new URL(r.request().url());
    const ids = u.searchParams.get('api_key') !== 'e2etestkey' ? null : u.pathname.endsWith('/search') ? [GIF_ID, 'AbCdEf123456'] : [GIF_ID];
    r.fulfill(ids ? { status: 200, contentType: 'application/json', body: JSON.stringify({ data: ids.map((id) => ({ id })) }) }
      : { status: 403, body: '{}' });
  });
  await ctx.route(/^https:\/\/(media\d?|i)\.giphy\.com\//, (r) => r.fulfill({ status: 200, contentType: 'image/gif', body: TINY_GIF }));
  await ctx.route(/^https:\/\/unpkg\.com\/leaflet@1\.9\.4\/dist\/(leaflet\.(js|css))$/, (r) => {
    const f = r.request().url().split('/').pop();
    r.fulfill({ status: 200, contentType: f.endsWith('.js') ? 'application/javascript' : 'text/css', body: fs.readFileSync(path.join(LEAFLET_DIR, f)),
      headers: { 'Access-Control-Allow-Origin': '*' } });
  });
  await ctx.route(/tile\.openstreetmap\.org/, (r) => {
    tileReferers.push(r.request().headers()['referer'] || '');               // (OSM refuses tiles without one)
    r.fulfill({ status: 200, contentType: 'image/gif', body: TINY_GIF });
  });
  const p = await ctx.newPage();
  p.errors = [];
  p.on('pageerror', e => p.errors.push('pageerror: ' + e.message));
  p.on('console', m => { if (m.type() === 'error' && !/WebSocket|Failed to load resource/.test(m.text())) p.errors.push('console: ' + m.text()); });
  return p;
}

async function waitOpen(p) {
  try {
    await p.waitForSelector('#conn-dot.open', { timeout: 10000 });
  } catch (e) {
    const err = await p.textContent('#login-error').catch(() => '');
    throw new Error('not connected: ' + (err || e.message) + ' ' + p.errors.join(' | '));
  }
}

async function loginWith(p, { url = SERVER, priv = PRIV, name = 'WebTester' } = {}) {
  if (url !== null) await p.fill('#f-url', url);
  await p.fill('#f-priv', priv);
  await p.fill('#f-name', name);
  await p.click('#login-go');
}

let b;
(async () => {
  b = await chromium.launch();
  const errors = [];
  hear(py('--advert', seed(), 'Seaside', '2', '36.60', '-121.89'));       // a repeater with a position
  hear(py('--advert', seed(), 'Carol', '1'));                             // a person
  const p = await newPage(b);
  await p.goto(pageUrl);
  ok(await p.isHidden('#f-key'), 'no API key field: logging in takes only the private key and a name');
  ok(await p.isChecked('#f-remember'), 'remember me: on by default');
  ok(/heard your node on the mesh/.test(await p.textContent('.login .card')), 'the intro says sending needs the key heard on the mesh');
  await p.uncheck('#f-remember');                                       // (the tests below start from a key not kept)
  await p.fill('#f-url', SERVER); await p.fill('#f-priv', PRIV); await p.fill('#f-name', 'WebTester');
  await p.waitForFunction(() => document.getElementById('f-pub').textContent.startsWith('Public key:'));
  await p.screenshot({ path: shotPrefix + '-login.png' });
  ok(await admin('/api/v1/web/settings', { motd_enabled: true, motd: 'Welcome to the mesh!\nBe nice.' }) === 200, 'admin sets a message of the day');
  await p.click('#login-go');
  await p.waitForSelector('#conn-dot.open', { timeout: 10000 });
  ok(true, 'logged in by signing with the private key');
  await p.waitForSelector('#dlg-motd[open]', { timeout: 10000 });
  ok(await p.textContent('#motd-text') === 'Welcome to the mesh!\nBe nice.', 'the message of the day pops up on login, line breaks kept');
  await p.check('#motd-hide');
  await p.click('#motd-ok');
  ok(await p.isHidden('#dlg-motd'), 'and is dismissed');
  ok(await admin('/api/v1/web/settings', { motd_enabled: false }) === 200, 'admin turns it off again');
  ok(/can read, but not send yet: Your key must be heard on RF before you can send messages\. Please send a flood advert\./
    .test(await p.textContent('#banner')), 'a key not heard on the air yet is pending: read only, with the admin\'s message');
  ok(await p.isDisabled('#send') && await p.isDisabled('#advert'), 'pending: can\'t send or advertise');
  await p.click('#join-room');
  await p.fill('#r-key', 'ab'.repeat(32));
  await p.click('#r-go');
  ok(/can't send yet/.test(await p.textContent('#r-error')), 'pending: can\'t join a room either');
  await p.click('#dlg-room [data-close]');
  await p.screenshot({ path: shotPrefix + '-pending.png' });

  hear(py('--advert', PRIV, 'WebTester'));                   // their MeshCore app adverts within range of the radio
  await p.waitForSelector('#toast:text("you can send now")', { timeout: 10000 });
  await p.waitForSelector('#banner', { state: 'hidden', timeout: 5000 });
  ok(true, 'heard on the air: the page switches to "can send" by itself');
  ok(await p.textContent('#room-name') === 'Public', 'Public is the default channel');
  await p.fill('#text', 'hello from the browser');
  await p.press('#text', 'Enter');
  await p.waitForSelector('.msg.mine .status:text("Sent")', { timeout: 10000 });
  ok(true, 'own message sent');

  inject('Public', 'Bob', 'hi @[WebTester], welcome');
  await p.waitForSelector('.msg .sender:text("Bob")', { timeout: 10000 });
  ok(await p.textContent('.msg:not(.mine) .meta span:nth-child(3)') === '2 hops · SNR 6.0', 'hops and SNR shown');
  ok(await p.locator('.mention.me').count() === 1, 'own mention highlighted');
  const once = py('Public', 'Bob', 'only once');
  hear(once); hear(once);
  await p.waitForSelector('.msg .text:text("only once")');
  await p.waitForTimeout(800);
  ok(await p.locator('.msg .text:text("only once")').count() === 1, 'a packet heard twice shows once');

  inject('Public', 'Carol', 'look at this https://giphy.com/gifs/cat-funny-' + GIF_ID + ' haha');
  await p.waitForSelector('.msg .gif img', { timeout: 10000 });
  await p.waitForFunction(() => { const i = document.querySelector('.msg .gif img'); return i && i.complete && i.naturalWidth > 0; }, null, { timeout: 10000 });
  ok(await p.getAttribute('.msg .gif img', 'src') === 'https://media.giphy.com/media/' + GIF_ID + '/giphy.gif', 'a Giphy link shows as the GIF');
  ok(/look at this\s+haha/.test(await p.textContent('.msg:has(.gif) .text')), 'the rest of the message stays around the GIF');
  await p.fill('#text', 'https://giphy.com/gifs/' + GIF_ID);
  await p.waitForSelector('#gif-preview img', { timeout: 5000 });
  ok(true, 'a Giphy link being typed is previewed');
  await p.press('#text', 'Enter');
  await p.waitForSelector('.msg.mine .gif img', { timeout: 10000 });
  ok(await p.isHidden('#gif-preview'), 'sent as a GIF; preview cleared');
  await p.click('#show-gifs');
  ok(await p.locator('.msg .gif img').count() === 0 && await p.locator('.msg .gif-link').count() === 2, 'Show GIFs off: links instead, nothing loaded');
  await p.click('#show-gifs');
  ok(await p.locator('.msg .gif img').count() === 2, 'Show GIFs back on');

  await p.click('#add-channel');
  await p.fill('#a-tag', 'test');
  await p.click('#add-go');
  ok(await p.textContent('#room-name') === '#test', 'joined #test');
  inject('#test', 'Carol', 'on the hashtag');
  await p.waitForSelector('.msg .text:text("on the hashtag")', { timeout: 10000 });
  ok(true, '#test message decrypted');
  inject('Public', 'Bob', 'while you were away');
  await p.waitForSelector('#channel-list .badge', { timeout: 10000 });
  ok(await p.textContent('#channel-list button:first-child .badge') === '1', 'unread badge on Public');

  await p.click('#add-channel');
  await p.click('.tab[data-kind=private]');
  await p.fill('#a-name', 'Ops');
  await p.fill('#a-secret', '00112233445566778899aabbccddeeff');
  await p.click('#add-go');
  ok(await p.textContent('#room-name') === 'Ops', 'joined private channel Ops');
  await p.fill('#text', 'secret plans');
  await p.press('#text', 'Enter');
  for (let i = 1; i <= 4; i++) { await p.fill('#text', 'burst ' + i); await p.press('#text', 'Enter'); }
  await p.waitForFunction(() => [...document.querySelectorAll('.msg.mine .status')].every(s => s.textContent === 'Sent'), null, { timeout: 30000 });
  ok(true, '5 messages through the rate limit (3 per 2 s), all sent');
  inject('00112233445566778899aabbccddeeff', 'Dave', 'private reply');
  await p.waitForSelector('.msg .text:text("private reply")', { timeout: 10000 });
  ok(true, 'private channel message decrypted');

  await p.click('#advert');
  await p.click('[data-advert=flood]');
  await p.waitForSelector('#toast:text("Advert sent.")', { timeout: 15000 });
  ok(true, 'advert sent');
  await p.click('#channel-info');
  ok(await p.inputValue('#i-secret') === '00112233445566778899aabbccddeeff', 'private secret shown in details');
  await p.click('#dlg-info [data-close]');
  await p.screenshot({ path: shotPrefix + '-chat.png' });

  // contacts: the server's directory, plus adverts heard while here
  await p.click('#open-contacts');
  await p.waitForSelector('#c-list .contact b:text("Carol")', { timeout: 10000 });
  ok(true, 'contacts: people from the server\'s directory');
  await p.click('.tab[data-ctab=repeater]');
  await p.waitForSelector('#c-list .contact b:text("Seaside")', { timeout: 5000 });
  ok(true, 'contacts: repeaters');
  await p.click('.tab[data-ctab=room]');
  ok(await p.locator('#c-list .contact').count() >= 1, 'contacts: the room on this radio');
  await p.click('#dlg-contacts [data-close]');

  // a DM with EchoBot (a Python meshroom_kaas node on its own KaaS key): delivered (ACKed), and its answer
  command('BOT_ADVERT');
  await p.click('#open-contacts');
  await p.click('.tab[data-ctab=chat]');
  await p.waitForSelector('#c-list .contact b:text("EchoBot")', { timeout: 15000 });
  await p.click('#c-list .contact:has(b:text("EchoBot")) button:text("Message")');
  ok(await p.textContent('#room-name') === 'EchoBot', 'DM conversation opened from contacts');
  await p.fill('#text', 'ping over the mesh');
  await p.press('#text', 'Enter');
  await p.waitForSelector('.msg.mine .status:text("Delivered")', { timeout: 30000 });
  ok(true, 'DM delivered: the bot ACKed it');
  await p.waitForSelector('.msg:not(.mine) .text:text("echo: ping over the mesh")', { timeout: 30000 });
  ok(true, 'DM received: the bot\'s answer, decrypted here');
  ok(await p.locator('#dm-list button:has-text("EchoBot")').count() === 1, 'the DM is listed in the sidebar');
  ok(/Delivered via (flood|zero hop|[0-9a-f]{2})/.test(await p.textContent('.msg.mine:has(.text:text("ping over the mesh")) .status')),
    'a delivered DM says which way it went: ' + await p.textContent('.msg.mine:has(.text:text("ping over the mesh")) .status'));
  // its route: automatic, a path set by hand, or flood (Details)
  await p.click('#channel-info');
  await p.waitForSelector('#i-route-box:not([hidden])');
  await p.waitForSelector('#i-suggested li', { timeout: 10000 });
  ok(await p.isChecked('input[name="i-route"][value="auto"]'), 'a DM\'s route: automatic to start with');
  await p.locator('#dlg-info').screenshot({ path: shotPrefix + '-route.png' });
  await p.check('input[name="i-route"][value="flood"]');
  ok(/route: flood \(set\)/.test(await p.textContent('#room-sub')), 'route set to flood: ' + await p.textContent('#room-sub'));
  await p.check('input[name="i-route"][value="manual"]');
  await p.fill('#i-manual', 'a1, b2');
  await p.click('#i-manual-set');
  ok(/route: a1 › b2 \(set\)/.test(await p.textContent('#room-sub')), 'a route set by hand: ' + await p.textContent('#room-sub'));
  await p.check('input[name="i-route"][value="auto"]');
  ok(/route: (automatic|.*\(learned\))/.test(await p.textContent('#room-sub')), 'back to automatic');
  await p.click('#dlg-info [data-close]');

  // the room on this radio: read and posted to through the server, not over the air (that's for our companion app)
  const txBefore = fs.readFileSync(W + '/dev.log', 'utf8').split('\n').filter((l) => l.startsWith('TX ')).length;
  await p.click('#join-room');
  const roomName = await p.evaluate(() => document.querySelector('#r-known option')?.value || '');
  ok(!!roomName, 'the room on this radio is offered by name: ' + roomName);
  await p.fill('#r-key', roomName);
  await p.fill('#r-pass', 'hello');
  await p.click('#r-go');
  await p.waitForSelector('#dlg-room', { state: 'hidden', timeout: 30000 });
  ok(/logged in/.test(await p.textContent('#room-sub')), 'logged in to the room');
  await p.fill('#text', 'hi room');
  await p.press('#text', 'Enter');
  await p.waitForSelector('.msg.mine .status:text("Delivered")', { timeout: 30000 });
  ok(true, 'room post delivered');
  command('SAY welcome, web user');
  await p.waitForSelector('.msg .text:text("welcome, web user")', { timeout: 30000 });
  ok(true, 'the room\'s post arrives');
  command('MEMBER_POST ' + PUB + ' sent from my companion');
  await p.waitForSelector('.msg.mine .text:text("sent from my companion")', { timeout: 10000 });
  ok(true, 'a post made with the same key from a companion app shows here, as ours');
  await p.waitForTimeout(1500);
  const roomTx = py === null ? [] : fs.readFileSync(W + '/dev.log', 'utf8').split('\n').filter((l) => l.startsWith('TX ')).slice(txBefore)
    .map((l) => execFileSync('python3', ['-c', 'import sys,os;sys.path.insert(0,os.path.join(os.environ["PYMESHROOM"],"client"));' +
      'from meshroom_kaas import Packet;print(Packet.parse(bytes.fromhex(sys.argv[1])).type_name)', l.slice(3)]).toString().trim());
  ok(!roomTx.some((t) => /ANON_REQ|ACK|TXT_MSG/.test(t)), 'nothing went over the air for the room on this radio: ' + (roomTx.join(' ') || 'nothing'));
  await p.waitForTimeout(800);                                           // (saved half a second after a change)
  const savedRoom = await p.evaluate((pub16) => {
    const list = JSON.parse(localStorage.getItem('meshcore-web.contacts.' + pub16) || '[]');
    return list.find((c) => c.room)?.room || null;
  }, PUB.slice(0, 16));
  ok(savedRoom && savedRoom.sealedPassword && !('password' in savedRoom) && !JSON.stringify(savedRoom).includes('hello'),
    'the room password is saved sealed with the private key, never in the clear');

  // @mentions: people who wrote here first
  await p.click('#channel-list button:has-text("Public")');
  await p.fill('#text', '');
  await p.type('#text', 'hey @Bo');
  await p.waitForSelector('#mentions button:text("@Bob")', { timeout: 5000 });
  await p.press('#text', 'Enter');
  ok(await p.inputValue('#text') === 'hey @[Bob] ', 'autocomplete: @Bo becomes @[Bob]');
  await p.fill('#text', '');

  // reactions (MeshCore One's format): to our own message, from someone else, and ours to theirs
  const hist = await p.evaluate((pub16) => JSON.parse(localStorage.getItem('meshcore-web.history.' + pub16) || '{}'), PUB.slice(0, 16));
  const pub = Object.values(hist).flat();
  const mine = pub.find((m) => m.mine && m.text === 'hello from the browser');
  inject('Public', 'Bob', '@[WebTester]👍\n' + messageHash(mine.text, mine.ts));
  await p.waitForSelector('.msg.mine:has(.text:text("hello from the browser")) .chip', { timeout: 10000 });
  ok(await p.textContent('.msg.mine:has(.text:text("hello from the browser")) .chip') === '👍' &&
    await p.locator('.msg .text:has-text("👍")').count() === 0, 'a reaction to our message shows on it, not as a message');
  inject('Public', 'Carol', '@[Nobody]🔥\nabcdefgh');
  await p.waitForSelector('.reaction-note:has-text("Carol")', { timeout: 10000 });
  ok(true, 'a reaction to a message we never saw: a note, not raw text');
  // the emoji picker: into the message box at the caret, and remembered as recent
  await p.fill('#text', 'nice ');
  await p.click('#emoji-btn');
  await p.click('#pick-tabs button[title="Nature"]');
  await p.click('#pick-grid button[aria-label="🐢"]');
  ok(await p.inputValue('#text') === 'nice 🐢', 'emoji picker: into the message box');
  await p.click('#emoji-btn');
  await p.click('#emoji-btn');
  ok(await p.isVisible('#pick-tabs button[title="Recent"]') && await p.isVisible('#pick-grid button[aria-label="🐢"]'), 'emoji picker: recent ones first');
  await p.keyboard.press('Escape');
  // the GIF picker: trending, then a search; the pick goes in as a Giphy link
  await p.fill('#text', '');
  ok(await p.isVisible('#gif-btn'), 'a GIF button, with the server\'s Giphy key');
  await p.click('#gif-btn');
  await p.waitForSelector('#pick-grid.gifs button img', { timeout: 5000 });
  ok(await p.textContent('#pick-foot') === 'Powered by GIPHY', 'GIF picker: trending, with Giphy\'s attribution');
  await p.fill('#gif-q', 'cats');
  await p.waitForFunction(() => document.querySelectorAll('#pick-grid.gifs button').length === 2, null, { timeout: 5000 });
  await p.click('#pick-grid.gifs button >> nth=0');
  ok(await p.inputValue('#text') === 'https://giphy.com/gifs/' + GIF_ID + ' ' && await p.isHidden('#pick-pop'), 'GIF picker: a search, and the pick as a Giphy link');
  await p.waitForSelector('#gif-preview img', { timeout: 5000 });
  await p.fill('#text', '');

  // a reaction that comes before its message (a catch-up still under way) waits, then goes onto it
  const T = Math.floor(Date.now() / 1000) - 50;
  inject('Public', 'Dave', '@[Eve]😮\n' + messageHash('arrives late', T));
  await p.waitForSelector('.reaction-note:has-text("Dave")', { timeout: 10000 });
  inject('Public', 'Eve', 'arrives late', T);
  await p.waitForSelector('.msg:has(.text:text("arrives late")) .chip:has-text("😮")', { timeout: 10000 });
  ok(await p.locator('.reaction-note:has-text("Dave")').count() === 0, 'a reaction before its message: the note goes onto it when it comes');
  // a retry stamped anew is the same message, and a reaction to the retry's stamp finds it
  inject('Public', 'Eve', 'said twice', T);
  await p.waitForSelector('.msg .text:text("said twice")', { timeout: 10000 });
  inject('Public', 'Eve', 'said twice', T + 31);
  inject('Public', 'Dave', '@[Eve]👀\n' + messageHash('said twice', T + 31));
  await p.waitForSelector('.msg:has(.text:text("said twice")) .chip:has-text("👀")', { timeout: 10000 });
  ok(await p.locator('.msg .text:text("said twice")').count() === 1, 'a retry is one message, and a reaction to its stamp finds it');
  await p.hover('.msg:has(.text:text("only once"))');
  await p.click('.msg:has(.text:text("only once")) .react-btn');
  await p.click('#react-pop button:text("❤️")');
  // any emoji, from the full picker
  await p.waitForSelector('.msg:has(.text:text("only once")) .chip.me', { timeout: 5000 });
  await p.hover('.msg:has(.text:text("only once"))');
  await p.click('.msg:has(.text:text("only once")) .react-btn');
  await p.click('#react-pop button.more');
  await p.click('#pick-tabs button[title="Food"]');
  await p.click('#pick-grid button[aria-label="🍕"]');
  await p.waitForSelector('.msg:has(.text:text("only once")) .chip.me:has-text("🍕")', { timeout: 5000 });
  ok(await p.isHidden('#pick-pop'), 'reacting with any emoji, from the full picker');
  await p.waitForSelector('.msg:has(.text:text("only once")) .chip.me', { timeout: 5000 });
  ok(true, 'reacting to a message: shown at once');
  const theirs = pub.find((m) => m.text === 'only once');
  const wantReaction = 'WebTester: @[Bob]❤️\n' + messageHash('only once', theirs.ts);
  inject('Public', 'Bob', '🎉');
  await p.waitForSelector('.msg .text.big:text("🎉")', { timeout: 10000 });
  ok(true, 'an emoji-only message is shown large');
  inject('Public', 'Bob', 'g:abcdefghijklmn');
  await p.waitForSelector('.msg:last-child .gif img', { timeout: 10000 });
  ok(true, 'a g:ID GIF (meshcore-open) is shown');

  // replies (MeshCore One's format): ours quotes theirs; theirs quoting ours shows the message it answers
  await p.hover('.msg:has(.text:text("only once"))');
  await p.click('.msg:has(.text:text("only once")) .reply-btn');
  ok(await p.isVisible('#reply-bar') && await p.textContent('#reply-name') === 'Bob', 'reply: the bar names who we answer');
  await p.fill('#text', 'sure thing');
  await p.press('#text', 'Enter');
  await p.waitForSelector('.msg.mine:has(.text:text("sure thing")) .quote.found', { timeout: 10000 });
  ok(await p.isHidden('#reply-bar') && /Bob only once/.test(await p.textContent('.msg.mine:has(.text:text("sure thing")) .quote')),
    'our reply shows the message it answers');
  const wantReply = 'WebTester: @[Bob]\\n>only once\\nsure thing';
  inject('Public', 'Bob', '@[WebTester]\n>hello from..\nnice one');
  await p.waitForSelector('.msg:has(.text:text("nice one")) .quote.found', { timeout: 10000 });
  ok(/hello from the browser/.test(await p.textContent('.msg:has(.text:text("nice one")) .quote')), 'their reply to us: the quote finds our message');
  await p.hover('.msg:has(.text:text("nice one"))');
  await p.screenshot({ path: shotPrefix + '-replies.png' });
  // a reaction that matches nothing: Look for it searches harder (and attaches it, or says why not)
  inject('Public', 'Dave', '@[Bob]👏\n' + messageHash('only once', theirs.ts + 40));
  await p.waitForSelector('.reaction-note:has-text("Dave") button', { timeout: 10000 });
  await p.click('.reaction-note:has-text("Dave") button');
  await p.waitForSelector('.msg:has(.text:text("only once")) .chip:has-text("👏")', { timeout: 15000 });
  ok(await p.locator('.reaction-note:has-text("Dave")').count() === 0, 'look for it: a reaction 40 s off is found and attached');
  await p.click('.reaction-note:has-text("Carol") button');
  await p.waitForSelector('.reaction-note:has-text("Carol") button:text("why?")', { timeout: 15000 });
  ok(/never received/.test(await p.getAttribute('.reaction-note:has-text("Carol")', 'title')), 'look for it: says why when nothing here matches');

  // the map
  await p.click('#open-map');
  await p.waitForSelector('#map-box .leaflet-interactive', { timeout: 15000 });
  ok(/1 of \d+ known nodes/.test(await p.textContent('#map-note')), 'map: ' + await p.textContent('#map-note'));
  await p.waitForFunction(() => document.querySelectorAll('.leaflet-tile-loaded').length > 0, null, { timeout: 10000 });
  if (!pageUrl.startsWith('file:')) ok(tileReferers.length && tileReferers.every((r) => /^https?:\/\/[^/]+\/$/.test(r)),
    'map tiles carry the page\'s origin as Referer, as OSM requires: ' + tileReferers[0]);
  await p.screenshot({ path: shotPrefix + '-map.png' });
  await p.click('#dlg-map [data-close]');

  // theme
  await p.selectOption('#theme', 'light');
  ok(await p.evaluate(() => document.documentElement.dataset.theme) === 'light', 'theme: light');
  await p.screenshot({ path: shotPrefix + '-light.png' });
  await p.selectOption('#theme', 'dark');
  ok(await p.evaluate(() => !document.documentElement.dataset.theme), 'theme: dark (the dashboard\'s)');

  await p.reload();
  ok(await p.inputValue('#f-priv') === '', 'private key not remembered without the checkbox');
  ok(await p.inputValue('#f-url') === SERVER && await p.inputValue('#f-name') === 'WebTester', 'URL and name remembered');
  const stored = await p.evaluate(() => JSON.stringify(localStorage));
  ok(!stored.includes(PRIV) && !stored.includes(token), 'neither key in localStorage');
  await p.fill('#f-priv', PRIV);
  await p.click('#login-go');
  await p.waitForSelector('#conn-dot.open', { timeout: 10000 });
  ok(await p.locator('#channel-list button').count() === 3, 'channels kept across reload');
  await p.click('#channel-list button:first-child');
  ok(await p.locator('.msg .text:text("hello from the browser")').count() === 1, 'history kept across reload');
  ok(await p.isHidden('#banner'), 'logging in again: already allowed to send');
  ok(await p.locator('#dm-list button:has-text("EchoBot")').count() === 1 && await p.locator('#room-list button').count() === 1,
    'DMs and rooms kept across reload');

  // saved login: with a passphrase the key is sealed; without one, it connects by itself
  await p.click('#logout');
  await p.check('#f-remember');
  await p.fill('#f-priv', PRIV);
  await p.fill('#f-pass', 'correct horse');
  await p.click('#login-go');
  await p.waitForSelector('#conn-dot.open', { timeout: 20000 });
  ok(!(await p.evaluate(() => JSON.stringify(localStorage))).includes(PRIV), 'with a passphrase, the saved key is sealed');
  await p.reload();
  ok(await p.isVisible('#unlock-box') && await p.isHidden('#priv-box'), 'reload: asks for the passphrase, not the key');
  await p.fill('#f-unlock', 'wrong');
  await p.click('#login-go');
  await p.waitForSelector('#login-error:not([hidden])', { timeout: 20000 });
  ok(/doesn't unlock/.test(await p.textContent('#login-error')), 'a wrong passphrase doesn\'t unlock');
  await p.fill('#f-unlock', 'correct horse');
  await p.click('#login-go');
  await p.waitForSelector('#conn-dot.open', { timeout: 20000 });
  ok(true, 'the right passphrase unlocks and connects');
  await p.click('#logout');
  await p.click('#unlock-other');
  await p.check('#f-remember');
  await p.fill('#f-priv', PRIV);
  await p.click('#login-go');
  await p.waitForSelector('#conn-dot.open', { timeout: 20000 });
  await p.reload();
  await p.waitForSelector('#conn-dot.open', { timeout: 20000 });
  ok(await p.isHidden('#login'), 'remembered without a passphrase: connects by itself');

  // away, then back: the server's backlog catches us up, read only
  await p.waitForTimeout(1500);                                            // (the cursor is saved)
  await p.click('#logout');
  inject('Public', 'Bob', 'missed while away');
  command('BOT_DM ' + PUB + ' are you there?');
  await p.waitForTimeout(2500);                                            // (kept: written about once a second)
  const sentFrames = [];
  p.on('websocket', (ws) => ws.on('framesent', (f) => sentFrames.push(String(f.payload))));
  await p.reload();
  await p.waitForSelector('#conn-dot.open', { timeout: 20000 });
  await p.waitForSelector('#toast:has-text("Caught up")', { timeout: 20000 });
  await p.click('#channel-list button:has-text("Public")');
  await p.waitForSelector('.msg:has(.text:text("missed while away")) .meta:has-text("while you were away")', { timeout: 10000 });
  ok(true, 'a channel message sent while we were away arrives on reconnect, marked so');
  await p.click('#dm-list button:has-text("EchoBot")');
  await p.waitForSelector('.msg .text:text("are you there?")', { timeout: 10000 });
  ok(await p.locator('.msg:has(.text:text("are you there?")) .meta:has-text("while you were away")').count() >= 1,
    'and a DM sent while we were away, from the backlog');
  const answered = sentFrames.map((f) => { try { return JSON.parse(f); } catch { return {}; } })
    .filter((m) => m.type === 'send').map((m) => (parseInt(m.raw.slice(0, 2), 16) >> 2) & 15).filter((t) => t === 3 || t === 8);
  ok(answered.length === 0, 'nothing answered for old packets (no ACKs or paths): ' + answered.length);

  ok(await admin('/api/v1/web/users/' + PUB + '/kick') === 200, 'admin kicks the key');
  await p.waitForSelector('#conn-dot.failed', { timeout: 10000 });
  ok(/admin disconnected/.test(await p.textContent('#banner')), 'kicked: ' + await p.textContent('#banner'));
  ok(await admin('/api/v1/web/users/' + PUB + '/ban', { name: 'WebTester' }) === 200, 'admin bans the key');
  const banned = await newPage(b);
  await banned.goto(pageUrl);
  await loginWith(banned);
  await banned.waitForSelector('#login-error:not([hidden])', { timeout: 10000 });
  ok(/banned/.test(await banned.textContent('#login-error')), 'banned key can\'t log in: ' + await banned.textContent('#login-error'));
  await admin('/api/v1/web/users/' + PUB + '/unban');

  // a reverse proxy that loses websockets: the login works, and the page says what became of the websocket
  for (const [mode, want, what] of [['strip', /without its Upgrade header/, 'a proxy dropping the Upgrade header'],
                                    ['drop', /never reached pyMeshRoom/, 'a proxy that doesn\'t pass websockets on']]) {
    const proxy = await startProxy(mode);
    // (a proxy's name has to be one the admin lists: else the server refuses logins signed for it)
    ok(await admin('/api/v1/web/settings', { web_hosts: ['127.0.0.1:' + proxy.address().port] }) === 200, 'admin allows the proxy\'s name');
    const pp = await newPage(b);
    await pp.goto(pageUrl);
    await loginWith(pp, { url: 'http://127.0.0.1:' + proxy.address().port });
    await pp.waitForSelector('#login-error:not([hidden])', { timeout: 15000 });
    ok(want.test(await pp.textContent('#login-error')), what + ': ' + await pp.textContent('#login-error'));
    await pp.context().close();
    proxy.close();
  }
  // all web sessions in use: the login says so, before any websocket
  const holder = await newPage(b);
  await holder.goto(pageUrl);
  await loginWith(holder, { priv: seed(), name: 'Holder' });
  await holder.waitForSelector('#conn-dot.open', { timeout: 10000 });
  const users = await (await fetch(SERVER + '/api/v1/web/users', { headers: { Cookie: cookie } })).json();
  ok(await admin('/api/v1/web/settings', { web_max_clients: users.connected }) === 200, 'admin caps web sessions at ' + users.connected);
  const full = await newPage(b);
  await full.goto(pageUrl);
  await loginWith(full, { priv: seed(), name: 'Late' });
  await full.waitForSelector('#login-error:not([hidden])', { timeout: 10000 });
  ok(/web sessions are in use/.test(await full.textContent('#login-error')), 'server full: ' + await full.textContent('#login-error'));
  await admin('/api/v1/web/settings', { web_max_clients: 32 });
  await full.context().close();
  await holder.context().close();

  // served by pyMeshRoom itself at /meshcore-web/: the server comes from the page's own address
  const served = await newPage(b);
  const res = await served.goto(SERVER + '/meshcore-web');
  ok(res.ok() && served.url() === SERVER + '/meshcore-web/', 'pyMeshRoom serves it at /meshcore-web/');
  ok(await served.isHidden('#url-box') && await served.textContent('#url-host') === '127.0.0.1:9101', 'served by the server: no URL to type');
  await loginWith(served, { url: null, name: 'SameOrigin' });
  await waitOpen(served);
  ok(true, 'logged in from the server\'s own page');
  ok(await served.evaluate(() => getComputedStyle(document.body).backgroundColor) === 'rgb(17, 20, 24)', 'the dashboard\'s look');
  await served.screenshot({ path: shotPrefix + '-served.png' });

  // a page password, set by the admin: the served page asks first; a standalone page asks when it logs in
  ok(await admin('/api/v1/web/settings', { page_password: 'open sesame' }) === 200, 'admin sets a page password');
  const locked = await newPage(b);
  await locked.goto(SERVER + '/meshcore-web/');
  ok(await locked.isVisible('input[name=password]') && await locked.locator('#login').count() === 0, 'the page asks for its password first');
  await locked.fill('input[name=password]', 'wrong');
  await locked.click('button[type=submit]');
  ok(/isn't the password/.test(await locked.textContent('body')), 'a wrong page password is refused');
  await locked.screenshot({ path: shotPrefix + '-locked.png' });
  await locked.fill('input[name=password]', 'open sesame');
  await locked.click('button[type=submit]');
  await locked.waitForSelector('#login:not([hidden])', { timeout: 10000 });
  await loginWith(locked, { url: null, name: 'Unlocked' });
  await waitOpen(locked);
  ok(true, 'the right page password opens the app, and logging in works');
  const standalone = await newPage(b);
  await standalone.goto(pageUrl);
  await loginWith(standalone, { name: 'Elsewhere' });
  await standalone.waitForSelector('#sitepw-box:not([hidden])', { timeout: 15000 });
  ok(/needs a password/.test(await standalone.textContent('#login-error')), 'a page elsewhere is asked for the server\'s page password');
  await standalone.fill('#f-sitepw', 'open sesame');
  await standalone.click('#login-go');
  await waitOpen(standalone);
  ok(true, 'with it, it logs in');
  ok(await admin('/api/v1/web/settings', { page_password: '' }) === 200, 'admin removes the page password');

  const mp = await newPage(b, { viewport: { width: 390, height: 780 }, isMobile: true, hasTouch: true });
  await mp.goto(pageUrl);
  await loginWith(mp, { name: 'Phone' });
  await mp.waitForSelector('#conn-dot.open', { timeout: 10000 });
  inject('Public', 'Bob', 'a longer message to see how wrapping looks on a narrow phone screen, with @[Phone] mentioned https://giphy.com/gifs/' + GIF_ID);
  await mp.waitForSelector('.msg .sender:text("Bob")', { timeout: 10000 });
  ok(await mp.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'no horizontal scroll on a phone');
  await mp.screenshot({ path: shotPrefix + '-phone.png' });

  const tx = execFileSync('python3', [H + '/readtx.py', W + '/dev.log', '#test', '00112233445566778899aabbccddeeff']).toString();
  ok(tx.includes("GRP Public 'WebTester: hello from the browser'"), 'the radio sent our Public message, readable by the Python client');
  ok(tx.includes("GRP 00112233445566778899aabbccddeeff 'WebTester: burst 4'"), 'the radio sent our private message, readable with the secret');
  ok(/ADVERT flood \w+ valid-sig WebTester/.test(tx), 'the radio sent our advert, with a valid signature');
  ok(tx.includes(wantReaction.replace('\n', '\\n')),                      // (readtx prints the line break as \n)
    'the radio sent our reaction, naming the message by its hash: ' + JSON.stringify(wantReaction));
  const sizes = execFileSync('python3', ['-c', 'import sys,os;sys.path.insert(0,os.path.join(os.environ["PYMESHROOM"],"client"));' +
    'from meshroom_kaas import Packet\nfor l in open(sys.argv[1]):\n  p = Packet.parse(bytes.fromhex(l[3:].strip())) if l.startswith("TX ") else None\n' +
    '  if p and p.ptype == 5 and p.is_flood: print((p.path_len >> 6) + 1)', W + '/dev.log']).toString().trim().split('\n');
  ok(sizes.length && sizes.every((n) => n === '2'), 'our channel floods collect 2-byte repeater ids by default: ' + [...new Set(sizes)].join(','));
  ok(tx.includes(wantReply), 'the radio sent our reply in MeshCore One\'s format: ' + wantReply);
  for (const pg of [p, banned, served, mp]) errors.push(...pg.errors);
  ok(errors.length === 0, 'no page errors' + (errors.length ? ': ' + errors.join(' | ') : ''));
})().catch(e => { console.log('FAIL', e.message); process.exitCode = 1; }).finally(() => b && b.close());
