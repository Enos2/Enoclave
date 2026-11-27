// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/tests/day4.mjs
// Purpose : End-to-end test for Day 4 using real HTTP calls and real Socket.IO
//           connections. Five sections, each check printing a green PASS or a
//           red FAIL (exit code 1 if anything fails).
//           1) Settings: defaults, validation, status change.
//           2) Presence: only MUTUAL contacts see each other; one-way contacts
//              do not; status changes and the privacy toggle propagate; closing
//              the last tab shows offline after the grace period.
//           3) Typing: blocked without a conversation, delivered once one
//              exists, silenced by the recipient's toggle, group delivery and
//              outsider rejection.
//           4) Read receipts: delivered to the sender, loadable over HTTP,
//              hidden and deleted when switched off, group receipts.
//           5) Encrypted files: validation, upload rules (wrong content type,
//              wrong size, wrong owner, double upload), byte-identical
//              download through a signed link, tampered or borrowed links,
//              access control for strangers, owners and removed group
//              members, deletion.
//           Takes about 45 seconds. Run it with the server running:
//             node .\tests\day4.mjs
//           It registers 4 users per run (limit: 20 per hour per network;
//           restart the server to reset that counter).
// =============================================================================
import crypto from 'node:crypto';
import { io } from 'socket.io-client';

const API = 'http://localhost:5000';
const ORIGIN = 'http://localhost:5173';
const KEY = { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'B'.repeat(43) };
const CT = 'QUJDREVGR0g=';
const IV = 'QUJDREVGR0hJSktM';

let passed = 0;
let failed = 0;

const check = (label, actual, expected) => {
  if (JSON.stringify(actual) === JSON.stringify(expected)) {
    passed += 1;
    console.log(`\x1b[32mPASS\x1b[0m  ${label}`);
  } else {
    failed += 1;
    console.log(`\x1b[31mFAIL\x1b[0m  ${label} (got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)})`);
  }
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wrap = (id) => ({ userId: id, wrappedKey: 'A'.repeat(64), iv: 'A'.repeat(16) });

async function http(user, method, path, body) {
  const res = await fetch(`${API}/api${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN, ...(user ? { Cookie: user.cookie } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* empty body */
  }
  return { status: res.status, json, res };
}

async function register(name) {
  const r = await http(null, 'POST', '/auth/register', { username: name, password: 'correct-horse-battery', publicKey: KEY });
  if (r.status !== 201) throw new Error(`register failed (${r.status}): ${JSON.stringify(r.json)}`);
  const cookie = r.res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
  return { id: r.json.user.id, cookie };
}

// Every event is recorded from the moment of creation, so nothing sent right after connecting is missed.
function connect(user) {
  return new Promise((resolve, reject) => {
    const socket = io(API, { transports: ['websocket'], extraHeaders: { Cookie: user.cookie, Origin: ORIGIN } });
    socket.log = [];
    socket.onAny((e, d) => socket.log.push({ e, d }));
    socket.on('connect', () => resolve(socket));
    socket.on('connect_error', reject);
  });
}

const emit = (socket, event, payload) => new Promise((resolve) => socket.emit(event, payload, resolve));

// Looks through events recorded since index "from"; resolves with the data or null after ms.
async function waitEvent(socket, name, { ms = 4000, from = 0, match = () => true } = {}) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const hit = socket.log.slice(from).find((x) => x.e === name && match(x.d));
    if (hit) return hit.d;
    await sleep(50);
  }
  return null;
}

async function put(user, id, body, type = 'application/octet-stream') {
  const res = await fetch(`${API}/api/files/${id}/content`, {
    method: 'PUT',
    headers: { 'Content-Type': type, Origin: ORIGIN, Cookie: user.cookie },
    body,
  });
  return res.status;
}

const n = Math.floor(Math.random() * 90000) + 10000;
const ann = await register(`ann${n}`);
const bob = await register(`bob${n}`);
const cat = await register(`cat${n}`);
const dan = await register(`dan${n}`);

console.log('\n-- Settings --');
{
  let r = await http(ann, 'GET', '/settings');
  check('defaults: presence on', r.json.settings.showPresence, true);
  check('defaults: status available', r.json.settings.status, 'available');
  check('empty update rejected (400)', (await http(ann, 'PUT', '/settings', {})).status, 400);
  check('invalid status rejected (400)', (await http(ann, 'PUT', '/settings', { status: 'invisible' })).status, 400);
  check('unknown field rejected (400)', (await http(ann, 'PUT', '/settings', { admin: true })).status, 400);
  r = await http(ann, 'PUT', '/settings', { status: 'focus' });
  check('status can be changed', r.json.settings.status, 'focus');
  await http(ann, 'PUT', '/settings', { status: 'available' });
}

console.log('\n-- Presence --');
await http(ann, 'POST', '/contacts', { userId: bob.id });
await http(bob, 'POST', '/contacts', { userId: ann.id });
await http(cat, 'POST', '/contacts', { userId: ann.id }); // one-way only
const annS = await connect(ann);
let bobS;
let catS;
{
  const snap = await waitEvent(annS, 'presence:snapshot');
  check('snapshot lists only the mutual contact, offline', snap?.peers.map((p) => [p.userId, p.online]), [[bob.id, false]]);

  bobS = await connect(bob);
  const up = await waitEvent(annS, 'presence:update', { match: (d) => d.userId === bob.id });
  check('mutual contact is told bob came online', [up?.online, up?.status], [true, 'available']);
  const bsnap = await waitEvent(bobS, 'presence:snapshot');
  check('bob sees ann online in his snapshot', bsnap?.peers.find((p) => p.userId === ann.id)?.online, true);

  catS = await connect(cat);
  check('one-way contact is not told cat is online',
    await waitEvent(annS, 'presence:update', { match: (d) => d.userId === cat.id, ms: 1500 }), null);
  check('one-way contact gets an empty snapshot', (await waitEvent(catS, 'presence:snapshot'))?.peers.length, 0);

  let mk = annS.log.length;
  await http(bob, 'PUT', '/settings', { status: 'focus' });
  const st = await waitEvent(annS, 'presence:update', { from: mk, match: (d) => d.userId === bob.id });
  check('status change reaches the contact', st?.status, 'focus');

  mk = annS.log.length;
  const mkB = bobS.log.length;
  await http(bob, 'PUT', '/settings', { showPresence: false });
  const hidden = await waitEvent(annS, 'presence:update', { from: mk, match: (d) => d.userId === bob.id });
  check('hiding presence shows bob offline to ann', hidden?.online, false);
  check('hiding presence also hides others from bob', (await waitEvent(bobS, 'presence:snapshot', { from: mkB }))?.peers.length, 0);

  mk = annS.log.length;
  await http(bob, 'PUT', '/settings', { showPresence: true, status: 'available' });
  const back = await waitEvent(annS, 'presence:update', { from: mk, match: (d) => d.userId === bob.id && d.online });
  check('turning presence back on shows bob online again', back?.online, true);

  mk = annS.log.length;
  bobS.close();
  const gone = await waitEvent(annS, 'presence:update', { from: mk, ms: 9000, match: (d) => d.userId === bob.id && !d.online });
  check('closing the last tab shows offline after the grace period', gone?.online, false);
}

console.log('\n-- Typing --');
let msgToBob;
let gid;
const danS = await connect(dan);
{
  bobS = await connect(bob);
  let mk = bobS.log.length;
  annS.emit('typing:set', { to: bob.id, typing: true });
  check('no typing signal without a conversation', await waitEvent(bobS, 'typing:update', { from: mk, ms: 1500 }), null);

  mk = bobS.log.length;
  check('message to bob is accepted', (await emit(annS, 'message:send', { to: bob.id, ciphertext: CT, iv: IV }))?.ok, true);
  msgToBob = await waitEvent(bobS, 'message:new', { from: mk });
  annS.emit('typing:set', { to: bob.id, typing: true });
  const tu = await waitEvent(bobS, 'typing:update', { from: mk, match: (d) => d.from === ann.id });
  check('typing is delivered once a conversation exists', tu?.typing, true);

  await http(bob, 'PUT', '/settings', { showTyping: false });
  mk = bobS.log.length;
  annS.emit('typing:set', { to: bob.id, typing: true });
  check('no typing signal while the recipient has typing off', await waitEvent(bobS, 'typing:update', { from: mk, ms: 1500 }), null);
  await http(bob, 'PUT', '/settings', { showTyping: true });

  const created = await http(ann, 'POST', '/groups', {
    name: 'Day 4 group',
    members: [bob.id, cat.id],
    envelopes: [wrap(ann.id), wrap(bob.id), wrap(cat.id)],
  });
  gid = created.json.group.id;
  mk = bobS.log.length;
  const mkC = catS.log.length;
  annS.emit('typing:set', { groupId: gid, typing: true });
  check('group typing reaches bob', (await waitEvent(bobS, 'typing:update', { from: mk, match: (d) => d.groupId === gid }))?.from, ann.id);
  check('group typing reaches cat', (await waitEvent(catS, 'typing:update', { from: mkC, match: (d) => d.groupId === gid }))?.from, ann.id);

  mk = bobS.log.length;
  danS.emit('typing:set', { groupId: gid, typing: true });
  check('an outsider cannot send group typing', await waitEvent(bobS, 'typing:update', { from: mk, match: (d) => d.from === dan.id, ms: 1500 }), null);
}

console.log('\n-- Read receipts --');
{
  let mk = annS.log.length;
  await emit(bobS, 'receipt:read', { peerId: ann.id, upTo: msgToBob.id });
  const rr = await waitEvent(annS, 'receipt:read', { from: mk });
  check('sender is told the message was read', [rr?.by, rr?.upTo], [bob.id, msgToBob.id]);
  const cur = await http(ann, 'GET', `/receipts/direct/${bob.id}`);
  check('the read cursor can be loaded over HTTP', typeof cur.json.theirs, 'string');

  await http(bob, 'PUT', '/settings', { readReceipts: false });
  const hidden = await http(ann, 'GET', `/receipts/direct/${bob.id}`);
  check('with receipts off the cursor is hidden', hidden.json.theirs, null);
  mk = annS.log.length;
  await emit(bobS, 'receipt:read', { peerId: ann.id, upTo: msgToBob.id });
  check('no receipt is sent while disabled', await waitEvent(annS, 'receipt:read', { from: mk, ms: 1500 }), null);
  await http(bob, 'PUT', '/settings', { readReceipts: true });
  const cleared = await http(ann, 'GET', `/receipts/direct/${bob.id}`);
  check('switching receipts off deleted the old cursor', cleared.json.theirs, null);

  const mkCat = catS.log.length;
  await emit(annS, 'group:send', { groupId: gid, epoch: 1, ciphertext: CT, iv: IV });
  const gm = await waitEvent(catS, 'group:message', { from: mkCat });
  mk = annS.log.length;
  await emit(catS, 'receipt:group_read', { groupId: gid, upTo: gm.id });
  check('group receipt reaches the sender', (await waitEvent(annS, 'receipt:group_read', { from: mk }))?.by, cat.id);
  const list = await http(ann, 'GET', `/receipts/group/${gid}`);
  check('group cursors list cat', list.json.members.map((m) => m.userId), [cat.id]);
  check('an outsider cannot read group cursors (404)', (await http(dan, 'GET', `/receipts/group/${gid}`)).status, 404);
}

console.log('\n-- Encrypted files --');
{
  const init = (u, body) => http(u, 'POST', '/files/init', body);
  check('both targets rejected (400)', (await init(ann, { kind: 'file', sizeBytes: 100, recipientId: bob.id, groupId: gid })).status, 400);
  check('no target rejected (400)', (await init(ann, { kind: 'file', sizeBytes: 100 })).status, 400);
  check('unknown field rejected (400)', (await init(ann, { kind: 'file', sizeBytes: 100, recipientId: bob.id, mime: 'x' })).status, 400);
  check('file over 25 MB rejected (400)', (await init(ann, { kind: 'file', sizeBytes: 30 * 1024 * 1024, recipientId: bob.id })).status, 400);
  check('voice note over 10 MB rejected (413)', (await init(ann, { kind: 'voice', sizeBytes: 11 * 1024 * 1024, recipientId: bob.id })).status, 413);
  check('unknown recipient gets 404', (await init(ann, { kind: 'file', sizeBytes: 100, recipientId: crypto.randomUUID() })).status, 404);
  check('outsider cannot upload to a group (404)', (await init(dan, { kind: 'file', sizeBytes: 100, groupId: gid })).status, 404);

  const bytes = crypto.randomBytes(1000);
  const created = await init(ann, { kind: 'file', sizeBytes: 1000, recipientId: bob.id });
  check('init succeeds (201)', created.status, 201);
  const id = created.json.file.id;

  check('wrong content type rejected (415)', await put(ann, id, bytes, 'text/plain'), 415);
  check('wrong size rejected (400)', await put(ann, id, bytes.subarray(0, 999)), 400);
  check('another user cannot upload to it (404)', await put(bob, id, bytes), 404);
  check('correct upload accepted (200)', await put(ann, id, bytes), 200);
  check('uploading twice is rejected (404)', await put(ann, id, bytes), 404);

  const link = await http(bob, 'GET', `/files/${id}/link`);
  check('recipient gets a download link', link.status, 200);
  const dl = await fetch(`${API}${link.json.url}`, { headers: { Origin: ORIGIN, Cookie: bob.cookie } });
  const got = Buffer.from(await dl.arrayBuffer());
  check('recipient downloads identical bytes', Buffer.compare(got, bytes), 0);
  check('download is a no-store binary', [dl.headers.get('cache-control'), dl.headers.get('content-type')], ['private, no-store', 'application/octet-stream']);

  const tampered = new URL(link.json.url, API);
  tampered.searchParams.set('s', 'A'.repeat(43));
  check('tampered signature rejected (403)', (await fetch(tampered, { headers: { Origin: ORIGIN, Cookie: bob.cookie } })).status, 403);
  check('link is bound to its user (403)', (await fetch(`${API}${link.json.url}`, { headers: { Origin: ORIGIN, Cookie: cat.cookie } })).status, 403);
  check('download without a session rejected (401)', (await fetch(`${API}${link.json.url}`, { headers: { Origin: ORIGIN } })).status, 401);
  check('stranger cannot get a link (404)', (await http(cat, 'GET', `/files/${id}/link`)).status, 404);
  check('owner can get a link', (await http(ann, 'GET', `/files/${id}/link`)).status, 200);

  check('recipient cannot delete the file (404)', (await http(bob, 'DELETE', `/files/${id}`)).status, 404);
  check('owner deletes the file (200)', (await http(ann, 'DELETE', `/files/${id}`)).status, 200);
  check('deleted file has no link (404)', (await http(bob, 'GET', `/files/${id}/link`)).status, 404);

  const g = await init(ann, { kind: 'voice', sizeBytes: 500, groupId: gid });
  const gidFile = g.json.file.id;
  check('group voice note uploads (200)', await put(ann, gidFile, crypto.randomBytes(500)), 200);
  check('group member gets a link (200)', (await http(bob, 'GET', `/files/${gidFile}/link`)).status, 200);
  check('non-member gets 404', (await http(dan, 'GET', `/files/${gidFile}/link`)).status, 404);
  await http(bob, 'POST', `/groups/${gid}/leave`);
  check('after leaving the group, access is gone (404)', (await http(bob, 'GET', `/files/${gidFile}/link`)).status, 404);
}

for (const s of [annS, bobS, catS, danS]) s.close();
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

// File: server/tests/day4.mjs
// End of file