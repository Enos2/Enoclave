// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/tests/day8.mjs
// Purpose : End-to-end test for Day 8 with real HTTP calls and real Socket.IO
//           connections; every check prints a green PASS or red FAIL (exit code
//           1 if anything fails). Three sections.
//           EDITS (direct): invalid ciphertext and unknown fields rejected; the
//           recipient, strangers and unknown ids get 404; the sender's edit is
//           pushed live to the recipient AND the sender's own devices and shows
//           in history with editedAt; the 10-edit limit; the 15-minute window
//           (the test back-dates a message in the database); a burning message
//           cannot be edited; if you blocked them you get 409; if THEY blocked
//           you it looks like success but the message is unchanged and they
//           receive nothing.
//           EDITS (group): wrong key epoch rejected, other members and outsiders
//           get 404, the sender's edit reaches the members and shows in history.
//           PINS (direct): outsiders get 404; either person can pin; live
//           'pin:update'; pinning twice is harmless; the limit of 3 per
//           conversation (409); listing includes ciphertext; unpinning frees a
//           slot; block rules (409 / silent no-op).
//           PINS (group): outsiders 404, ordinary members 403, admins can pin,
//           the limit of 5, listing, and a pin disappearing when its message is
//           deleted. ACCOUNT: the checkup warns when two-factor is off, and the
//           data export includes reactions, two-factor status, pin count and
//           edit times without secrets. Needs the server running with
//           TEST_MODE=1:  node .\tests\day8.mjs
//           Takes 3-5 minutes on a slow database connection (many requests).
// =============================================================================
import crypto from 'node:crypto';
import { io } from 'socket.io-client';
import { query, closePool } from '../src/config/db.js';

const API = 'http://localhost:5000';
const ORIGIN = 'http://localhost:5173';
const KEY = { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'B'.repeat(43) };
const CT = 'QUJDREVGR0g=';
const CT2 = Buffer.from('EDITED-CIPHERTEXT').toString('base64');
const IV = 'QUJDREVGR0hJSktM';
const PASSWORD = 'correct-horse-battery';

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
  const r = await http(null, 'POST', '/auth/register', { username: name, password: PASSWORD, publicKey: KEY });
  if (r.status !== 201) throw new Error(`register failed (${r.status}): ${JSON.stringify(r.json)}`);
  const cookie = r.res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
  return { id: r.json.user.id, cookie, name };
}

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

async function waitEvent(socket, name, { ms = 5000, from = 0, match = () => true } = {}) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const hit = socket.log.slice(from).find((x) => x.e === name && match(x.d));
    if (hit) return hit.d;
    await sleep(50);
  }
  return null;
}

async function sendDirect(fromS, to, toS, extra = {}) {
  const mk = toS.log.length;
  await emit(fromS, 'message:send', { to: to.id, ciphertext: CT, iv: IV, ...extra });
  return waitEvent(toS, 'message:new', { from: mk });
}

async function sendGroup(fromS, groupId, toS) {
  const mk = toS.log.length;
  await emit(fromS, 'group:send', { groupId, epoch: 1, ciphertext: CT, iv: IV });
  return waitEvent(toS, 'group:message', { from: mk });
}

const n = Math.floor(Math.random() * 90000) + 10000;
const ann = await register(`ann${n}`);
const bob = await register(`bob${n}`);
const cat = await register(`cat${n}`);
const dan = await register(`dan${n}`);
const annS = await connect(ann);
const bobS = await connect(bob);
const catS = await connect(cat);
const danS = await connect(dan);

const editDirect = (u, id, body) => http(u, 'PUT', `/edits/direct/${id}`, body);
const editGroup = (u, id, body) => http(u, 'PUT', `/edits/group/${id}`, body);
const good = { ciphertext: CT2, iv: IV };

console.log('\n-- Edits (direct) --');
const msg = await sendDirect(annS, bob, bobS);
const m2 = await sendDirect(annS, bob, bobS);
{
  check('invalid ciphertext is rejected (400)', (await editDirect(ann, msg.id, { ciphertext: '***', iv: IV })).status, 400);
  check('unknown field is rejected (400)', (await editDirect(ann, msg.id, { ...good, admin: true })).status, 400);
  check('the recipient cannot edit the sender message (404)', (await editDirect(bob, msg.id, good)).status, 404);
  check('a stranger cannot edit it (404)', (await editDirect(cat, msg.id, good)).status, 404);
  check('an unknown message gives 404', (await editDirect(ann, crypto.randomUUID(), good)).status, 404);

  const mkB = bobS.log.length;
  const mkA = annS.log.length;
  const ok = await editDirect(ann, msg.id, good);
  check('the sender edits (200)', ok.status, 200);
  const ev = await waitEvent(bobS, 'message:edited', { from: mkB });
  check('the recipient is told live with the new ciphertext', [ev?.id, ev?.ciphertext], [msg.id, CT2]);
  check('the sender devices are told too', (await waitEvent(annS, 'message:edited', { from: mkA }))?.id, msg.id);
  const h = (await http(bob, 'GET', `/messages/${ann.id}`)).json.messages.find((m) => m.id === msg.id);
  check('history shows the new ciphertext and editedAt', [h.ciphertext, typeof h.editedAt], [CT2, 'string']);

  let last = 0;
  for (let i = 0; i < 9; i += 1) last = (await editDirect(ann, msg.id, good)).status;
  check('ten edits are allowed in total', last, 200);
  check('the eleventh edit is refused (409)', (await editDirect(ann, msg.id, good)).status, 409);

  await query("UPDATE messages SET created_at = now() - interval '20 minutes' WHERE id = $1", [m2.id]);
  check('a message older than 15 minutes cannot be edited (409)', (await editDirect(ann, m2.id, good)).status, 409);

  const burn = await sendDirect(annS, bob, bobS, { burnAfterReadSeconds: 30 });
  check('a burn message can be edited before it is read (200)', (await editDirect(ann, burn.id, good)).status, 200);
  const mkBurn = annS.log.length;
  await emit(bobS, 'message:read', { id: burn.id });
  await waitEvent(annS, 'message:burning', { from: mkBurn });
  check('a message whose burn timer started cannot be edited (409)', (await editDirect(ann, burn.id, good)).status, 409);

  const toCat = await sendDirect(annS, cat, catS);
  await http(ann, 'POST', '/blocks', { userId: cat.id });
  check('editing a message to someone you blocked is refused (409)', (await editDirect(ann, toCat.id, good)).status, 409);
  await http(ann, 'DELETE', `/blocks/${cat.id}`);

  const toDan = await sendDirect(annS, dan, danS);
  await http(dan, 'POST', '/blocks', { userId: ann.id });
  const mkD = danS.log.length;
  check('when they blocked you the edit looks like success (200)', (await editDirect(ann, toDan.id, good)).status, 200);
  const seen = (await http(dan, 'GET', `/messages/${ann.id}`)).json.messages.find((m) => m.id === toDan.id);
  check('...but the message is unchanged', [seen.ciphertext, seen.editedAt], [CT, null]);
  check('...and they received nothing', await waitEvent(danS, 'message:edited', { from: mkD, ms: 1500 }), null);
  await http(dan, 'DELETE', `/blocks/${ann.id}`);
}

console.log('\n-- Edits (group) --');
let gid;
let gm;
{
  gid = (await http(ann, 'POST', '/groups', { name: 'Day 8 group', members: [bob.id, cat.id], envelopes: [wrap(ann.id), wrap(bob.id), wrap(cat.id)] })).json.group.id;
  gm = await sendGroup(annS, gid, bobS);

  check('a wrong key epoch is rejected (409)', (await editGroup(ann, gm.id, { epoch: 2, ...good })).status, 409);
  check('another member cannot edit it (404)', (await editGroup(bob, gm.id, { epoch: 1, ...good })).status, 404);
  check('an outsider cannot edit it (404)', (await editGroup(dan, gm.id, { epoch: 1, ...good })).status, 404);

  const mkC = catS.log.length;
  check('the sender edits (200)', (await editGroup(ann, gm.id, { epoch: 1, ...good })).status, 200);
  const ev = await waitEvent(catS, 'group:message:edited', { from: mkC });
  check('members are told live', [ev?.id, ev?.ciphertext, ev?.groupId], [gm.id, CT2, gid]);
  const h = (await http(bob, 'GET', `/groups/${gid}/messages`)).json.messages.find((m) => m.id === gm.id);
  check('group history shows the edit', [h.ciphertext, typeof h.editedAt], [CT2, 'string']);
}

console.log('\n-- Pins (direct) --');
{
  const m6 = await sendDirect(annS, bob, bobS);
  const m7 = await sendDirect(annS, bob, bobS);
  const pin = (u, kind, id) => http(u, 'PUT', `/pins/${kind}/${id}`);
  const unpin = (u, kind, id) => http(u, 'DELETE', `/pins/${kind}/${id}`);

  check('a stranger cannot pin (404)', (await pin(cat, 'direct', msg.id)).status, 404);
  const mk = annS.log.length;
  check('the recipient pins (200)', (await pin(bob, 'direct', msg.id)).status, 200);
  const ev = await waitEvent(annS, 'pin:update', { from: mk });
  check('the other person is told live', [ev?.kind, ev?.messageId, ev?.pinned, ev?.by], ['direct', msg.id, true, bob.id]);
  check('the sender can pin too (200)', (await pin(ann, 'direct', m2.id)).status, 200);
  check('pinning twice is harmless (200)', (await pin(ann, 'direct', m2.id)).status, 200);
  check('a third pin works (200)', (await pin(ann, 'direct', m6.id)).status, 200);
  check('a fourth pin is refused (409)', (await pin(ann, 'direct', m7.id)).status, 409);

  const list = await http(bob, 'GET', `/pins/conversation/${ann.id}`);
  check('the conversation has 3 pins', list.json.pins.length, 3);
  check('pins include the ciphertext', list.json.pins.every((p) => typeof p.message.ciphertext === 'string'), true);

  const mk2 = bobS.log.length;
  check('unpinning works (200)', (await unpin(ann, 'direct', m6.id)).status, 200);
  check('the unpin is announced', (await waitEvent(bobS, 'pin:update', { from: mk2 }))?.pinned, false);
  check('a freed slot can be used (200)', (await pin(ann, 'direct', m7.id)).status, 200);

  const toCat = await sendDirect(annS, cat, catS);
  await http(ann, 'POST', '/blocks', { userId: cat.id });
  check('pinning in a chat with someone you blocked is refused (409)', (await pin(ann, 'direct', toCat.id)).status, 409);
  await http(ann, 'DELETE', `/blocks/${cat.id}`);

  const fromDan = await sendDirect(danS, ann, annS);
  await http(dan, 'POST', '/blocks', { userId: ann.id });
  check('when they blocked you it looks like success (200)', (await pin(ann, 'direct', fromDan.id)).status, 200);
  check('...but nothing was pinned for them', (await http(dan, 'GET', `/pins/conversation/${ann.id}`)).json.pins.length, 0);
}

console.log('\n-- Pins (group) --');
{
  const pin = (u, id) => http(u, 'PUT', `/pins/group/${id}`);
  check('an outsider cannot pin (404)', (await pin(dan, gm.id)).status, 404);
  check('an ordinary member cannot pin (403)', (await pin(bob, gm.id)).status, 403);
  const mk = catS.log.length;
  check('an admin pins (200)', (await pin(ann, gm.id)).status, 200);
  const ev = await waitEvent(catS, 'pin:update', { from: mk });
  check('members are told live', [ev?.kind, ev?.groupId, ev?.pinned], ['group', gid, true]);
  check('a member can list the pins', (await http(cat, 'GET', `/pins/groups/${gid}`)).json.pins.length, 1);
  check('an outsider cannot list pins (404)', (await http(dan, 'GET', `/pins/groups/${gid}`)).status, 404);

  const extra = [];
  for (let i = 0; i < 5; i += 1) extra.push(await sendGroup(annS, gid, bobS));
  for (let i = 0; i < 4; i += 1) await pin(ann, extra[i].id);
  check('a sixth pin is refused (409)', (await pin(ann, extra[4].id)).status, 409);
  check('five pins are listed', (await http(ann, 'GET', `/pins/groups/${gid}`)).json.pins.length, 5);

  await http(ann, 'DELETE', `/pins/group/${extra[0].id}`);
  check('after unpinning, another message can be pinned (200)', (await pin(ann, extra[4].id)).status, 200);

  await http(ann, 'DELETE', `/groups/${gid}/messages/${extra[1].id}`);
  const after = (await http(ann, 'GET', `/pins/groups/${gid}`)).json.pins;
  check('deleting a message removes its pin', after.some((p) => p.messageId === extra[1].id), false);
  check('four pins remain', after.length, 4);
}

console.log('\n-- Account additions --');
{
  const sec = await http(ann, 'GET', '/account/security');
  check('the checkup warns that two-factor is off', sec.json.checks.find((c) => c.id === 'two_factor')?.status, 'warn');

  await http(ann, 'PUT', `/reactions/direct/${msg.id}`, { reaction: 'heart' });
  const exp = await fetch(`${API}/api/account/export`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN, Cookie: ann.cookie },
    body: JSON.stringify({ password: PASSWORD }),
  });
  const text = await exp.text();
  const data = JSON.parse(text);
  check('export succeeds (200)', exp.status, 200);
  check('export includes the reactions given', data.reactionsGiven.some((r) => r.reaction === 'heart'), true);
  check('export shows two-factor as off', data.twoFactor.enabled, false);
  check('export counts the pins created', data.pinsCreated >= 1, true);
  check('export shows edit times', Boolean(data.directMessages.find((m) => m.id === msg.id)?.edited_at), true);
  check('export never contains secrets', [/password_hash/i, /secret_enc/i, /code_hash/i].some((r) => r.test(text)), false);
}

for (const s of [annS, bobS, catS, danS]) s.close();
await closePool();
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

// File: server/tests/day8.mjs
// End of file