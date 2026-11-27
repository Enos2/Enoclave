// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/tests/day3b.mjs
// Purpose : End-to-end test for Day 3B, using real HTTP calls and real
//           Socket.IO connections (so the realtime code is exercised for
//           real). It checks: direct burn-on-read (the timer does not start
//           until the RECIPIENT reads; the sender cannot start it; both sides
//           are told; the message disappears after the countdown); group
//           burn-on-read (the timer waits for EVERY member, then starts); a
//           non-member cannot post to a group; self-destruct rooms (members
//           cannot set a lifespan, outsiders get 404, out-of-range values are
//           rejected, an admin can set one, members see the expiry, the room
//           is destroyed on time and members are told). Prints a green PASS
//           or red FAIL per check and exits with code 1 if anything fails.
//           It takes about 50 seconds because it waits for real timers.
//           Run it with the server running:  node .\tests\day3b.mjs
//           Note: each run registers 4 users and registration is limited to
//           20 per hour per network; restart the server to reset the counter.
// =============================================================================
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
  const r = await http(null, 'POST', '/auth/register', {
    username: name,
    password: 'correct-horse-battery',
    publicKey: KEY,
  });
  if (r.status !== 201) throw new Error(`register failed (${r.status}): ${JSON.stringify(r.json)}`);
  const cookie = r.res.headers
    .getSetCookie()
    .map((c) => c.split(';')[0])
    .join('; ');
  return { id: r.json.user.id, cookie };
}

function connect(user) {
  return new Promise((resolve, reject) => {
    const socket = io(API, { transports: ['websocket'], extraHeaders: { Cookie: user.cookie, Origin: ORIGIN } });
    socket.on('connect', () => resolve(socket));
    socket.on('connect_error', reject);
  });
}

const emit = (socket, event, payload) => new Promise((resolve) => socket.emit(event, payload, resolve));

// Resolves with the event data, or null if nothing arrives within ms.
const waitFor = (socket, event, ms = 5000) =>
  new Promise((resolve) => {
    const onEvent = (data) => {
      clearTimeout(timer);
      resolve(data);
    };
    const timer = setTimeout(() => {
      socket.off(event, onEvent);
      resolve(null);
    }, ms);
    socket.once(event, onEvent);
  });

const n = Math.floor(Math.random() * 90000) + 10000;
const ann = await register(`ann${n}`);
const bob = await register(`bob${n}`);
const cat = await register(`cat${n}`);
const dan = await register(`dan${n}`);
const annS = await connect(ann);
const bobS = await connect(bob);
const catS = await connect(cat);
const danS = await connect(dan);

console.log('\n-- Direct burn-on-read --');
{
  const gotNew = waitFor(bobS, 'message:new');
  const sent = await emit(annS, 'message:send', { to: bob.id, ciphertext: CT, iv: IV, burnAfterReadSeconds: 3 });
  check('burn message is accepted', sent?.ok, true);
  const msg = await gotNew;
  check('message carries the burn setting', msg?.burnAfterReadSeconds, 3);
  check('timer has not started before reading', msg?.expiresAt, null);

  const senderTry = waitFor(annS, 'message:burning', 1500);
  await emit(annS, 'message:read', { id: msg.id });
  check('sender cannot start the burn timer', await senderTry, null);

  const toSender = waitFor(annS, 'message:burning');
  const toReader = waitFor(bobS, 'message:burning');
  await emit(bobS, 'message:read', { id: msg.id });
  check('recipient reading starts the timer', typeof (await toReader)?.expiresAt, 'string');
  check('sender is told the timer started', (await toSender)?.id, msg.id);

  let hist = await http(bob, 'GET', `/messages/${ann.id}`);
  check('message is still visible during the countdown', hist.json.messages.some((m) => m.id === msg.id), true);
  await sleep(4500);
  hist = await http(bob, 'GET', `/messages/${ann.id}`);
  check('message is gone after the countdown', hist.json.messages.some((m) => m.id === msg.id), false);
}

console.log('\n-- Group burn-on-read --');
{
  const created = await http(ann, 'POST', '/groups', {
    name: 'Burn test',
    members: [bob.id, cat.id],
    envelopes: [wrap(ann.id), wrap(bob.id), wrap(cat.id)],
  });
  const gid = created.json.group.id;

  const atBob = waitFor(bobS, 'group:message');
  const atCat = waitFor(catS, 'group:message');
  const sent = await emit(annS, 'group:send', { groupId: gid, epoch: 1, ciphertext: CT, iv: IV, burnAfterReadSeconds: 3 });
  check('group burn message is accepted', sent?.ok, true);
  const msg = await atBob;
  await atCat;

  const early = waitFor(annS, 'group:burning', 1500);
  await emit(bobS, 'group:read', { groupId: gid, id: msg.id });
  check('timer waits until every member has read', await early, null);

  const started = waitFor(annS, 'group:burning');
  await emit(catS, 'group:read', { groupId: gid, id: msg.id });
  check('timer starts when the last member reads', typeof (await started)?.expiresAt, 'string');

  await sleep(4500);
  const hist = await http(bob, 'GET', `/groups/${gid}/messages`);
  check('group message is gone after the countdown', hist.json.messages.length, 0);

  const outsider = await emit(danS, 'group:send', { groupId: gid, epoch: 1, ciphertext: CT, iv: IV });
  check('non-member cannot post to the group', outsider?.ok, false);
}

console.log('\n-- Self-destruct rooms --');
{
  const created = await http(ann, 'POST', '/groups', {
    name: 'Room test',
    members: [bob.id],
    envelopes: [wrap(ann.id), wrap(bob.id)],
  });
  const rid = created.json.group.id;
  const url = `/rooms/${rid}/lifespan`;

  check('member cannot set a lifespan (403)', (await http(bob, 'PUT', url, { lifespanSeconds: 60 })).status, 403);
  check('outsider gets 404', (await http(dan, 'PUT', url, { lifespanSeconds: 60 })).status, 404);
  check('too short a lifespan is rejected (400)', (await http(ann, 'PUT', url, { lifespanSeconds: 1 })).status, 400);
  check('admin sets a 10 second lifespan (200)', (await http(ann, 'PUT', url, { lifespanSeconds: 10 })).status, 200);

  const info = await http(bob, 'GET', `/rooms/${rid}`);
  check('member can see the expiry time', typeof info.json.room.expiresAt, 'string');

  const destroyed = await waitFor(bobS, 'group:destroyed', 30000);
  check('members are told the room was destroyed', destroyed?.groupId, rid);
  check('destroyed room is gone (404)', (await http(ann, 'GET', `/groups/${rid}`)).status, 404);
}

for (const s of [annS, bobS, catS, danS]) s.close();
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

// File: server/tests/day3b.mjs
// End of file