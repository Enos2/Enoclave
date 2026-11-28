// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/tests/day6.mjs
// Purpose : End-to-end test for Day 6 with real HTTP calls and real Socket.IO
//           connections; every check prints a green PASS or red FAIL (exit code
//           1 if anything fails). Three sections.
//           ACCOUNT: passphrase change validation, success, the OTHER device
//           being signed out while this one stays signed in, old/new
//           passphrase behaviour, the per-user lockout after 5 wrong attempts
//           (even with the right passphrase afterwards), the security
//           checkup, and the data export (wrong passphrase refused, attachment
//           headers, contains the sent ciphertext, never contains a password
//           hash or the passphrase).
//           SCHEDULED MESSAGES: time-range and recipient validation, blocked
//           recipients, listing WITHOUT ciphertext, cancelling (only by the
//           sender), delivery (never before the scheduled time, judged by the
//           server's own timestamps so slow networks cannot break the test;
//           the recipient gets it with its burn setting intact and the sender
//           gets a delivered notification), silent drop when the recipient has
//           blocked the sender, and the queue draining completely afterwards.
//           CHAT PREFERENCES: defaults, pin/archive/mute/default-timer,
//           validation, the 5-pin limit, group membership checks, live sync to
//           the user's devices, and reset-to-default removing the row.
//           Takes up to about 90 seconds on a slow database connection (it
//           waits for real delivery timers). Needs the server running with
//           TEST_MODE=1:  node .\tests\day6.mjs
// =============================================================================
import crypto from 'node:crypto';
import { io } from 'socket.io-client';

const API = 'http://localhost:5000';
const ORIGIN = 'http://localhost:5173';
const KEY = { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'B'.repeat(43) };
const CT = 'QUJDREVGR0g=';
const IV = 'QUJDREVGR0hJSktM';
const PASSWORD = 'correct-horse-battery';
const NEWPW = 'a-much-better-passphrase';

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
const inSeconds = (s) => new Date(Date.now() + s * 1000).toISOString();

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

const cookieOf = (res) => res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');

async function register(name) {
  const r = await http(null, 'POST', '/auth/register', { username: name, password: PASSWORD, publicKey: KEY });
  if (r.status !== 201) throw new Error(`register failed (${r.status}): ${JSON.stringify(r.json)}`);
  return { id: r.json.user.id, cookie: cookieOf(r.res), name };
}

async function login(name, password) {
  const r = await http(null, 'POST', '/auth/login', { username: name, password });
  return { status: r.status, cookie: r.status === 200 ? cookieOf(r.res) : null };
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

async function waitEvent(socket, name, { ms = 4000, from = 0, match = () => true } = {}) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const hit = socket.log.slice(from).find((x) => x.e === name && match(x.d));
    if (hit) return hit.d;
    await sleep(50);
  }
  return null;
}

const n = Math.floor(Math.random() * 90000) + 10000;
const ann = await register(`ann${n}`);
const bob = await register(`bob${n}`);
const cat = await register(`cat${n}`);
const dan = await register(`dan${n}`);
const eve = await register(`eve${n}`);
const annS = await connect(ann);
const bobS = await connect(bob);
const danS = await connect(dan);

console.log('\n-- Account --');
{
  const pw = await register(`pw${n}`);
  const second = await login(pw.name, PASSWORD);
  const url = '/account/password';

  check('wrong current passphrase is rejected (401)', (await http(pw, 'PUT', url, { currentPassword: 'not-the-password', newPassword: NEWPW })).status, 401);
  check('new passphrase equal to the old one is rejected (400)', (await http(pw, 'PUT', url, { currentPassword: PASSWORD, newPassword: PASSWORD })).status, 400);
  check('too-short new passphrase is rejected (400)', (await http(pw, 'PUT', url, { currentPassword: PASSWORD, newPassword: 'short' })).status, 400);
  check('unknown field is rejected (400)', (await http(pw, 'PUT', url, { currentPassword: PASSWORD, newPassword: NEWPW, admin: true })).status, 400);

  const changed = await http(pw, 'PUT', url, { currentPassword: PASSWORD, newPassword: NEWPW });
  check('passphrase changes (200)', changed.status, 200);
  check('exactly one other device was signed out', changed.json.otherSessionsRevoked, 1);
  check("the other device's session stops working (401)", (await http({ cookie: second.cookie }, 'GET', '/auth/me')).status, 401);
  check('this device stays signed in (200)', (await http(pw, 'GET', '/auth/me')).status, 200);
  check('the old passphrase no longer works (401)', (await login(pw.name, PASSWORD)).status, 401);
  check('the new passphrase works (200)', (await login(pw.name, NEWPW)).status, 200);

  const lk = await register(`lk${n}`);
  const wrong = [];
  for (let i = 0; i < 5; i += 1) {
    wrong.push((await http(lk, 'PUT', url, { currentPassword: 'wrong-wrong-1', newPassword: NEWPW })).status);
  }
  check('five wrong attempts all give 401', wrong, [401, 401, 401, 401, 401]);
  check('after that the user is locked out, even with the right passphrase (429)', (await http(lk, 'PUT', url, { currentPassword: PASSWORD, newPassword: NEWPW })).status, 429);

  const sec = await http(pw, 'GET', '/account/security');
  check('the checkup returns a score from 0 to 100', typeof sec.json.score === 'number' && sec.json.score >= 0 && sec.json.score <= 100, true);
  check('the checkup includes the devices check', sec.json.checks.some((c) => c.id === 'sessions'), true);
  check('the checkup does not leak internal penalty values', sec.json.checks.some((c) => 'penalty' in c), false);

  await emit(annS, 'message:send', { to: bob.id, ciphertext: CT, iv: IV });
  check('export with a wrong passphrase is rejected (401)', (await http(ann, 'POST', '/account/export', { password: 'nope-nope-nope' })).status, 401);
  const exp = await fetch(`${API}/api/account/export`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN, Cookie: ann.cookie },
    body: JSON.stringify({ password: PASSWORD }),
  });
  const text = await exp.text();
  check('export succeeds (200)', exp.status, 200);
  check('export is a no-store attachment', [exp.headers.get('cache-control'), exp.headers.get('content-disposition')?.startsWith('attachment')], ['no-store', true]);
  const data = JSON.parse(text);
  check('export contains the profile', data.profile.username, ann.name);
  check('export contains the sent message as ciphertext', data.directMessages.some((m) => m.ciphertext === CT), true);
  check('export never contains a password hash or the passphrase', [/password_hash/i, /passwordHash/, new RegExp(PASSWORD)].some((r) => r.test(text)), false);
}

console.log('\n-- Scheduled messages --');
{
  const body = (extra = {}) => ({ to: bob.id, ciphertext: CT, iv: IV, deliverAt: inSeconds(12), ...extra });

  check('delivery in 2 seconds is rejected (400)', (await http(ann, 'POST', '/scheduled', body({ deliverAt: inSeconds(2) }))).status, 400);
  check('delivery in 40 days is rejected (400)', (await http(ann, 'POST', '/scheduled', body({ deliverAt: inSeconds(40 * 86400) }))).status, 400);
  check('a time without timezone is rejected (400)', (await http(ann, 'POST', '/scheduled', body({ deliverAt: '2030-01-01T10:00:00' }))).status, 400);
  check('scheduling to yourself is rejected (400)', (await http(ann, 'POST', '/scheduled', body({ to: ann.id }))).status, 400);
  check('unknown recipient gives 404', (await http(ann, 'POST', '/scheduled', body({ to: crypto.randomUUID() }))).status, 404);
  check('unknown field is rejected (400)', (await http(ann, 'POST', '/scheduled', body({ admin: true }))).status, 400);

  await http(dan, 'POST', '/blocks', { userId: ann.id });
  await http(ann, 'POST', '/blocks', { userId: eve.id });
  check('scheduling to someone you blocked gives 409', (await http(ann, 'POST', '/scheduled', body({ to: eve.id }))).status, 409);

  const mkBob = bobS.log.length;
  const mkDan = danS.log.length;
  const mkAnn = annS.log.length;
  const s1 = await http(ann, 'POST', '/scheduled', body({ burnAfterReadSeconds: 30 }));
  const s2 = await http(ann, 'POST', '/scheduled', body({ to: dan.id }));
  const s3 = await http(ann, 'POST', '/scheduled', body({ deliverAt: inSeconds(3600) }));
  check('scheduling succeeds (201)', [s1.status, s2.status, s3.status], [201, 201, 201]);

  const list = await http(ann, 'GET', '/scheduled');
  check('the sender sees 3 pending messages', list.json.scheduled.length, 3);
  check('the list never includes ciphertext', JSON.stringify(list.json).includes(CT), false);
  check('another user cannot cancel it (404)', (await http(bob, 'DELETE', `/scheduled/${s3.json.scheduled.id}`)).status, 404);
  check('the sender cancels one (200)', (await http(ann, 'DELETE', `/scheduled/${s3.json.scheduled.id}`)).status, 200);
  check('cancelling twice gives 404', (await http(ann, 'DELETE', `/scheduled/${s3.json.scheduled.id}`)).status, 404);

  const delivered = await waitEvent(bobS, 'message:new', { from: mkBob, ms: 60000 });
  check('the recipient receives the message', delivered?.from, ann.id);
  check(
    'it was not delivered before its scheduled time (server timestamps)',
    Date.parse(delivered?.createdAt) >= Date.parse(s1.json.scheduled.deliverAt),
    true
  );
  check('the burn setting survives delivery', delivered?.burnAfterReadSeconds, 30);
  const note = await waitEvent(annS, 'scheduled:delivered', { from: mkAnn });
  check('the sender is told it was delivered', note?.id, s1.json.scheduled.id);
  check('the message is in the recipient history', (await http(bob, 'GET', `/messages/${ann.id}`)).json.messages.some((m) => m.id === delivered?.id), true);

  let left = 1;
  for (let i = 0; i < 40 && left > 0; i += 1) {
    left = (await http(ann, 'GET', '/scheduled')).json.scheduled.length;
    if (left > 0) await sleep(1500);
  }
  check('the queue is empty afterwards', left, 0);
  check('a recipient who blocked the sender receives nothing', danS.log.slice(mkDan).some((x) => x.e === 'message:new'), false);
  check('the blocked sender gets no failure event', annS.log.slice(mkAnn).some((x) => x.e === 'scheduled:failed'), false);
}

console.log('\n-- Chat preferences --');
{
  const g1 = (await http(ann, 'POST', '/groups', { name: 'Prefs one', members: [bob.id], envelopes: [wrap(ann.id), wrap(bob.id)] })).json.group.id;
  const g2 = (await http(ann, 'POST', '/groups', { name: 'Prefs two', members: [bob.id], envelopes: [wrap(ann.id), wrap(bob.id)] })).json.group.id;
  const direct = (id, body) => http(ann, 'PUT', `/chats/prefs/direct/${id}`, body);
  const group = (id, body) => http(ann, 'PUT', `/chats/prefs/group/${id}`, body);

  check('no preferences by default', (await http(ann, 'GET', '/chats/prefs')).json.prefs, []);

  const mk = annS.log.length;
  const pinned = await direct(bob.id, { pinned: true });
  check('pin a chat (200)', pinned.json.prefs.pinned, true);
  check('the change is pushed to the user devices', (await waitEvent(annS, 'prefs:updated', { from: mk }))?.targetId, bob.id);

  const muted = await direct(bob.id, { archived: true, mutedUntil: inSeconds(3600), defaultTtlSeconds: 3600 });
  check('archive, mute and a default timer are stored', [muted.json.prefs.archived, typeof muted.json.prefs.mutedUntil, muted.json.prefs.defaultTtlSeconds], [true, 'string', 3600]);
  check('a mute time in the past is rejected (400)', (await direct(bob.id, { mutedUntil: inSeconds(-60) })).status, 400);
  check('a 4 second default timer is rejected (400)', (await direct(bob.id, { defaultTtlSeconds: 4 })).status, 400);
  check('unknown field is rejected (400)', (await direct(bob.id, { admin: true })).status, 400);
  check('empty update is rejected (400)', (await direct(bob.id, {})).status, 400);
  check('preferences for yourself are rejected (400)', (await direct(ann.id, { pinned: true })).status, 400);
  check('unknown peer gives 404', (await direct(crypto.randomUUID(), { pinned: true })).status, 404);
  check('a group you are not in gives 404', (await http(dan, 'PUT', `/chats/prefs/group/${g1}`, { pinned: true })).status, 404);

  await direct(cat.id, { pinned: true });
  await direct(dan.id, { pinned: true });
  await group(g1, { pinned: true });
  await group(g2, { pinned: true });
  check('a sixth pinned chat is refused (409)', (await direct(eve.id, { pinned: true })).status, 409);

  const reset = await direct(bob.id, { pinned: false, archived: false, mutedUntil: null, defaultTtlSeconds: null });
  check('resetting returns the defaults', [reset.json.prefs.pinned, reset.json.prefs.mutedUntil, reset.json.prefs.defaultTtlSeconds], [false, null, null]);
  check('a reset chat is removed from the list', (await http(ann, 'GET', '/chats/prefs')).json.prefs.some((p) => p.targetId === bob.id), false);
  check('after unpinning, another chat can be pinned (200)', (await direct(eve.id, { pinned: true })).status, 200);
}

for (const s of [annS, bobS, danS]) s.close();
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

// File: server/tests/day6.mjs
// End of file