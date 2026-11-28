// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/tests/day7.mjs
// Purpose : End-to-end test for Day 7 with real HTTP calls and real Socket.IO
//           connections; every check prints a green PASS or red FAIL (exit code
//           1 if anything fails). Three sections.
//           TOTP ALGORITHM: the official RFC 6238 test vectors and a base32
//           round trip, so the code generator is proven correct against the
//           standard, not just against itself.
//           TWO-FACTOR: off by default; setup and enable need the passphrase and
//           a real code; 10 recovery codes in the right format; login needs the
//           code (401 + twoFactorRequired, then generic errors for wrong codes);
//           a code cannot be reused (replay), a recovery code works exactly
//           once and in any case/with or without the dash; sending both factors
//           is rejected; regenerating replaces the old codes and needs a TOTP
//           code; disabling needs passphrase AND code; after disabling, login
//           needs no code. A separate user proves the lockouts: five wrong
//           codes at login give 429 even for a valid code afterwards, and five
//           wrong disable attempts lock the two-factor endpoints.
//           REACTIONS: validation; strangers get 404; live delivery to the
//           other side; changing replaces; removal is announced with a null
//           reaction; block rules (409 when you blocked them, silent no-op when
//           they blocked you); unsending a message deletes its reactions;
//           the same for group messages, including outsiders.
//           The test reaches into the database directly once or twice (like
//           day5.mjs) to reset the "last used step" so it does not have to
//           wait 30 seconds between codes. Needs the server running with
//           TEST_MODE=1:  node .\tests\day7.mjs   (about 1 minute)
// =============================================================================
import crypto from 'node:crypto';
import { io } from 'socket.io-client';
import { query, closePool } from '../src/config/db.js';
import { base32Decode, hotp, stepAt } from '../src/utils/totp.js';

const API = 'http://localhost:5000';
const ORIGIN = 'http://localhost:5173';
const KEY = { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'B'.repeat(43) };
const CT = 'QUJDREVGR0g=';
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
const codeAt = (secret, offset = 0) => hotp(secret, stepAt(Date.now()) + offset);

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

console.log('\n-- TOTP algorithm --');
{
  const rfc = Buffer.from('12345678901234567890');
  check('RFC 6238 test vector at t=59', hotp(rfc, 1, 8), '94287082');
  check('RFC 6238 test vector at t=1111111109', hotp(rfc, 37037036, 8), '07081804');
  check('base32 decodes the standard RFC secret', base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ').toString(), '12345678901234567890');
}

console.log('\n-- Two-factor authentication --');
{
  const u = await register(`tf${n}`);
  const base = '/two-factor';
  const resetStep = () => query('UPDATE two_factor SET last_step = 0 WHERE user_id = $1', [u.id]);
  const loginAs = (body) => http(null, 'POST', '/auth/login', { username: u.name, password: PASSWORD, ...body });

  check('2FA is off by default', (await http(u, 'GET', `${base}/status`)).json, { enabled: false, recoveryCodesRemaining: 0 });
  check('setup with a wrong passphrase is refused (401)', (await http(u, 'POST', `${base}/setup`, { password: 'not-the-password' })).status, 401);
  check('enabling before setup is refused (400)', (await http(u, 'POST', `${base}/enable`, { code: '123456' })).status, 400);

  const setup = await http(u, 'POST', `${base}/setup`, { password: PASSWORD });
  check('setup succeeds (200)', setup.status, 200);
  check('setup returns a 32-character secret', setup.json.secret.length, 32);
  check('setup returns an otpauth URL', setup.json.otpauthUrl.startsWith('otpauth://totp/Enoclave:'), true);
  check('the setup response is no-store', setup.res.headers.get('cache-control'), 'no-store');
  const secret = base32Decode(setup.json.secret);

  check('a malformed code is rejected (400)', (await http(u, 'POST', `${base}/enable`, { code: '12ab56' })).status, 400);
  check('a wrong code does not enable 2FA (400)', (await http(u, 'POST', `${base}/enable`, { code: '000000' })).status, 400);

  const enableCode = codeAt(secret);
  const en = await http(u, 'POST', `${base}/enable`, { code: enableCode });
  check('the right code enables 2FA (200)', en.status, 200);
  const codes = en.json.recoveryCodes;
  check('10 recovery codes are returned', codes.length, 10);
  check('recovery codes look like xxxxxx-xxxxxx', codes.every((c) => /^[a-z2-9]{6}-[a-z2-9]{6}$/.test(c)), true);
  check('the codes are all different', new Set(codes).size, 10);
  check('status shows 2FA enabled with 10 codes', (await http(u, 'GET', `${base}/status`)).json, { enabled: true, recoveryCodesRemaining: 10 });
  check('setup again while enabled is refused (409)', (await http(u, 'POST', `${base}/setup`, { password: PASSWORD })).status, 409);

  const needs = await loginAs({});
  check('login without a code asks for one (401 + twoFactorRequired)', [needs.status, needs.json.twoFactorRequired], [401, true]);
  const wrongCode = await loginAs({ code: '000000' });
  check('a wrong code gives the generic error (401)', [wrongCode.status, wrongCode.json.error, wrongCode.json.twoFactorRequired], [401, 'Invalid credentials', undefined]);
  check('both factors at once are rejected (400)', (await loginAs({ code: '123456', recoveryCode: 'abcdef-ghjkmn' })).status, 400);
  check('a malformed code is rejected (400)', (await loginAs({ code: '12345' })).status, 400);
  check('the code used to enable cannot be reused (401)', (await loginAs({ code: enableCode })).status, 401);

  const next = codeAt(secret, 1);
  check('the next valid code logs in (200)', (await loginAs({ code: next })).status, 200);
  check('the same code cannot be replayed (401)', (await loginAs({ code: next })).status, 401);

  check('a recovery code logs in (200)', (await loginAs({ recoveryCode: codes[0] })).status, 200);
  check('a recovery code works only once (401)', (await loginAs({ recoveryCode: codes[0] })).status, 401);
  check('recovery codes are accepted in capitals without the dash (200)', (await loginAs({ recoveryCode: codes[1].toUpperCase().replace('-', '') })).status, 200);
  check('two recovery codes are used up', (await http(u, 'GET', `${base}/status`)).json.recoveryCodesRemaining, 8);

  await resetStep();
  check('regenerating with a recovery code instead of a code is rejected (400)', (await http(u, 'POST', `${base}/recovery-codes`, { password: PASSWORD, recoveryCode: codes[3] })).status, 400);
  const regen = await http(u, 'POST', `${base}/recovery-codes`, { password: PASSWORD, code: codeAt(secret) });
  check('regenerating with a valid code succeeds (200)', regen.status, 200);
  check('the old recovery codes are replaced', regen.json.recoveryCodes.some((c) => codes.includes(c)), false);
  check('status shows 10 fresh codes', (await http(u, 'GET', `${base}/status`)).json.recoveryCodesRemaining, 10);

  await resetStep();
  check('disabling with a wrong passphrase is refused (401)', (await http(u, 'POST', `${base}/disable`, { password: 'not-the-password', code: codeAt(secret) })).status, 401);
  check('disabling with a wrong code is refused (400)', (await http(u, 'POST', `${base}/disable`, { password: PASSWORD, code: '000000' })).status, 400);
  check('disabling needs a second factor (400)', (await http(u, 'POST', `${base}/disable`, { password: PASSWORD })).status, 400);
  const off = await http(u, 'POST', `${base}/disable`, { password: PASSWORD, recoveryCode: regen.json.recoveryCodes[0] });
  check('disabling with passphrase and a recovery code succeeds (200)', off.status, 200);
  check('status shows 2FA off', (await http(u, 'GET', `${base}/status`)).json, { enabled: false, recoveryCodesRemaining: 0 });
  check('after disabling, login needs no code (200)', (await loginAs({})).status, 200);

  const lk = await register(`lk${n}`);
  const lkSetup = await http(lk, 'POST', `${base}/setup`, { password: PASSWORD });
  const lkSecret = base32Decode(lkSetup.json.secret);
  await http(lk, 'POST', `${base}/enable`, { code: codeAt(lkSecret) });
  const lkLogin = (body) => http(null, 'POST', '/auth/login', { username: lk.name, password: PASSWORD, ...body });

  const bad = [];
  for (let i = 0; i < 5; i += 1) bad.push((await lkLogin({ code: '000000' })).status);
  check('five wrong codes at login all give 401', bad, [401, 401, 401, 401, 401]);
  const locked = await lkLogin({ code: codeAt(lkSecret, 1) });
  check('then even a valid code is refused (429)', locked.status, 429);
  check('the lockout tells the client when to retry', locked.res.headers.get('retry-after') !== null, true);

  const badDisable = [];
  for (let i = 0; i < 5; i += 1) badDisable.push((await http(lk, 'POST', `${base}/disable`, { password: PASSWORD, code: '000000' })).status);
  check('five wrong disable attempts all give 400', badDisable, [400, 400, 400, 400, 400]);
  check('then the two-factor endpoints are locked (429)', (await http(lk, 'POST', `${base}/disable`, { password: PASSWORD, code: codeAt(lkSecret, 1) })).status, 429);
}

console.log('\n-- Reactions --');
const ann = await register(`ann${n}`);
const bob = await register(`bob${n}`);
const cat = await register(`cat${n}`);
const dan = await register(`dan${n}`);
const annS = await connect(ann);
const bobS = await connect(bob);
const catS = await connect(cat);
const danS = await connect(dan);
{
  const url = (id) => `/reactions/direct/${id}`;
  let mk = bobS.log.length;
  await emit(annS, 'message:send', { to: bob.id, ciphertext: CT, iv: IV });
  const msg = await waitEvent(bobS, 'message:new', { from: mk });

  check('an unknown reaction is rejected (400)', (await http(bob, 'PUT', url(msg.id), { reaction: 'poop' })).status, 400);
  check('an unknown field is rejected (400)', (await http(bob, 'PUT', url(msg.id), { reaction: 'heart', admin: true })).status, 400);
  check('a stranger cannot react (404)', (await http(cat, 'PUT', url(msg.id), { reaction: 'heart' })).status, 404);
  check('an unknown message gives 404', (await http(bob, 'PUT', url(crypto.randomUUID()), { reaction: 'heart' })).status, 404);

  mk = annS.log.length;
  check('the recipient reacts (200)', (await http(bob, 'PUT', url(msg.id), { reaction: 'heart' })).status, 200);
  const ev = await waitEvent(annS, 'reaction:update', { from: mk });
  check('the other person is told live', [ev?.kind, ev?.messageId, ev?.userId, ev?.reaction], ['direct', msg.id, bob.id, 'heart']);
  check('the sender can react too (200)', (await http(ann, 'PUT', url(msg.id), { reaction: 'fire' })).status, 200);

  let list = await http(ann, 'GET', `/reactions/conversation/${bob.id}`);
  check('both reactions are listed', list.json.reactions[msg.id].length, 2);

  await http(bob, 'PUT', url(msg.id), { reaction: 'laugh' });
  list = await http(ann, 'GET', `/reactions/conversation/${bob.id}`);
  const bobs = list.json.reactions[msg.id].find((r) => r.userId === bob.id);
  check('changing a reaction replaces it', [list.json.reactions[msg.id].length, bobs.reaction], [2, 'laugh']);

  mk = annS.log.length;
  check('removing a reaction succeeds (200)', (await http(bob, 'DELETE', url(msg.id))).status, 200);
  check('the removal is announced with a null reaction', (await waitEvent(annS, 'reaction:update', { from: mk }))?.reaction, null);
  check('removing again is harmless (200)', (await http(bob, 'DELETE', url(msg.id))).status, 200);
  list = await http(ann, 'GET', `/reactions/conversation/${bob.id}`);
  check('one reaction remains', list.json.reactions[msg.id].length, 1);

  mk = annS.log.length;
  await emit(danS, 'message:send', { to: ann.id, ciphertext: CT, iv: IV });
  const m2 = await waitEvent(annS, 'message:new', { from: mk });
  await http(ann, 'POST', '/blocks', { userId: dan.id });
  check('reacting to someone you blocked is refused (409)', (await http(ann, 'PUT', url(m2.id), { reaction: 'heart' })).status, 409);
  await http(ann, 'DELETE', `/blocks/${dan.id}`);
  await http(dan, 'POST', '/blocks', { userId: ann.id });
  const mkD = danS.log.length;
  check('when they blocked you it looks like success (200)', (await http(ann, 'PUT', url(m2.id), { reaction: 'heart' })).status, 200);
  const seen = await http(dan, 'GET', `/reactions/conversation/${ann.id}`);
  check('...but nothing was stored', (seen.json.reactions[m2.id] ?? []).length, 0);
  check('...and they were not told', await waitEvent(danS, 'reaction:update', { from: mkD, ms: 1500 }), null);

  await http(ann, 'DELETE', `/messages/item/${msg.id}`);
  list = await http(ann, 'GET', `/reactions/conversation/${bob.id}`);
  check('unsending a message deletes its reactions', msg.id in list.json.reactions, false);
}

{
  const gid = (await http(ann, 'POST', '/groups', { name: 'React test', members: [bob.id, cat.id], envelopes: [wrap(ann.id), wrap(bob.id), wrap(cat.id)] })).json.group.id;
  const mk = bobS.log.length;
  await emit(annS, 'group:send', { groupId: gid, epoch: 1, ciphertext: CT, iv: IV });
  const gm = await waitEvent(bobS, 'group:message', { from: mk });
  const url = `/reactions/group/${gm.id}`;

  check('an outsider cannot react to a group message (404)', (await http(dan, 'PUT', url, { reaction: 'pray' })).status, 404);
  const mkC = catS.log.length;
  check('a member reacts (200)', (await http(bob, 'PUT', url, { reaction: 'pray' })).status, 200);
  const ev = await waitEvent(catS, 'reaction:update', { from: mkC });
  check('other members are told live', [ev?.kind, ev?.groupId, ev?.userId, ev?.reaction], ['group', gid, bob.id, 'pray']);
  const list = await http(cat, 'GET', `/reactions/groups/${gid}`);
  check('the group reaction is listed', list.json.reactions[gm.id].length, 1);
  check('an outsider cannot list group reactions (404)', (await http(dan, 'GET', `/reactions/groups/${gid}`)).status, 404);

  const mk2 = catS.log.length;
  await http(bob, 'DELETE', url);
  check('removal reaches the group', (await waitEvent(catS, 'reaction:update', { from: mk2 }))?.reaction, null);
}

for (const s of [annS, bobS, catS, danS]) s.close();
await closePool();
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

// File: server/tests/day7.mjs
// End of file