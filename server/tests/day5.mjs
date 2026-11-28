// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/tests/day5.mjs
// Purpose : End-to-end test for Day 5 with real HTTP calls and real Socket.IO
//           connections; each check prints a green PASS or red FAIL (exit code
//           1 if anything fails).
//           HARDENING: health and readiness endpoints, hidden X-Powered-By,
//           CSP and request-id headers, malformed JSON -> 400 (not 500),
//           oversized body -> 413, unknown URL -> JSON 404, writes without the
//           Origin header -> 403.
//           REPORTS: reporting yourself or unknown targets, reasons and unknown
//           fields validated, duplicate reports -> 409, a direct message can be
//           reported only by its recipient, a group message only by a member
//           (never by its author), the server snapshot of the ciphertext,
//           the reporter's own report list, and the anti-brigading flag after 5
//           different reporters.
//           ADMIN: non-admins get 404, listing and filtering, evidence detail,
//           resolving once (409 on repeat), suspension validation, admins
//           cannot suspend themselves, a suspension kills the live socket,
//           the old session, new logins and new socket connections, lifting it
//           restores access, and the audit trail records both actions.
//           Needs the server running (use TEST_MODE=1 so rate limits do not
//           interfere):  node .\tests\day5.mjs
// =============================================================================
import { io } from 'socket.io-client';
import { query, closePool } from '../src/config/db.js';

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

const tryConnect = (user) =>
  new Promise((resolve) => {
    const s = io(API, { transports: ['websocket'], reconnection: false, extraHeaders: { Cookie: user.cookie, Origin: ORIGIN } });
    const done = (ok) => {
      s.close();
      resolve(ok);
    };
    s.on('connect', () => done(true));
    s.on('connect_error', () => done(false));
    setTimeout(() => done(false), 4000);
  });

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
const rep = await register(`rep${n}`);
const tgt = await register(`tgt${n}`);
const adm = await register(`adm${n}`);
const oth = await register(`oth${n}`);
await query('UPDATE users SET is_admin = true WHERE id = $1', [adm.id]);
const tgtS = await connect(tgt);

console.log('\n-- Hardening --');
{
  const health = await fetch(`${API}/api/health`);
  check('health endpoint answers 200', health.status, 200);
  check('readiness endpoint answers 200', (await fetch(`${API}/api/ready`)).status, 200);
  check('X-Powered-By is hidden', health.headers.get('x-powered-by'), null);
  check('strict CSP header is present', health.headers.get('content-security-policy')?.includes("default-src 'none'"), true);
  check('every response has a request id', health.headers.get('x-request-id')?.length, 36);

  const bad = await fetch(`${API}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN },
    body: '{not json',
  });
  check('malformed JSON gives 400, not 500', bad.status, 400);
  const big = await fetch(`${API}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN },
    body: JSON.stringify({ username: 'x'.repeat(60_000) }),
  });
  check('oversized body gives 413', big.status, 413);
  const missing = await fetch(`${API}/api/does-not-exist`);
  check('unknown URL gives a JSON 404', [missing.status, (await missing.json()).error], [404, 'Not found']);
  const noOrigin = await fetch(`${API}/api/auth/logout`, { method: 'POST' });
  check('write without an Origin header is refused (403)', noOrigin.status, 403);
  check('admin API without a session gives 401', (await http(null, 'GET', '/admin/reports')).status, 401);
}

console.log('\n-- Reports --');
let userReportId;
let msgReportId;
let groupMsgId;
{
  check('reporting yourself is rejected (400)', (await http(rep, 'POST', '/reports', { type: 'user', targetUserId: rep.id, reason: 'spam' })).status, 400);
  check('unknown target gives 404', (await http(rep, 'POST', '/reports', { type: 'user', targetUserId: crypto.randomUUID(), reason: 'spam' })).status, 404);
  check('invalid reason is rejected (400)', (await http(rep, 'POST', '/reports', { type: 'user', targetUserId: tgt.id, reason: 'boring' })).status, 400);
  check('unknown field is rejected (400)', (await http(rep, 'POST', '/reports', { type: 'user', targetUserId: tgt.id, reason: 'spam', admin: true })).status, 400);
  check('a user report needs a target (400)', (await http(rep, 'POST', '/reports', { type: 'user', reason: 'spam' })).status, 400);

  const r1 = await http(rep, 'POST', '/reports', { type: 'user', targetUserId: tgt.id, reason: 'harassment', note: 'keeps messaging me' });
  check('report a user (201)', r1.status, 201);
  userReportId = r1.json.report.id;
  check('reporting the same user again gives 409', (await http(rep, 'POST', '/reports', { type: 'user', targetUserId: tgt.id, reason: 'spam' })).status, 409);

  let mk = tgtS.log.length;
  await emit(tgtS, 'message:send', { to: rep.id, ciphertext: CT, iv: IV });
  const msg = await waitEvent(tgtS, 'message:new', { from: mk });
  const m1 = await http(rep, 'POST', '/reports', { type: 'message', messageId: msg.id, reason: 'scam', evidence: 'he said something bad' });
  check('the recipient can report a direct message (201)', m1.status, 201);
  msgReportId = m1.json.report.id;
  check('the same message cannot be reported twice (409)', (await http(rep, 'POST', '/reports', { type: 'message', messageId: msg.id, reason: 'scam' })).status, 409);
  check('the sender cannot report their own message (404)', (await http(tgt, 'POST', '/reports', { type: 'message', messageId: msg.id, reason: 'spam' })).status, 404);
  check('a stranger cannot report it (404)', (await http(oth, 'POST', '/reports', { type: 'message', messageId: msg.id, reason: 'spam' })).status, 404);

  const created = await http(rep, 'POST', '/groups', { name: 'Report test', members: [tgt.id], envelopes: [wrap(rep.id), wrap(tgt.id)] });
  const gid = created.json.group.id;
  mk = tgtS.log.length;
  await emit(tgtS, 'group:send', { groupId: gid, epoch: 1, ciphertext: CT, iv: IV });
  const gm = await waitEvent(tgtS, 'group:message', { from: mk });
  groupMsgId = gm.id;
  check('a member can report a group message (201)', (await http(rep, 'POST', '/reports', { type: 'group_message', messageId: gm.id, reason: 'spam' })).status, 201);
  check('an outsider cannot report it (404)', (await http(oth, 'POST', '/reports', { type: 'group_message', messageId: gm.id, reason: 'spam' })).status, 404);
  check('the author cannot report their own group message (400)', (await http(tgt, 'POST', '/reports', { type: 'group_message', messageId: gm.id, reason: 'spam' })).status, 400);

  const mine = await http(rep, 'GET', '/reports/mine');
  check('the reporter sees their 3 reports', mine.json.reports.length, 3);

  for (let i = 1; i <= 4; i += 1) {
    const extra = await register(`brg${i}x${n}`);
    await http(extra, 'POST', '/reports', { type: 'user', targetUserId: tgt.id, reason: 'spam' });
  }
}

console.log('\n-- Admin moderation --');
{
  check('a normal user gets 404 on the admin API', (await http(rep, 'GET', '/admin/reports')).status, 404);
  check('a normal user cannot suspend (404)', (await http(rep, 'POST', `/admin/users/${tgt.id}/suspend`, { durationSeconds: 3600, reason: 'x' })).status, 404);

  const list = await http(adm, 'GET', '/admin/reports?status=open');
  check('admin lists open reports', list.json.reports.length >= 7, true);
  const flagged = await http(adm, 'GET', '/admin/reports?status=open&flagged=true');
  check('5 different reporters trigger the brigading flag', flagged.json.reports.some((r) => r.reported.id === tgt.id), true);

  const detail = await http(adm, 'GET', `/admin/reports/${msgReportId}`);
  check('detail shows the server-side ciphertext snapshot', detail.json.report.evidence.ciphertext, CT);
  check('detail shows the reporter text, separately', detail.json.report.evidence.reporterSuppliedText, 'he said something bad');
  check('unknown report gives 404', (await http(adm, 'GET', `/admin/reports/${crypto.randomUUID()}`)).status, 404);

  check('invalid resolve status is rejected (400)', (await http(adm, 'POST', `/admin/reports/${userReportId}/resolve`, { status: 'maybe' })).status, 400);
  check('admin dismisses a report (200)', (await http(adm, 'POST', `/admin/reports/${userReportId}/resolve`, { status: 'dismissed', note: 'not enough' })).status, 200);
  check('a closed report cannot be reopened (409)', (await http(adm, 'POST', `/admin/reports/${userReportId}/resolve`, { status: 'actioned' })).status, 409);

  check('suspending needs durationSeconds (400)', (await http(adm, 'POST', `/admin/users/${tgt.id}/suspend`, { reason: 'x' })).status, 400);
  check('a 5 second suspension is rejected (400)', (await http(adm, 'POST', `/admin/users/${tgt.id}/suspend`, { durationSeconds: 5, reason: 'x' })).status, 400);
  check('an admin cannot suspend themselves (403)', (await http(adm, 'POST', `/admin/users/${adm.id}/suspend`, { durationSeconds: 3600, reason: 'x' })).status, 403);

  const search = await http(adm, 'GET', `/admin/users?q=tgt${n}`);
  check('admin user search shows open reports', search.json.users[0].openReports >= 4, true);

  const mk = tgtS.log.length;
  const sus = await http(adm, 'POST', `/admin/users/${tgt.id}/suspend`, { durationSeconds: 3600, reason: 'harassment', reportId: msgReportId });
  check('admin suspends the user (200)', sus.status, 200);
  check('the live user is told about the suspension', (await waitEvent(tgtS, 'account:suspended', { from: mk })) !== null, true);
  await sleep(500);
  check('the live socket is disconnected', tgtS.connected, false);
  check('the old session stops working (401)', (await http(tgt, 'GET', '/auth/me')).status, 401);
  const login = await http(null, 'POST', '/auth/login', { username: tgt.name, password: PASSWORD });
  check('login is refused with 403', [login.status, login.json.error], [403, 'Account suspended']);
  check('new socket connections are refused', await tryConnect(tgt), false);
  const closed = await http(adm, 'GET', `/admin/reports/${msgReportId}`);
  check('the linked report was closed as actioned', closed.json.report.status, 'actioned');

  check('admin lifts the suspension (200)', (await http(adm, 'DELETE', `/admin/users/${tgt.id}/suspension`)).status, 200);
  check('lifting it twice gives 404', (await http(adm, 'DELETE', `/admin/users/${tgt.id}/suspension`)).status, 404);
  check('the user can log in again (200)', (await http(null, 'POST', '/auth/login', { username: tgt.name, password: PASSWORD })).status, 200);

  const actions = await http(adm, 'GET', '/admin/actions?limit=20');
  const forTarget = actions.json.actions.filter((a) => a.target.id === tgt.id).map((a) => a.action);
  check('the audit trail records suspend and unsuspend', ['suspend', 'unsuspend'].every((a) => forTarget.includes(a)), true);
}

tgtS.close();
await closePool();
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

// File: server/tests/day5.mjs
// End of file