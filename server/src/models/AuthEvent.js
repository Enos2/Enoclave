// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/AuthEvent.js
// Purpose : The security audit log and brute-force lockout. logEvent records
//           register, login success/failure, logout, key rotation and
//           similar events with a keyed network hash and a device label
//           (never a raw IP); it swallows its own errors so a logging
//           problem can never break login. lockoutSeconds counts recent
//           failures per username+network (limit 5) and per username overall
//           (limit 25) over a 15-minute window and returns how many seconds
//           remain until the limit lifts, which the login route returns as
//           Retry-After. recentEvents feeds the account security timeline.
// =============================================================================
import { query } from '../config/db.js';

const IP_LIMIT = 5; // failed logins per username + network in the window
const USER_LIMIT = 25; // failed logins per username from anywhere in the window

// Audit logging must never break authentication, so errors are swallowed and reported to the console.
export async function logEvent({ userId = null, username = null, event, ipHash, deviceLabel }) {
  try {
    await query(
      `INSERT INTO auth_events (user_id, username, event, ip_hash, device_label)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, username, event, ipHash, deviceLabel]
    );
  } catch (err) {
    console.error('[audit] log failed:', err.message);
  }
}

// Seconds until the limit lifts: the time the Nth most recent failure leaves the 15-minute window.
async function secondsLocked(sql, params, limit) {
  const { rows } = await query(sql, [...params, limit]);
  if (rows.length < limit) return 0;
  return Math.max(0, Math.ceil(Number(rows[limit - 1].secs)));
}

export async function lockoutSeconds(username, ipHash) {
  const [byIp, byUser] = await Promise.all([
    secondsLocked(
      `SELECT EXTRACT(EPOCH FROM (created_at + interval '15 minutes' - now())) AS secs
       FROM auth_events
       WHERE event = 'login_failed' AND username = $1 AND ip_hash = $2
         AND created_at > now() - interval '15 minutes'
       ORDER BY created_at DESC LIMIT $3`,
      [username, ipHash],
      IP_LIMIT
    ),
    secondsLocked(
      `SELECT EXTRACT(EPOCH FROM (created_at + interval '15 minutes' - now())) AS secs
       FROM auth_events
       WHERE event = 'login_failed' AND username = $1
         AND created_at > now() - interval '15 minutes'
       ORDER BY created_at DESC LIMIT $2`,
      [username],
      USER_LIMIT
    ),
  ]);
  return Math.max(byIp, byUser);
}

export async function recentEvents(userId, limit = 50) {
  const { rows } = await query(
    `SELECT event, device_label, created_at
     FROM auth_events WHERE user_id = $1
     ORDER BY created_at DESC LIMIT $2`,
    [userId, limit]
  );
  return rows;
}

// File: server/src/models/AuthEvent.js
// End of file