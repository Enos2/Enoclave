// File: server/src/models/Session.js
// Purpose: Data access for login sessions (devices): create, validate, list and revoke.
import { query } from '../config/db.js';
import { SESSION_TTL_MS } from '../utils/token.js';

const MAX_ACTIVE = 10;
const ACTIVE = 'revoked_at IS NULL AND expires_at > now()';

// Creates a session and evicts the oldest ones beyond MAX_ACTIVE. Returns the new session and evicted ids.
export async function createSession({ userId, deviceLabel, ipHash }) {
  const { rows } = await query(
    `INSERT INTO sessions (user_id, device_label, ip_hash, expires_at)
     VALUES ($1, $2, $3, now() + make_interval(secs => $4::double precision))
     RETURNING id, expires_at`,
    [userId, deviceLabel, ipHash, SESSION_TTL_MS / 1000]
  );
  const evicted = await query(
    `UPDATE sessions SET revoked_at = now()
     WHERE user_id = $1 AND revoked_at IS NULL
       AND id NOT IN (
         SELECT id FROM sessions
         WHERE user_id = $1 AND revoked_at IS NULL
         ORDER BY created_at DESC LIMIT $2
       )
     RETURNING id`,
    [userId, MAX_ACTIVE]
  );
  return { session: rows[0], evicted: evicted.rows.map((r) => r.id) };
}

export async function findActiveSession(id, userId) {
  const { rows } = await query(
    `SELECT id FROM sessions WHERE id = $1 AND user_id = $2 AND ${ACTIVE}`,
    [id, userId]
  );
  return rows[0] || null;
}

// Updates last_seen at most once a minute to avoid a write on every request.
export async function touchSession(id) {
  await query(
    "UPDATE sessions SET last_seen_at = now() WHERE id = $1 AND last_seen_at < now() - interval '1 minute'",
    [id]
  );
}

export async function listSessions(userId) {
  const { rows } = await query(
    `SELECT id, device_label, created_at, last_seen_at, expires_at
     FROM sessions WHERE user_id = $1 AND ${ACTIVE}
     ORDER BY last_seen_at DESC`,
    [userId]
  );
  return rows;
}

export async function revokeSession(id, userId) {
  const { rowCount } = await query(
    'UPDATE sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL',
    [id, userId]
  );
  return rowCount > 0;
}

export async function revokeOthers(userId, keepId) {
  const { rows } = await query(
    `UPDATE sessions SET revoked_at = now()
     WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL
     RETURNING id`,
    [userId, keepId]
  );
  return rows.map((r) => r.id);
}

export async function revokeAll(userId) {
  const { rows } = await query(
    'UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL RETURNING id',
    [userId]
  );
  return rows.map((r) => r.id);
}

// File: server/src/models/Session.js
// End of file