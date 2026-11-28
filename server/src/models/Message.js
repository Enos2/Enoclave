// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/Message.js
// Purpose : Data-access layer for 1-to-1 encrypted messages. The server stores
//           and returns ciphertext only; it can never read message content.
//           Supports three kinds of disappearing message: (1) send-time expiry
//           (ttlSeconds: gone N seconds after sending), (2) burn-on-read
//           (burnSeconds: the timer starts only when the RECIPIENT reads it,
//           via markBurn), and (3) both together, where the earlier deadline
//           wins. Expired messages are hidden from every read immediately and
//           physically deleted by the background sweeper. Other rules enforced
//           here: only the sender can unsend a message; clearing a chat removes
//           it for both people; only the recipient can start a burn timer, and
//           only once (markBurn returns a row only on the first read, so
//           callers notify exactly once).
//           EDITING (editMessage): one transaction that locks the message row
//           and allows the change only if ALL of these hold - the caller is the
//           sender, the message has not expired, it was sent less than 15
//           minutes ago by the SERVER's clock, no burn timer has started, and it
//           has been edited fewer than 10 times. Block rules match normal
//           sending: if the sender blocked the recipient the edit is refused
//           ('unblock_first'); if the recipient blocked the sender the call
//           reports a silent success and changes NOTHING, so a blocked sender
//           learns nothing. The new ciphertext replaces the old one and
//           edited_at is stamped. Every query is parameterised.
// =============================================================================
import { query, withTransaction } from '../config/db.js';

const COLS = 'id, from_id, to_id, ciphertext, iv, created_at, expires_at, burn_after_read_seconds, edited_at';
const NOT_EXPIRED = '(expires_at IS NULL OR expires_at > now())';
const MAX_EDITS = 10;

export async function createMessage({ from, to, ciphertext, iv, ttlSeconds, burnSeconds }) {
  const { rows } = await query(
    `INSERT INTO messages (from_id, to_id, ciphertext, iv, expires_at, burn_after_read_seconds)
     VALUES ($1, $2, $3, $4,
       CASE WHEN $5::double precision IS NULL THEN NULL
            ELSE now() + make_interval(secs => $5::double precision) END,
       $6::integer)
     RETURNING ${COLS}`,
    [from, to, ciphertext, iv, ttlSeconds ?? null, burnSeconds ?? null]
  );
  return rows[0];
}

// Returns { error } | { silent: true, peer } | { message, peer }.
export async function editMessage({ id, userId, ciphertext, iv }) {
  return withTransaction(async (c) => {
    const m = await c.query(
      `SELECT to_id, edit_count, burn_started_at,
              (created_at > now() - interval '15 minutes') AS in_window
       FROM messages
       WHERE id = $1 AND from_id = $2 AND ${NOT_EXPIRED}
       FOR UPDATE`,
      [id, userId]
    );
    if (!m.rowCount) return { error: 'not_found' };
    const row = m.rows[0];
    if (!row.in_window) return { error: 'too_late' };
    if (row.burn_started_at) return { error: 'burning' };
    if (row.edit_count >= MAX_EDITS) return { error: 'edit_limit' };

    const b = await c.query(
      `SELECT EXISTS (SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2) AS i_blocked,
              EXISTS (SELECT 1 FROM blocks WHERE blocker_id = $2 AND blocked_id = $1) AS blocked_me`,
      [userId, row.to_id]
    );
    if (b.rows[0].i_blocked) return { error: 'unblock_first' };
    if (b.rows[0].blocked_me) return { silent: true, peer: row.to_id };

    const up = await c.query(
      `UPDATE messages
       SET ciphertext = $2, iv = $3, edited_at = now(), edit_count = edit_count + 1
       WHERE id = $1
       RETURNING ${COLS}`,
      [id, ciphertext, iv]
    );
    return { message: up.rows[0], peer: row.to_id };
  });
}

// Starts the burn timer of a message. Only the recipient can do it, only once.
// Returns { id, from_id, to_id, expires_at } on the first read, otherwise null.
export async function markBurn(messageId, readerId) {
  const { rows } = await query(
    `WITH target AS (
       SELECT id FROM messages
       WHERE id = $1 AND to_id = $2
         AND burn_after_read_seconds IS NOT NULL
         AND burn_started_at IS NULL
         AND ${NOT_EXPIRED}
       FOR UPDATE
     )
     UPDATE messages m
     SET burn_started_at = now(),
         expires_at = LEAST(COALESCE(m.expires_at, 'infinity'::timestamptz),
                            now() + make_interval(secs => m.burn_after_read_seconds::double precision))
     FROM target t
     WHERE m.id = t.id
     RETURNING m.id, m.from_id, m.to_id, m.expires_at`,
    [messageId, readerId]
  );
  return rows[0] || null;
}

export async function listConversations(userId) {
  const { rows } = await query(
    `SELECT m.peer_id AS id, u.username
     FROM (
       SELECT CASE WHEN from_id = $1 THEN to_id ELSE from_id END AS peer_id,
              max(created_at) AS last_at
       FROM messages
       WHERE (from_id = $1 OR to_id = $1) AND ${NOT_EXPIRED}
       GROUP BY 1
     ) m
     JOIN users u ON u.id = m.peer_id
     ORDER BY m.last_at DESC
     LIMIT 50`,
    [userId]
  );
  return rows;
}

export async function getHistory(me, peer, limit) {
  const { rows } = await query(
    `SELECT ${COLS} FROM messages
     WHERE ((from_id = $1 AND to_id = $2) OR (from_id = $2 AND to_id = $1))
       AND ${NOT_EXPIRED}
     ORDER BY created_at DESC
     LIMIT $3`,
    [me, peer, limit]
  );
  return rows.reverse();
}

// Only the sender can unsend; returns the deleted row or null.
export async function deleteOwnMessage(id, userId) {
  const { rows } = await query(
    'DELETE FROM messages WHERE id = $1 AND from_id = $2 RETURNING id, from_id, to_id',
    [id, userId]
  );
  return rows[0] || null;
}

export async function clearChat(me, peer) {
  await query(
    `DELETE FROM messages
     WHERE (from_id = $1 AND to_id = $2) OR (from_id = $2 AND to_id = $1)`,
    [me, peer]
  );
}

// File: server/src/models/Message.js
// End of file