// File: server/src/models/Message.js
// Purpose: PostgreSQL data access for encrypted messages. The server only ever handles ciphertext.
import { query } from '../config/db.js';

const COLS = 'id, from_id, to_id, ciphertext, iv, created_at, expires_at';
const NOT_EXPIRED = '(expires_at IS NULL OR expires_at > now())';

export async function createMessage({ from, to, ciphertext, iv, ttlSeconds }) {
  const { rows } = await query(
    `INSERT INTO messages (from_id, to_id, ciphertext, iv, expires_at)
     VALUES ($1, $2, $3, $4,
       CASE WHEN $5::double precision IS NULL THEN NULL
            ELSE now() + make_interval(secs => $5::double precision) END)
     RETURNING ${COLS}`,
    [from, to, ciphertext, iv, ttlSeconds ?? null]
  );
  return rows[0];
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