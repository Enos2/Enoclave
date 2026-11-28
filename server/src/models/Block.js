// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/Block.js
// Purpose : Data-access layer for blocking. blockUser adds a block (capped
//           at 500 per user, under an advisory lock) and, in the same
//           transaction, removes the target from the blocker's contacts;
//           unblockUser reverses it; listBlocks returns a user's blocks.
//           getBlockState tells the message handlers whether I blocked
//           someone or they blocked me. A blocked user's messages are
//           silently dropped while the sender still sees success, so nobody
//           can learn they were blocked. Every query is parameterised.
// =============================================================================
import { query, withTransaction } from '../config/db.js';

const MAX_BLOCKS = 500;

export async function listBlocks(blockerId) {
  const { rows } = await query(
    `SELECT u.id, u.username, b.created_at
     FROM blocks b JOIN users u ON u.id = b.blocked_id
     WHERE b.blocker_id = $1
     ORDER BY b.created_at DESC`,
    [blockerId]
  );
  return rows;
}

// Returns 'blocked' | 'exists' | 'limit'. A missing user raises a FK error (code 23503).
export async function blockUser(blockerId, blockedId) {
  return withTransaction(async (c) => {
    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`blocks:${blockerId}`]);
    const existing = await c.query('SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [blockerId, blockedId]);
    if (existing.rowCount) return 'exists';
    const count = await c.query('SELECT count(*)::int AS n FROM blocks WHERE blocker_id = $1', [blockerId]);
    if (count.rows[0].n >= MAX_BLOCKS) return 'limit';
    await c.query('INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2)', [blockerId, blockedId]);
    await c.query('DELETE FROM contacts WHERE owner_id = $1 AND contact_id = $2', [blockerId, blockedId]);
    return 'blocked';
  });
}

export async function unblockUser(blockerId, blockedId) {
  const { rowCount } = await query('DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [blockerId, blockedId]);
  return rowCount > 0;
}

// iBlocked: I blocked them. blockedMe: they blocked me.
export async function getBlockState(me, other) {
  const { rows } = await query(
    `SELECT
       EXISTS (SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2) AS i_blocked,
       EXISTS (SELECT 1 FROM blocks WHERE blocker_id = $2 AND blocked_id = $1) AS blocked_me`,
    [me, other]
  );
  return { iBlocked: rows[0].i_blocked, blockedMe: rows[0].blocked_me };
}

// File: server/src/models/Block.js
// End of file