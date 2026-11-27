// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/Signal.js
// Purpose : Data-access layer for typing indicators and read receipts. Every
//           permission rule is evaluated inside SQL, in one round trip.
//           Typing: canType allows a direct typing signal only if both users
//           have typing enabled, neither has blocked the other, AND the pair
//           has exchanged messages before (so strangers cannot ping people).
//           groupTypingAudience returns the other group members who should
//           receive a group typing signal, and is empty unless the sender is a
//           member with typing enabled. Nothing about typing is ever stored.
//           Read receipts are stored as ONE cursor ("read up to this time") per
//           user per conversation. markDirectRead / markGroupCursor accept a
//           message id, but the server derives the time from the message itself
//           and only if that message really belongs to the conversation and is
//           visible to the reader, so cursors cannot be forged; cursors only
//           ever move forward (GREATEST). Nothing is stored while the reader has
//           receipts off. Reciprocity: the other side sees a cursor only if both
//           have receipts enabled (and, for direct chats, no block).
//           directCursors and groupCursors back the receipts HTTP API.
// =============================================================================
import { query } from '../config/db.js';

export async function canType(me, to) {
  const { rows } = await query(
    `SELECT (
       COALESCE((SELECT show_typing FROM user_settings WHERE user_id = $1::uuid), true)
       AND COALESCE((SELECT show_typing FROM user_settings WHERE user_id = $2::uuid), true)
       AND NOT EXISTS (SELECT 1 FROM blocks
                       WHERE (blocker_id = $1::uuid AND blocked_id = $2::uuid)
                          OR (blocker_id = $2::uuid AND blocked_id = $1::uuid))
       AND EXISTS (SELECT 1 FROM messages
                   WHERE (from_id = $1::uuid AND to_id = $2::uuid)
                      OR (from_id = $2::uuid AND to_id = $1::uuid))
     ) AS ok`,
    [me, to]
  );
  return rows[0].ok === true;
}

export async function groupTypingAudience(groupId, me) {
  const { rows } = await query(
    `SELECT gm.user_id
     FROM group_members gm
     LEFT JOIN user_settings s ON s.user_id = gm.user_id
     WHERE gm.group_id = $1::uuid AND gm.user_id <> $2::uuid
       AND COALESCE(s.show_typing, true)
       AND EXISTS (SELECT 1 FROM group_members x WHERE x.group_id = $1::uuid AND x.user_id = $2::uuid)
       AND COALESCE((SELECT show_typing FROM user_settings WHERE user_id = $2::uuid), true)`,
    [groupId, me]
  );
  return rows.map((r) => r.user_id);
}

// Returns { lastReadAt, notify } when a cursor was stored, otherwise null.
export async function markDirectRead(me, peer, messageId) {
  const { rows } = await query(
    `WITH s AS (
       SELECT COALESCE((SELECT read_receipts FROM user_settings WHERE user_id = $1::uuid), true) AS mine,
              COALESCE((SELECT read_receipts FROM user_settings WHERE user_id = $2::uuid), true) AS theirs,
              NOT EXISTS (SELECT 1 FROM blocks
                          WHERE (blocker_id = $1::uuid AND blocked_id = $2::uuid)
                             OR (blocker_id = $2::uuid AND blocked_id = $1::uuid)) AS open
     ),
     m AS (
       SELECT created_at FROM messages
       WHERE id = $3::uuid AND from_id = $2::uuid AND to_id = $1::uuid
         AND (expires_at IS NULL OR expires_at > now())
     ),
     ins AS (
       INSERT INTO read_cursors (user_id, peer_id, last_read_at)
       SELECT $1::uuid, $2::uuid, m.created_at FROM m, s WHERE s.mine
       ON CONFLICT (user_id, peer_id) DO UPDATE
         SET last_read_at = GREATEST(read_cursors.last_read_at, EXCLUDED.last_read_at)
       RETURNING last_read_at
     )
     SELECT ins.last_read_at, (s.theirs AND s.open) AS notify FROM ins, s`,
    [me, peer, messageId]
  );
  return rows[0] ? { lastReadAt: rows[0].last_read_at, notify: rows[0].notify } : null;
}

// Returns the stored cursor time, or null (not a member, receipts off, or message not visible).
export async function markGroupCursor(groupId, me, messageId) {
  const { rows } = await query(
    `WITH s AS (
       SELECT COALESCE((SELECT read_receipts FROM user_settings WHERE user_id = $2::uuid), true) AS mine
     ),
     m AS (
       SELECT gmsg.created_at
       FROM group_messages gmsg
       JOIN group_members gm ON gm.group_id = gmsg.group_id AND gm.user_id = $2::uuid
       WHERE gmsg.id = $3::uuid AND gmsg.group_id = $1::uuid
         AND gmsg.created_at >= gm.joined_at
         AND (gmsg.expires_at IS NULL OR gmsg.expires_at > now())
     ),
     ins AS (
       INSERT INTO group_read_cursors (group_id, user_id, last_read_at)
       SELECT $1::uuid, $2::uuid, m.created_at FROM m, s WHERE s.mine
       ON CONFLICT (group_id, user_id) DO UPDATE
         SET last_read_at = GREATEST(group_read_cursors.last_read_at, EXCLUDED.last_read_at)
       RETURNING last_read_at
     )
     SELECT last_read_at FROM ins`,
    [groupId, me, messageId]
  );
  return rows[0]?.last_read_at ?? null;
}

// Other members who have receipts enabled (they are the ones who may be told about a read).
export async function groupReceiptAudience(groupId, me) {
  const { rows } = await query(
    `SELECT gm.user_id
     FROM group_members gm
     LEFT JOIN user_settings s ON s.user_id = gm.user_id
     WHERE gm.group_id = $1::uuid AND gm.user_id <> $2::uuid AND COALESCE(s.read_receipts, true)`,
    [groupId, me]
  );
  return rows.map((r) => r.user_id);
}

// mine: my own cursor. theirs: the peer's cursor, or null when either side has receipts off or a block exists.
export async function directCursors(me, peer) {
  const { rows } = await query(
    `SELECT
       (SELECT last_read_at FROM read_cursors WHERE user_id = $1::uuid AND peer_id = $2::uuid) AS mine,
       CASE WHEN COALESCE((SELECT read_receipts FROM user_settings WHERE user_id = $1::uuid), true)
                 AND COALESCE((SELECT read_receipts FROM user_settings WHERE user_id = $2::uuid), true)
                 AND NOT EXISTS (SELECT 1 FROM blocks
                                 WHERE (blocker_id = $1::uuid AND blocked_id = $2::uuid)
                                    OR (blocker_id = $2::uuid AND blocked_id = $1::uuid))
            THEN (SELECT last_read_at FROM read_cursors WHERE user_id = $2::uuid AND peer_id = $1::uuid)
       END AS theirs`,
    [me, peer]
  );
  return rows[0];
}

// Cursors of the other members, only if I have receipts on and they do too. The caller checks membership.
export async function groupCursors(groupId, me) {
  const { rows } = await query(
    `SELECT c.user_id, c.last_read_at
     FROM group_read_cursors c
     JOIN group_members gm ON gm.group_id = c.group_id AND gm.user_id = c.user_id
     LEFT JOIN user_settings s ON s.user_id = c.user_id
     WHERE c.group_id = $1::uuid AND c.user_id <> $2::uuid AND COALESCE(s.read_receipts, true)
       AND COALESCE((SELECT read_receipts FROM user_settings WHERE user_id = $2::uuid), true)
     ORDER BY c.user_id`,
    [groupId, me]
  );
  return rows;
}

// File: server/src/models/Signal.js
// End of file