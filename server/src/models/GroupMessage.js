// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/GroupMessage.js
// Purpose : Data-access layer for encrypted group messages. The server stores
//           and returns ciphertext only. Security rules are enforced inside the
//           SQL itself, so a bug in a route or socket handler cannot bypass
//           them: (1) a message is inserted only if the sender is currently a
//           member, uses the group's CURRENT key epoch, the group is not
//           waiting for a rekey, and the room has not expired - all in one
//           atomic INSERT ... SELECT; (2) history is filtered by the member's
//           join time, so late joiners never receive older messages; (3) only
//           the sender or an admin can delete a message.
//           Burn-on-read: a message can carry burn_after_read_seconds. Each
//           member's read is recorded (markGroupRead); once EVERY member who
//           could see the message has read it, the burn timer starts and
//           expires_at is set (startDueBurns). The background sweeper also
//           calls startDueBurns, which covers the case where the last unread
//           member leaves the group. Expired messages are hidden immediately
//           and physically removed by the sweeper.
// =============================================================================
import { query } from '../config/db.js';

const COLS = 'id, group_id, from_id, epoch, ciphertext, iv, created_at, expires_at, burn_after_read_seconds';

// Returns the stored message, or null when the sender may not post (not a member, stale epoch,
// rekey pending, or the room has expired).
export async function createGroupMessage({ groupId, fromId, epoch, ciphertext, iv, ttlSeconds, burnSeconds }) {
  const { rows } = await query(
    `INSERT INTO group_messages (group_id, from_id, epoch, ciphertext, iv, expires_at, burn_after_read_seconds)
     SELECT g.id, $2::uuid, g.epoch, $4::text, $5::text,
            CASE WHEN $6::double precision IS NULL THEN NULL
                 ELSE now() + make_interval(secs => $6::double precision) END,
            $7::integer
     FROM chat_groups g
     JOIN group_members gm ON gm.group_id = g.id AND gm.user_id = $2::uuid
     WHERE g.id = $1::uuid AND g.epoch = $3::int AND g.needs_rekey = false
       AND (g.expires_at IS NULL OR g.expires_at > now())
     RETURNING ${COLS}`,
    [groupId, fromId, epoch, ciphertext, iv, ttlSeconds ?? null, burnSeconds ?? null]
  );
  return rows[0] || null;
}

// Newest first; "before" is an ISO timestamp for paging. Callers reverse for display.
export async function listGroupMessages({ groupId, userId, limit, before }) {
  const { rows } = await query(
    `SELECT m.id, m.group_id, m.from_id, m.epoch, m.ciphertext, m.iv, m.created_at, m.expires_at,
            m.burn_after_read_seconds
     FROM group_messages m
     JOIN group_members gm ON gm.group_id = m.group_id AND gm.user_id = $2
     WHERE m.group_id = $1
       AND m.created_at >= gm.joined_at
       AND (m.expires_at IS NULL OR m.expires_at > now())
       AND ($4::timestamptz IS NULL OR m.created_at < $4::timestamptz)
     ORDER BY m.created_at DESC
     LIMIT $3`,
    [groupId, userId, limit, before ?? null]
  );
  return rows;
}

// Sender or admin only. Returns the deleted row's ids or null.
export async function deleteGroupMessage({ groupId, messageId, actorId }) {
  const { rows } = await query(
    `DELETE FROM group_messages m
     USING group_members gm
     WHERE m.id = $1 AND m.group_id = $2
       AND gm.group_id = m.group_id AND gm.user_id = $3
       AND (m.from_id = $3 OR gm.role = 'admin')
     RETURNING m.id, m.group_id`,
    [messageId, groupId, actorId]
  );
  return rows[0] || null;
}

// Starts the burn timer of every burn message whose eligible members have all read it
// (pass one id to check a single message, or null to check all). Returns the messages that just started.
export async function startDueBurns(messageId = null) {
  const { rows } = await query(
    `UPDATE group_messages m
     SET burn_started_at = now(),
         expires_at = LEAST(COALESCE(m.expires_at, 'infinity'::timestamptz),
                            now() + make_interval(secs => m.burn_after_read_seconds::double precision))
     WHERE m.burn_after_read_seconds IS NOT NULL
       AND m.burn_started_at IS NULL
       AND ($1::uuid IS NULL OR m.id = $1::uuid)
       AND (m.expires_at IS NULL OR m.expires_at > now())
       AND EXISTS (SELECT 1 FROM group_message_reads r WHERE r.message_id = m.id)
       AND NOT EXISTS (
         SELECT 1 FROM group_members gm
         WHERE gm.group_id = m.group_id
           AND gm.user_id <> m.from_id
           AND gm.joined_at <= m.created_at
           AND NOT EXISTS (
             SELECT 1 FROM group_message_reads r2
             WHERE r2.message_id = m.id AND r2.user_id = gm.user_id
           )
       )
     RETURNING m.id, m.group_id, m.expires_at`,
    [messageId]
  );
  return rows;
}

// Records that a member read a burn message, then starts the timer if everyone has now read it.
// Only members who could see the message (joined before it was sent) and not its sender count.
// Returns the messages whose timer just started (usually zero or one).
export async function markGroupRead({ groupId, messageId, userId }) {
  await query(
    `INSERT INTO group_message_reads (message_id, user_id)
     SELECT m.id, $3::uuid
     FROM group_messages m
     JOIN group_members gm ON gm.group_id = m.group_id AND gm.user_id = $3::uuid
     WHERE m.id = $1 AND m.group_id = $2
       AND m.burn_after_read_seconds IS NOT NULL
       AND m.from_id <> $3::uuid
       AND m.created_at >= gm.joined_at
       AND (m.expires_at IS NULL OR m.expires_at > now())
     ON CONFLICT DO NOTHING`,
    [messageId, groupId, userId]
  );
  return startDueBurns(messageId);
}

// File: server/src/models/GroupMessage.js
// End of file