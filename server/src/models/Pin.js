// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/Pin.js
// Purpose : Data-access layer for pinned messages. DIRECT chats: either of the
//           two people can pin or unpin a message of their conversation; the
//           pin list is SHARED by both, with at most 3 pins per conversation.
//           Block rules match reactions: if you blocked the other person you
//           cannot pin ('unblock_first'); if THEY blocked you the call reports
//           a silent success and stores nothing, so a blocked user learns
//           nothing. Unpinning is always allowed. GROUPS: only group ADMINS can
//           pin or unpin ('forbidden' for ordinary members; 'not_found' for
//           anyone who is not a member or could not see the message, so ids
//           cannot be probed), with at most 5 pins per group. Pinning an already
//           pinned message is harmless. Each pin/unpin runs in one transaction
//           under an advisory lock per conversation or group, so parallel
//           requests can never exceed the limits. Expired messages cannot be
//           pinned and their pins are hidden (and removed with the message by
//           ON DELETE CASCADE). listDirectPins / listGroupPins return the pins
//           together with the pinned message's ciphertext so clients can show
//           them without loading the whole history; group lists only include
//           messages the caller could see (sent after they joined). All queries
//           are parameterised.
// =============================================================================
import { query, withTransaction } from '../config/db.js';

export const MAX_DIRECT_PINS = 3;
export const MAX_GROUP_PINS = 5;

// Returns { error } | { peer, changed, silent? }.
export async function setDirectPin({ messageId, userId, pinned }) {
  return withTransaction(async (c) => {
    const m = await c.query(
      `SELECT from_id, to_id FROM messages
       WHERE id = $1 AND (from_id = $2 OR to_id = $2) AND (expires_at IS NULL OR expires_at > now())`,
      [messageId, userId]
    );
    if (!m.rowCount) return { error: 'not_found' };
    const peer = m.rows[0].from_id === userId ? m.rows[0].to_id : m.rows[0].from_id;

    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`pins:${[userId, peer].sort().join(':')}`]);

    if (!pinned) {
      const d = await c.query('DELETE FROM pinned_direct WHERE message_id = $1', [messageId]);
      return { peer, changed: d.rowCount > 0 };
    }

    const b = await c.query(
      `SELECT EXISTS (SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2) AS i_blocked,
              EXISTS (SELECT 1 FROM blocks WHERE blocker_id = $2 AND blocked_id = $1) AS blocked_me`,
      [userId, peer]
    );
    if (b.rows[0].i_blocked) return { error: 'unblock_first' };
    if (b.rows[0].blocked_me) return { peer, changed: false, silent: true };

    const already = await c.query('SELECT 1 FROM pinned_direct WHERE message_id = $1', [messageId]);
    if (already.rowCount) return { peer, changed: false };

    const n = await c.query(
      `SELECT count(*)::int AS n
       FROM pinned_direct p JOIN messages x ON x.id = p.message_id
       WHERE (x.from_id = $1 AND x.to_id = $2) OR (x.from_id = $2 AND x.to_id = $1)`,
      [userId, peer]
    );
    if (n.rows[0].n >= MAX_DIRECT_PINS) return { error: 'limit' };

    await c.query('INSERT INTO pinned_direct (message_id, pinned_by) VALUES ($1, $2)', [messageId, userId]);
    return { peer, changed: true };
  });
}

// Returns { error } | { groupId, changed }.
export async function setGroupPin({ messageId, userId, pinned }) {
  return withTransaction(async (c) => {
    const m = await c.query(
      `SELECT m.group_id, gm.role
       FROM group_messages m
       JOIN group_members gm ON gm.group_id = m.group_id AND gm.user_id = $2
       JOIN chat_groups g ON g.id = m.group_id
       WHERE m.id = $1 AND m.created_at >= gm.joined_at
         AND (m.expires_at IS NULL OR m.expires_at > now())
         AND (g.expires_at IS NULL OR g.expires_at > now())`,
      [messageId, userId]
    );
    if (!m.rowCount) return { error: 'not_found' };
    const { group_id: groupId, role } = m.rows[0];
    if (role !== 'admin') return { error: 'forbidden' };

    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`pins:group:${groupId}`]);

    if (!pinned) {
      const d = await c.query('DELETE FROM pinned_group WHERE message_id = $1', [messageId]);
      return { groupId, changed: d.rowCount > 0 };
    }

    const already = await c.query('SELECT 1 FROM pinned_group WHERE message_id = $1', [messageId]);
    if (already.rowCount) return { groupId, changed: false };

    const n = await c.query('SELECT count(*)::int AS n FROM pinned_group WHERE group_id = $1', [groupId]);
    if (n.rows[0].n >= MAX_GROUP_PINS) return { error: 'limit' };

    await c.query('INSERT INTO pinned_group (message_id, group_id, pinned_by) VALUES ($1, $2, $3)', [
      messageId,
      groupId,
      userId,
    ]);
    return { groupId, changed: true };
  });
}

export async function listDirectPins(me, peer) {
  const { rows } = await query(
    `SELECT p.pinned_by, p.pinned_at,
            m.id, m.from_id, m.to_id, m.ciphertext, m.iv, m.created_at, m.expires_at,
            m.burn_after_read_seconds, m.edited_at
     FROM pinned_direct p JOIN messages m ON m.id = p.message_id
     WHERE ((m.from_id = $1 AND m.to_id = $2) OR (m.from_id = $2 AND m.to_id = $1))
       AND (m.expires_at IS NULL OR m.expires_at > now())
     ORDER BY p.pinned_at DESC`,
    [me, peer]
  );
  return rows;
}

export async function listGroupPins(groupId, userId) {
  const { rows } = await query(
    `SELECT p.pinned_by, p.pinned_at,
            m.id, m.group_id, m.from_id, m.epoch, m.ciphertext, m.iv, m.created_at, m.expires_at,
            m.burn_after_read_seconds, m.edited_at
     FROM pinned_group p
     JOIN group_messages m ON m.id = p.message_id
     JOIN group_members gm ON gm.group_id = m.group_id AND gm.user_id = $2
     WHERE p.group_id = $1
       AND m.created_at >= gm.joined_at
       AND (m.expires_at IS NULL OR m.expires_at > now())
     ORDER BY p.pinned_at DESC`,
    [groupId, userId]
  );
  return rows;
}

// File: server/src/models/Pin.js
// End of file