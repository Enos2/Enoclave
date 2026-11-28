// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/Reaction.js
// Purpose : Data-access layer for message reactions. REACTIONS is the fixed
//           list (thumbs_up, heart, laugh, wow, sad, pray, fire, thumbs_down);
//           the database enforces the same list, so no arbitrary text can be
//           stored. One reaction per user per message: reacting again replaces
//           the old one; passing null removes it. Reactions are plaintext
//           metadata (the server can see who reacted with what) while message
//           content stays encrypted.
//           setDirectReaction: the user must be a participant of a direct
//           message that has not expired. Blocks follow the messaging rules: if
//           the user blocked the other person the result is 'unblock_first';
//           if the OTHER person blocked the user the call looks successful but
//           nothing is stored ('silent'), so a blocked user learns nothing.
//           Removing a reaction is always allowed.
//           setGroupReaction: the user must be a member who could see the
//           message (it was sent after they joined), and neither the message
//           nor the room may have expired.
//           listDirectReactions / listGroupReactions return the reactions on
//           the latest N visible messages of one conversation, for loading when
//           a chat is opened (live changes arrive over realtime). All queries
//           are parameterised; reactions disappear automatically with their
//           message (ON DELETE CASCADE).
// =============================================================================
import { query } from '../config/db.js';

export const REACTIONS = ['thumbs_up', 'heart', 'laugh', 'wow', 'sad', 'pray', 'fire', 'thumbs_down'];

// Returns { error } | { peer, changed, silent? }. reaction === null removes the user's reaction.
export async function setDirectReaction({ messageId, userId, reaction }) {
  const m = await query(
    `SELECT from_id, to_id FROM messages
     WHERE id = $1 AND (from_id = $2 OR to_id = $2) AND (expires_at IS NULL OR expires_at > now())`,
    [messageId, userId]
  );
  if (!m.rowCount) return { error: 'not_found' };
  const peer = m.rows[0].from_id === userId ? m.rows[0].to_id : m.rows[0].from_id;

  if (reaction === null) {
    const d = await query('DELETE FROM direct_reactions WHERE message_id = $1 AND user_id = $2', [messageId, userId]);
    return { peer, changed: d.rowCount > 0 };
  }

  const b = await query(
    `SELECT EXISTS (SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2) AS i_blocked,
            EXISTS (SELECT 1 FROM blocks WHERE blocker_id = $2 AND blocked_id = $1) AS blocked_me`,
    [userId, peer]
  );
  if (b.rows[0].i_blocked) return { error: 'unblock_first' };
  if (b.rows[0].blocked_me) return { peer, changed: false, silent: true };

  await query(
    `INSERT INTO direct_reactions (message_id, user_id, reaction) VALUES ($1, $2, $3)
     ON CONFLICT (message_id, user_id) DO UPDATE SET reaction = EXCLUDED.reaction, created_at = now()`,
    [messageId, userId, reaction]
  );
  return { peer, changed: true };
}

// Returns { error } | { groupId, changed }.
export async function setGroupReaction({ messageId, userId, reaction }) {
  const m = await query(
    `SELECT m.group_id
     FROM group_messages m
     JOIN group_members gm ON gm.group_id = m.group_id AND gm.user_id = $2
     JOIN chat_groups g ON g.id = m.group_id
     WHERE m.id = $1 AND m.created_at >= gm.joined_at
       AND (m.expires_at IS NULL OR m.expires_at > now())
       AND (g.expires_at IS NULL OR g.expires_at > now())`,
    [messageId, userId]
  );
  if (!m.rowCount) return { error: 'not_found' };
  const groupId = m.rows[0].group_id;

  if (reaction === null) {
    const d = await query('DELETE FROM group_reactions WHERE message_id = $1 AND user_id = $2', [messageId, userId]);
    return { groupId, changed: d.rowCount > 0 };
  }
  await query(
    `INSERT INTO group_reactions (message_id, user_id, reaction) VALUES ($1, $2, $3)
     ON CONFLICT (message_id, user_id) DO UPDATE SET reaction = EXCLUDED.reaction, created_at = now()`,
    [messageId, userId, reaction]
  );
  return { groupId, changed: true };
}

export async function listDirectReactions(me, peer, limit) {
  const { rows } = await query(
    `SELECT r.message_id, r.user_id, r.reaction
     FROM direct_reactions r
     JOIN (
       SELECT id FROM messages
       WHERE ((from_id = $1 AND to_id = $2) OR (from_id = $2 AND to_id = $1))
         AND (expires_at IS NULL OR expires_at > now())
       ORDER BY created_at DESC LIMIT $3
     ) m ON m.id = r.message_id
     ORDER BY r.created_at`,
    [me, peer, limit]
  );
  return rows;
}

export async function listGroupReactions(groupId, userId, limit) {
  const { rows } = await query(
    `SELECT r.message_id, r.user_id, r.reaction
     FROM group_reactions r
     JOIN (
       SELECT m.id FROM group_messages m
       JOIN group_members gm ON gm.group_id = m.group_id AND gm.user_id = $2
       WHERE m.group_id = $1 AND m.created_at >= gm.joined_at
         AND (m.expires_at IS NULL OR m.expires_at > now())
       ORDER BY m.created_at DESC LIMIT $3
     ) m ON m.id = r.message_id
     ORDER BY r.created_at`,
    [groupId, userId, limit]
  );
  return rows;
}

// File: server/src/models/Reaction.js
// End of file