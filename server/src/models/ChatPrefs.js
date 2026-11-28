// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/ChatPrefs.js
// Purpose : Data-access layer for each user's PRIVATE per-conversation
//           preferences: pinned (at most 5 per user), archived, muted until a
//           time, and a default disappearing-message timer that the user's
//           clients apply when sending. Nobody else can see or be told about
//           these. listPrefs returns the user's non-default preferences with
//           the peer's username or the group's name (a mute whose time has
//           passed is reported as not muted). setPref changes only the fields
//           provided, in one transaction under a per-user lock (so parallel
//           requests cannot exceed the pin limit): it verifies the target (a
//           direct peer must exist; for a group the user must be a MEMBER, and
//           non-members get "not_found" so group ids cannot be probed), updates
//           or inserts the row, and DELETES the row again if everything is back
//           to its default, so nothing unnecessary is stored. A field omitted
//           from the patch is left alone; sending null clears mutedUntil or
//           defaultTtlSeconds. All queries are parameterised.
// =============================================================================
import { query, withTransaction } from '../config/db.js';

export const MAX_PINNED = 5;

const SELECT = `
  SELECT p.pinned, p.archived,
         CASE WHEN p.muted_until > now() THEN p.muted_until END AS muted_until,
         p.default_ttl_seconds, p.peer_id, p.group_id,
         u.username AS peer_username, g.name AS group_name
  FROM chat_prefs p
  LEFT JOIN users u ON u.id = p.peer_id
  LEFT JOIN chat_groups g ON g.id = p.group_id`;

export async function listPrefs(userId) {
  const { rows } = await query(`${SELECT} WHERE p.user_id = $1 ORDER BY p.pinned DESC, p.updated_at DESC`, [userId]);
  return rows;
}

// Returns { pref } (null when reset to defaults) or { error: 'not_found' | 'pin_limit' }.
export async function setPref({ userId, peerId, groupId, patch }) {
  return withTransaction(async (c) => {
    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`prefs:${userId}`]);

    const targetId = peerId ?? groupId;
    const col = peerId ? 'peer_id' : 'group_id';

    if (peerId) {
      const u = await c.query('SELECT 1 FROM users WHERE id = $1', [peerId]);
      if (!u.rowCount) return { error: 'not_found' };
    } else {
      const m = await c.query('SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2', [groupId, userId]);
      if (!m.rowCount) return { error: 'not_found' };
    }

    if (patch.pinned === true) {
      const n = await c.query(
        `SELECT count(*)::int AS n FROM chat_prefs
         WHERE user_id = $1 AND pinned AND COALESCE(peer_id, group_id) <> $2::uuid`,
        [userId, targetId]
      );
      if (n.rows[0].n >= MAX_PINNED) return { error: 'pin_limit' };
    }

    const args = [
      patch.pinned ?? null,
      patch.archived ?? null,
      'mutedUntil' in patch,
      patch.mutedUntil ?? null,
      'defaultTtlSeconds' in patch,
      patch.defaultTtlSeconds ?? null,
    ];

    const upd = await c.query(
      `UPDATE chat_prefs SET
         pinned = COALESCE($3::boolean, pinned),
         archived = COALESCE($4::boolean, archived),
         muted_until = CASE WHEN $5::boolean THEN $6::timestamptz ELSE muted_until END,
         default_ttl_seconds = CASE WHEN $7::boolean THEN $8::integer ELSE default_ttl_seconds END,
         updated_at = now()
       WHERE user_id = $1 AND ${col} = $2
       RETURNING id`,
      [userId, targetId, ...args]
    );
    if (!upd.rowCount) {
      await c.query(
        `INSERT INTO chat_prefs (user_id, ${col}, pinned, archived, muted_until, default_ttl_seconds)
         VALUES ($1, $2, COALESCE($3::boolean, false), COALESCE($4::boolean, false),
                 CASE WHEN $5::boolean THEN $6::timestamptz END,
                 CASE WHEN $7::boolean THEN $8::integer END)`,
        [userId, targetId, ...args]
      );
    }

    await c.query(
      `DELETE FROM chat_prefs
       WHERE user_id = $1 AND ${col} = $2
         AND NOT pinned AND NOT archived
         AND (muted_until IS NULL OR muted_until <= now())
         AND default_ttl_seconds IS NULL`,
      [userId, targetId]
    );

    const { rows } = await c.query(`${SELECT} WHERE p.user_id = $1 AND p.${col} = $2`, [userId, targetId]);
    return { pref: rows[0] ?? null };
  });
}

// File: server/src/models/ChatPrefs.js
// End of file