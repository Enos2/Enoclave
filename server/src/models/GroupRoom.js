// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/GroupRoom.js
// Purpose : Data-access layer for self-destruct rooms: group chats that destroy
//           themselves at a chosen time. setLifespan lets a group ADMIN set or
//           clear the expiry (10 seconds to 30 days from now); non-admins get
//           'forbidden', non-members 'not_found' so room ids cannot be probed.
//           getLifespan returns the expiry plus the server clock, so clients
//           can show a countdown even if their own clock is wrong.
//           destroyExpiredGroups is called by the room sweeper: in ONE
//           statement it finds expired rooms (skipping any another process is
//           already handling), records who the members were, then deletes the
//           rooms; the database cascade removes their messages, wrapped keys,
//           invites and join requests. It returns each destroyed room with its
//           member ids so the caller can notify them in realtime.
// =============================================================================
import { query } from '../config/db.js';
import { getMembership } from './Group.js';

export const MIN_LIFESPAN_SECONDS = 10;
export const MAX_LIFESPAN_SECONDS = 30 * 24 * 60 * 60;

// lifespanSeconds = null clears the expiry (the room lives until everyone leaves).
export async function setLifespan({ groupId, actorId, lifespanSeconds }) {
  const m = await getMembership(groupId, actorId);
  if (!m) return { error: 'not_found' };
  if (m.role !== 'admin') return { error: 'forbidden' };
  const { rows } = await query(
    `UPDATE chat_groups
     SET expires_at = CASE WHEN $2::double precision IS NULL THEN NULL
                           ELSE now() + make_interval(secs => $2::double precision) END,
         updated_at = now()
     WHERE id = $1 AND (expires_at IS NULL OR expires_at > now())
     RETURNING expires_at`,
    [groupId, lifespanSeconds]
  );
  if (!rows[0]) return { error: 'not_found' };
  return { expiresAt: rows[0].expires_at };
}

export async function getLifespan(groupId, userId) {
  const m = await getMembership(groupId, userId);
  if (!m) return null;
  const { rows } = await query('SELECT expires_at, now() AS server_time FROM chat_groups WHERE id = $1', [groupId]);
  return rows[0] || null;
}

// Returns [{ id, user_ids: [...] }] for every room destroyed by this call.
export async function destroyExpiredGroups() {
  const { rows } = await query(
    `WITH doomed AS (
       SELECT id FROM chat_groups
       WHERE expires_at IS NOT NULL AND expires_at <= now()
       FOR UPDATE SKIP LOCKED
     ),
     roster AS (
       SELECT gm.group_id, array_agg(gm.user_id) AS user_ids
       FROM group_members gm JOIN doomed d ON d.id = gm.group_id
       GROUP BY gm.group_id
     ),
     gone AS (
       DELETE FROM chat_groups g USING doomed d WHERE g.id = d.id RETURNING g.id
     )
     SELECT gone.id, COALESCE(roster.user_ids, '{}') AS user_ids
     FROM gone LEFT JOIN roster ON roster.group_id = gone.id`
  );
  return rows;
}

// File: server/src/models/GroupRoom.js
// End of file