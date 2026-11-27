// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/Group.js
// Purpose : Data-access layer for group chats. Owns every SQL statement that
//           touches chat_groups, group_members and group_key_envelopes.
//           Group state-changing operations run inside ONE transaction that
//           first locks the group row (SELECT ... FOR UPDATE), so two admins
//           acting at the same moment cannot corrupt membership or key state.
//           Permission rules live here, not only in the routes, so any caller
//           is protected: only admins can rename, add, remove, promote or
//           rekey; a group always keeps at least one admin (the longest-standing
//           member is promoted automatically if the last admin leaves); an
//           emptied group is deleted. Adding someone who blocked you (or whom
//           you blocked) fails with a generic "cannot_add" so block status is
//           never revealed. Removal, leaving, or a member rotating keys sets
//           needs_rekey: no messages can be sent until an admin supplies new
//           wrapped keys for exactly the current members. The server cannot read
//           group keys; it only stores the wrapped envelopes and checks that
//           they cover the right people.
// =============================================================================
import { query, withTransaction } from '../config/db.js';

export const MAX_MEMBERS = 50;
export const MAX_GROUPS_PER_USER = 100;

// Locks the group row and returns the caller's role; null means "no such group or not a member".
async function lockAsMember(c, groupId, actorId) {
  const { rows } = await c.query(
    `SELECT g.id, g.epoch, g.needs_rekey, gm.role
     FROM chat_groups g
     JOIN group_members gm ON gm.group_id = g.id AND gm.user_id = $2
     WHERE g.id = $1
     FOR UPDATE OF g`,
    [groupId, actorId]
  );
  return rows[0] || null;
}

// The envelope list must cover exactly the expected member ids: no one missing, no extras, no duplicates.
function assertCoverage(expectedIds, envelopes) {
  const want = new Set(expectedIds);
  const got = new Set(envelopes.map((e) => e.userId));
  const ok =
    want.size === expectedIds.length &&
    got.size === envelopes.length &&
    want.size === got.size &&
    [...want].every((id) => got.has(id));
  if (!ok) {
    const err = new Error('Envelopes must cover exactly the group members');
    err.code = 'BAD_ENVELOPES';
    throw err;
  }
}

// Stores wrapped group keys for one epoch. The wrapper's public key is snapshotted so the
// recipient can still unwrap even if the wrapper later rotates keys or deletes their account.
async function insertEnvelopes(c, groupId, epoch, wrapperId, envelopes) {
  const w = await c.query('SELECT public_key FROM users WHERE id = $1', [wrapperId]);
  await c.query(
    `INSERT INTO group_key_envelopes (group_id, epoch, user_id, wrapped_by, wrapper_public_key, wrapped_key, iv)
     SELECT $1::uuid, $2::int, t.u, $3::uuid, $4::jsonb, t.w, t.i
     FROM unnest($5::uuid[], $6::text[], $7::text[]) AS t(u, w, i)`,
    [
      groupId,
      epoch,
      wrapperId,
      JSON.stringify(w.rows[0].public_key),
      envelopes.map((e) => e.userId),
      envelopes.map((e) => e.wrappedKey),
      envelopes.map((e) => e.iv),
    ]
  );
}

// Returns 'cannot_add' (deliberately generic) if any user is missing, blocked either way, or in too many groups.
async function checkAddable(c, actorId, userIds) {
  if (userIds.length === 0) return null;
  const found = await c.query('SELECT id FROM users WHERE id = ANY($1::uuid[])', [userIds]);
  if (found.rowCount !== userIds.length) return 'cannot_add';
  const blocked = await c.query(
    `SELECT 1 FROM blocks
     WHERE (blocker_id = $1 AND blocked_id = ANY($2::uuid[]))
        OR (blocked_id = $1 AND blocker_id = ANY($2::uuid[]))
     LIMIT 1`,
    [actorId, userIds]
  );
  if (blocked.rowCount) return 'cannot_add';
  const full = await c.query(
    `SELECT 1 FROM group_members WHERE user_id = ANY($1::uuid[])
     GROUP BY user_id HAVING count(*) >= $2 LIMIT 1`,
    [userIds, MAX_GROUPS_PER_USER]
  );
  if (full.rowCount) return 'cannot_add';
  return null;
}

// Removes one member and keeps the group consistent. Must run inside a transaction.
async function removeMemberInternal(c, groupId, userId) {
  const del = await c.query('DELETE FROM group_members WHERE group_id = $1 AND user_id = $2', [groupId, userId]);
  if (!del.rowCount) return null;
  await c.query('DELETE FROM group_key_envelopes WHERE group_id = $1 AND user_id = $2', [groupId, userId]);

  const left = await c.query(
    `SELECT count(*)::int AS n, (count(*) FILTER (WHERE role = 'admin'))::int AS admins
     FROM group_members WHERE group_id = $1`,
    [groupId]
  );
  const { n, admins } = left.rows[0];
  if (n === 0) {
    await c.query('DELETE FROM chat_groups WHERE id = $1', [groupId]);
    return { deleted: true, promoted: null };
  }

  let promoted = null;
  if (admins === 0) {
    const p = await c.query(
      `UPDATE group_members SET role = 'admin'
       WHERE (group_id, user_id) = (
         SELECT group_id, user_id FROM group_members
         WHERE group_id = $1 ORDER BY joined_at, user_id LIMIT 1
       )
       RETURNING user_id`,
      [groupId]
    );
    promoted = p.rows[0].user_id;
  }
  await c.query('UPDATE chat_groups SET needs_rekey = true, updated_at = now() WHERE id = $1', [groupId]);
  return { deleted: false, promoted };
}

export async function createGroup({ creatorId, name, memberIds, envelopes }) {
  return withTransaction(async (c) => {
    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`groups:user:${creatorId}`]);
    const everyone = [creatorId, ...memberIds];
    assertCoverage(everyone, envelopes);

    const mine = await c.query('SELECT count(*)::int AS n FROM group_members WHERE user_id = $1', [creatorId]);
    if (mine.rows[0].n >= MAX_GROUPS_PER_USER) return { error: 'limit' };
    const bad = await checkAddable(c, creatorId, memberIds);
    if (bad) return { error: bad };

    const g = await c.query('INSERT INTO chat_groups (name, created_by) VALUES ($1, $2) RETURNING id, name, epoch', [
      name,
      creatorId,
    ]);
    const groupId = g.rows[0].id;
    await c.query(
      `INSERT INTO group_members (group_id, user_id, role)
       SELECT $1::uuid, u, CASE WHEN u = $2::uuid THEN 'admin' ELSE 'member' END
       FROM unnest($3::uuid[]) AS u`,
      [groupId, creatorId, everyone]
    );
    await insertEnvelopes(c, groupId, 1, creatorId, envelopes);
    return { group: g.rows[0] };
  });
}

export async function listGroupsForUser(userId) {
  const { rows } = await query(
    `SELECT g.id, g.name, g.epoch, g.needs_rekey, gm.role,
            (SELECT count(*)::int FROM group_members x WHERE x.group_id = g.id) AS member_count
     FROM group_members gm JOIN chat_groups g ON g.id = gm.group_id
     WHERE gm.user_id = $1
     ORDER BY g.updated_at DESC`,
    [userId]
  );
  return rows;
}

// Group details plus every member's public key (needed by clients to wrap keys). Null if not a member.
export async function getGroupForMember(groupId, userId) {
  const g = await query(
    `SELECT g.id, g.name, g.epoch, g.needs_rekey, gm.role, gm.joined_at
     FROM chat_groups g JOIN group_members gm ON gm.group_id = g.id AND gm.user_id = $2
     WHERE g.id = $1`,
    [groupId, userId]
  );
  if (!g.rows[0]) return null;
  const m = await query(
    `SELECT u.id, u.username, u.public_key, gm.role, gm.joined_at
     FROM group_members gm JOIN users u ON u.id = gm.user_id
     WHERE gm.group_id = $1
     ORDER BY gm.joined_at, u.username`,
    [groupId]
  );
  return { group: g.rows[0], members: m.rows };
}

export async function getMembership(groupId, userId) {
  const { rows } = await query(
    `SELECT g.epoch, g.needs_rekey, gm.role, gm.joined_at
     FROM chat_groups g JOIN group_members gm ON gm.group_id = g.id AND gm.user_id = $2
     WHERE g.id = $1`,
    [groupId, userId]
  );
  return rows[0] || null;
}

export async function listMemberIds(groupId) {
  const { rows } = await query('SELECT user_id FROM group_members WHERE group_id = $1', [groupId]);
  return rows.map((r) => r.user_id);
}

export async function renameGroup({ groupId, actorId, name }) {
  return withTransaction(async (c) => {
    const me = await lockAsMember(c, groupId, actorId);
    if (!me) return 'not_found';
    if (me.role !== 'admin') return 'forbidden';
    await c.query('UPDATE chat_groups SET name = $2, updated_at = now() WHERE id = $1', [groupId, name]);
    return 'ok';
  });
}

// envelope = { wrappedKey, iv }: the current epoch key wrapped for the new member by the acting admin.
export async function addMember({ groupId, actorId, userId, envelope }) {
  return withTransaction(async (c) => {
    const me = await lockAsMember(c, groupId, actorId);
    if (!me) return 'not_found';
    if (me.role !== 'admin') return 'forbidden';
    if (me.needs_rekey) return 'needs_rekey';

    const count = await c.query('SELECT count(*)::int AS n FROM group_members WHERE group_id = $1', [groupId]);
    if (count.rows[0].n >= MAX_MEMBERS) return 'full';
    const already = await c.query('SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2', [groupId, userId]);
    if (already.rowCount) return 'exists';
    const bad = await checkAddable(c, actorId, [userId]);
    if (bad) return bad;

    await c.query('INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)', [groupId, userId]);
    await insertEnvelopes(c, groupId, me.epoch, actorId, [{ userId, ...envelope }]);
    await c.query('UPDATE chat_groups SET updated_at = now() WHERE id = $1', [groupId]);
    return 'added';
  });
}

export async function removeMember({ groupId, actorId, targetId }) {
  return withTransaction(async (c) => {
    const me = await lockAsMember(c, groupId, actorId);
    if (!me) return 'not_found';
    if (me.role !== 'admin') return 'forbidden';
    if (actorId === targetId) return 'self';
    const res = await removeMemberInternal(c, groupId, targetId);
    return res ? 'removed' : 'target_missing';
  });
}

// Returns { deleted, promoted } or null if the caller was not a member.
export async function leaveGroup({ groupId, userId }) {
  return withTransaction(async (c) => {
    const me = await lockAsMember(c, groupId, userId);
    if (!me) return null;
    return removeMemberInternal(c, groupId, userId);
  });
}

// Used when an account is deleted. Runs inside the caller's transaction.
export async function leaveAllGroups(c, userId) {
  const { rows } = await c.query('SELECT group_id FROM group_members WHERE user_id = $1', [userId]);
  const affected = [];
  for (const r of rows) {
    await c.query('SELECT id FROM chat_groups WHERE id = $1 FOR UPDATE', [r.group_id]);
    const res = await removeMemberInternal(c, r.group_id, userId);
    if (res) affected.push({ groupId: r.group_id, deleted: res.deleted });
  }
  return affected;
}

export async function setRole({ groupId, actorId, targetId, role }) {
  return withTransaction(async (c) => {
    const me = await lockAsMember(c, groupId, actorId);
    if (!me) return 'not_found';
    if (me.role !== 'admin') return 'forbidden';
    const t = await c.query('SELECT role FROM group_members WHERE group_id = $1 AND user_id = $2', [groupId, targetId]);
    if (!t.rowCount) return 'target_missing';
    if (t.rows[0].role === role) return 'ok';
    if (role === 'member') {
      const a = await c.query(
        "SELECT count(*)::int AS n FROM group_members WHERE group_id = $1 AND role = 'admin'",
        [groupId]
      );
      if (a.rows[0].n <= 1) return 'last_admin';
    }
    await c.query('UPDATE group_members SET role = $3 WHERE group_id = $1 AND user_id = $2', [groupId, targetId, role]);
    await c.query('UPDATE chat_groups SET updated_at = now() WHERE id = $1', [groupId]);
    return 'ok';
  });
}

// Starts a new key epoch. fromEpoch must match the server's epoch (guards against two admins racing).
export async function rekey({ groupId, actorId, fromEpoch, envelopes }) {
  return withTransaction(async (c) => {
    const me = await lockAsMember(c, groupId, actorId);
    if (!me) return { error: 'not_found' };
    if (me.role !== 'admin') return { error: 'forbidden' };
    if (me.epoch !== fromEpoch) return { error: 'stale' };

    const ids = await c.query('SELECT user_id FROM group_members WHERE group_id = $1', [groupId]);
    assertCoverage(ids.rows.map((r) => r.user_id), envelopes);

    const next = me.epoch + 1;
    await c.query('UPDATE chat_groups SET epoch = $2, needs_rekey = false, updated_at = now() WHERE id = $1', [
      groupId,
      next,
    ]);
    await insertEnvelopes(c, groupId, next, actorId, envelopes);
    return { epoch: next };
  });
}

export async function listMyEnvelopes(groupId, userId) {
  const { rows } = await query(
    `SELECT epoch, wrapped_key, iv, wrapped_by, wrapper_public_key
     FROM group_key_envelopes
     WHERE group_id = $1 AND user_id = $2
     ORDER BY epoch`,
    [groupId, userId]
  );
  return rows;
}

// File: server/src/models/Group.js
// End of file