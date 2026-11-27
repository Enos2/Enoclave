// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/GroupInvite.js
// Purpose : Data-access layer for group invite links and join requests.
//           Invite flow: an admin creates an invite (the random token is
//           returned ONCE; only its SHA-256 hash is stored). Anyone logged in
//           can preview or redeem a token. Redeeming does NOT add the person:
//           it consumes one use and creates a pending join request, which an
//           admin approves (supplying the group key wrapped for the newcomer,
//           because only a member's client can do that) or denies.
//           Security rules: a missing, expired, revoked, used-up or blocked
//           invite all return the same generic 'invalid' result so nothing can
//           be probed; the invite row is locked while redeeming so a
//           single-use link can never be used twice by a race; per-group and
//           per-user caps stop request flooding; every admin action re-checks
//           membership and role; non-members get 'not_found', never
//           'forbidden', so groups cannot be discovered by id.
// =============================================================================
import crypto from 'node:crypto';
import { query, withTransaction } from '../config/db.js';
import { MAX_MEMBERS, addMember, getMembership } from './Group.js';

const MAX_ACTIVE_INVITES = 20;
const MAX_PENDING_PER_GROUP = 100;
const MAX_PENDING_PER_USER = 20;
const ACTIVE = 'i.revoked_at IS NULL AND i.expires_at > now() AND i.uses < i.max_uses';

export const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

// Returns null when the actor is an admin, otherwise the reason code.
async function adminCheck(groupId, actorId) {
  const m = await getMembership(groupId, actorId);
  if (!m) return 'not_found';
  if (m.role !== 'admin') return 'forbidden';
  return null;
}

export async function createInvite({ groupId, actorId, ttlSeconds, maxUses }) {
  return withTransaction(async (c) => {
    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`invites:${groupId}`]);
    const role = await c.query('SELECT role FROM group_members WHERE group_id = $1 AND user_id = $2', [
      groupId,
      actorId,
    ]);
    if (!role.rowCount) return { error: 'not_found' };
    if (role.rows[0].role !== 'admin') return { error: 'forbidden' };

    const active = await c.query(`SELECT count(*)::int AS n FROM group_invites i WHERE i.group_id = $1 AND ${ACTIVE}`, [
      groupId,
    ]);
    if (active.rows[0].n >= MAX_ACTIVE_INVITES) return { error: 'limit' };

    const token = crypto.randomBytes(32).toString('base64url'); // 43 characters, 256 bits
    const { rows } = await c.query(
      `INSERT INTO group_invites (group_id, created_by, token_hash, max_uses, expires_at)
       VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5::double precision))
       RETURNING id, max_uses, expires_at`,
      [groupId, actorId, hashToken(token), maxUses, ttlSeconds]
    );
    return { invite: rows[0], token };
  });
}

export async function listInvites(groupId, actorId) {
  const denied = await adminCheck(groupId, actorId);
  if (denied) return { error: denied };
  const { rows } = await query(
    `SELECT i.id, i.max_uses, i.uses, i.expires_at, i.created_at, u.username AS created_by_name
     FROM group_invites i LEFT JOIN users u ON u.id = i.created_by
     WHERE i.group_id = $1 AND ${ACTIVE}
     ORDER BY i.created_at DESC`,
    [groupId]
  );
  return { invites: rows };
}

export async function revokeInvite({ groupId, actorId, inviteId }) {
  const denied = await adminCheck(groupId, actorId);
  if (denied) return denied;
  const { rowCount } = await query(
    'UPDATE group_invites SET revoked_at = now() WHERE id = $1 AND group_id = $2 AND revoked_at IS NULL',
    [inviteId, groupId]
  );
  return rowCount ? 'ok' : 'target_missing';
}

// Shows what a link leads to. Returns null for any invalid link (same answer for every failure).
export async function previewInvite(token, userId) {
  const { rows } = await query(
    `SELECT g.name,
            (SELECT count(*)::int FROM group_members x WHERE x.group_id = g.id) AS member_count,
            EXISTS (SELECT 1 FROM group_members y WHERE y.group_id = g.id AND y.user_id = $2) AS already_member
     FROM group_invites i JOIN chat_groups g ON g.id = i.group_id
     WHERE i.token_hash = $1 AND ${ACTIVE}`,
    [hashToken(token), userId]
  );
  return rows[0] || null;
}

// Consumes one use and creates a pending request. Result: { status, groupId } or { error }.
export async function redeemInvite(token, userId) {
  return withTransaction(async (c) => {
    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`joinreq:${userId}`]);

    const inv = await c.query(
      `SELECT i.id, i.group_id, i.created_by
       FROM group_invites i
       WHERE i.token_hash = $1 AND ${ACTIVE}
       FOR UPDATE`,
      [hashToken(token)]
    );
    if (!inv.rowCount) return { error: 'invalid' };
    const { id: inviteId, group_id: groupId, created_by: creator } = inv.rows[0];

    const member = await c.query('SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2', [groupId, userId]);
    if (member.rowCount) return { status: 'member', groupId };
    const pending = await c.query('SELECT 1 FROM group_join_requests WHERE group_id = $1 AND user_id = $2', [
      groupId,
      userId,
    ]);
    if (pending.rowCount) return { status: 'pending', groupId };

    if (creator) {
      const blocked = await c.query(
        `SELECT 1 FROM blocks
         WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)`,
        [userId, creator]
      );
      if (blocked.rowCount) return { error: 'invalid' };
    }

    const size = await c.query(
      `SELECT (SELECT count(*)::int FROM group_members WHERE group_id = $1) AS members,
              (SELECT count(*)::int FROM group_join_requests WHERE group_id = $1) AS pending,
              (SELECT count(*)::int FROM group_join_requests WHERE user_id = $2) AS mine`,
      [groupId, userId]
    );
    const s = size.rows[0];
    if (s.members >= MAX_MEMBERS) return { error: 'full' };
    if (s.pending >= MAX_PENDING_PER_GROUP || s.mine >= MAX_PENDING_PER_USER) return { error: 'limit' };

    await c.query('UPDATE group_invites SET uses = uses + 1 WHERE id = $1', [inviteId]);
    await c.query('INSERT INTO group_join_requests (group_id, user_id, invite_id) VALUES ($1, $2, $3)', [
      groupId,
      userId,
      inviteId,
    ]);
    return { status: 'pending', groupId };
  });
}

// Includes each requester's public key, which the approving admin's client needs to wrap the group key.
export async function listJoinRequests(groupId, actorId) {
  const denied = await adminCheck(groupId, actorId);
  if (denied) return { error: denied };
  const { rows } = await query(
    `SELECT u.id, u.username, u.public_key, r.created_at
     FROM group_join_requests r JOIN users u ON u.id = r.user_id
     WHERE r.group_id = $1
     ORDER BY r.created_at`,
    [groupId]
  );
  return { requests: rows };
}

async function deleteRequest(groupId, userId) {
  const { rowCount } = await query('DELETE FROM group_join_requests WHERE group_id = $1 AND user_id = $2', [
    groupId,
    userId,
  ]);
  return rowCount > 0;
}

// Adds the requester using the normal addMember rules (admin check, rekey pending, size, blocks).
export async function approveJoinRequest({ groupId, actorId, userId, envelope }) {
  const denied = await adminCheck(groupId, actorId);
  if (denied) return denied;
  const exists = await query('SELECT 1 FROM group_join_requests WHERE group_id = $1 AND user_id = $2', [
    groupId,
    userId,
  ]);
  if (!exists.rowCount) return 'target_missing';

  const result = await addMember({ groupId, actorId, userId, envelope });
  if (result === 'added' || result === 'exists') {
    await deleteRequest(groupId, userId);
    return 'added';
  }
  if (result === 'cannot_add') await deleteRequest(groupId, userId); // user vanished or got blocked: clear it
  return result;
}

export async function denyJoinRequest({ groupId, actorId, userId }) {
  const denied = await adminCheck(groupId, actorId);
  if (denied) return denied;
  return (await deleteRequest(groupId, userId)) ? 'ok' : 'target_missing';
}

export async function listAdminIds(groupId) {
  const { rows } = await query("SELECT user_id FROM group_members WHERE group_id = $1 AND role = 'admin'", [groupId]);
  return rows.map((r) => r.user_id);
}

// File: server/src/models/GroupInvite.js
// End of file