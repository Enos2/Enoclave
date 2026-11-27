// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/User.js
// Purpose : Data-access layer for user accounts. Every query is parameterised
//           ($1, $2 ...), so user input can never change the meaning of a SQL
//           statement. Handles create/find/search, public-key rotation and
//           account deletion. Two behaviours worth knowing:
//           (1) Rotating a public key flags every group the user belongs to
//               as needs_rekey, because the old wrapped group keys were
//               encrypted to the old key and the new device cannot open them.
//           (2) Deleting an account first removes the user from all groups
//               (promoting an admin or deleting the group if needed), then
//               deletes the user; the database cascades the rest.
// =============================================================================
import { query, withTransaction } from '../config/db.js';
import { leaveAllGroups } from './Group.js';

const COLS = 'id, username, public_key, token_version';

export async function createUser({ username, passwordHash, publicKey }) {
  const { rows } = await query(
    `INSERT INTO users (username, password_hash, public_key)
     VALUES ($1, $2, $3::jsonb)
     RETURNING ${COLS}`,
    [username, passwordHash, JSON.stringify(publicKey)]
  );
  return rows[0];
}

export async function findUserById(id) {
  const { rows } = await query(`SELECT ${COLS} FROM users WHERE id = $1`, [id]);
  return rows[0] || null;
}

export async function findUserWithHash(username) {
  const { rows } = await query(`SELECT ${COLS}, password_hash FROM users WHERE username = $1`, [username]);
  return rows[0] || null;
}

export async function getPasswordHash(id) {
  const { rows } = await query('SELECT password_hash FROM users WHERE id = $1', [id]);
  return rows[0]?.password_hash || null;
}

export async function userExists(id) {
  const { rowCount } = await query('SELECT 1 FROM users WHERE id = $1', [id]);
  return rowCount > 0;
}

// The prefix is already restricted to [a-z0-9_]; "_" is escaped because it is a LIKE wildcard.
// Users who have blocked the searcher are hidden from the results.
export async function searchUsers(prefix, searcherId) {
  const pattern = `${prefix.replace(/_/g, '\\_')}%`;
  const { rows } = await query(
    `SELECT u.id, u.username FROM users u
     WHERE u.username LIKE $1 ESCAPE '\\'
       AND u.id <> $2
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.blocker_id = u.id AND b.blocked_id = $2)
     ORDER BY u.username
     LIMIT 10`,
    [pattern, searcherId]
  );
  return rows;
}

// Returns { user, groupIds }. groupIds are the groups that now need a new key (so callers can notify members).
export async function updatePublicKey(id, publicKey) {
  const { rows } = await query(
    `UPDATE users SET public_key = $2::jsonb, updated_at = now()
     WHERE id = $1
     RETURNING ${COLS}`,
    [id, JSON.stringify(publicKey)]
  );
  if (!rows[0]) return { user: null, groupIds: [] };
  const flagged = await query(
    `UPDATE chat_groups SET needs_rekey = true, updated_at = now()
     WHERE id IN (SELECT group_id FROM group_members WHERE user_id = $1)
     RETURNING id`,
    [id]
  );
  return { user: rows[0], groupIds: flagged.rows.map((r) => r.id) };
}

export async function bumpTokenVersion(id) {
  await query('UPDATE users SET token_version = token_version + 1 WHERE id = $1', [id]);
}

// Returns the groups the user left, as [{ groupId, deleted }], so callers can notify remaining members.
export async function deleteUser(id) {
  return withTransaction(async (c) => {
    const affected = await leaveAllGroups(c, id);
    await c.query('DELETE FROM users WHERE id = $1', [id]);
    return affected;
  });
}

// File: server/src/models/User.js
// End of file