// File: server/src/models/User.js
// Purpose: PostgreSQL data access for users. Parameterised queries only; never builds SQL from input.
import { query } from '../config/db.js';

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

export async function updatePublicKey(id, publicKey) {
  const { rows } = await query(
    `UPDATE users SET public_key = $2::jsonb, updated_at = now()
     WHERE id = $1
     RETURNING ${COLS}`,
    [id, JSON.stringify(publicKey)]
  );
  return rows[0] || null;
}

export async function bumpTokenVersion(id) {
  await query('UPDATE users SET token_version = token_version + 1 WHERE id = $1', [id]);
}

// Messages, sessions, contacts and blocks are removed automatically (ON DELETE CASCADE).
export async function deleteUser(id) {
  await query('DELETE FROM users WHERE id = $1', [id]);
}

// File: server/src/models/User.js
// End of file