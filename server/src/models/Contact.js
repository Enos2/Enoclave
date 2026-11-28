// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/Contact.js
// Purpose : Data-access layer for each user's contact list. listContacts
//           returns a user's contacts; addContact runs in a transaction
//           under a per-user advisory lock, so parallel requests cannot
//           exceed the 500-contact cap, and refuses to add someone you have
//           blocked; removeContact deletes one. Contacts are one-directional
//           records; presence is shown only between MUTUAL contacts (both
//           added each other), which models/Presence.js enforces. Every
//           query is parameterised.
// =============================================================================
import { query, withTransaction } from '../config/db.js';

const MAX_CONTACTS = 500;

export async function listContacts(ownerId) {
  const { rows } = await query(
    `SELECT u.id, u.username, c.created_at
     FROM contacts c JOIN users u ON u.id = c.contact_id
     WHERE c.owner_id = $1
     ORDER BY u.username`,
    [ownerId]
  );
  return rows;
}

// Returns 'added' | 'exists' | 'blocked' | 'limit'. A missing user raises a FK error (code 23503).
export async function addContact(ownerId, contactId) {
  return withTransaction(async (c) => {
    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`contacts:${ownerId}`]);
    const existing = await c.query('SELECT 1 FROM contacts WHERE owner_id = $1 AND contact_id = $2', [ownerId, contactId]);
    if (existing.rowCount) return 'exists';
    const blocked = await c.query('SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [ownerId, contactId]);
    if (blocked.rowCount) return 'blocked';
    const count = await c.query('SELECT count(*)::int AS n FROM contacts WHERE owner_id = $1', [ownerId]);
    if (count.rows[0].n >= MAX_CONTACTS) return 'limit';
    await c.query('INSERT INTO contacts (owner_id, contact_id) VALUES ($1, $2)', [ownerId, contactId]);
    return 'added';
  });
}

export async function removeContact(ownerId, contactId) {
  const { rowCount } = await query('DELETE FROM contacts WHERE owner_id = $1 AND contact_id = $2', [ownerId, contactId]);
  return rowCount > 0;
}

// File: server/src/models/Contact.js
// End of file