// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/Attachment.js
// Purpose : Data-access layer for encrypted file and voice-note metadata (the
//           bytes themselves are handled by utils/storage.js). The server never
//           knows what a file is, only that it is an opaque blob of a declared
//           size, so file TYPES cannot be enforced here; clients restrict types,
//           the server enforces sizes and quotas.
//           createUpload checks, in one transaction under a per-user lock (so
//           two parallel requests cannot dodge the quota): the size limit for
//           the kind (25 MB files, 10 MB voice), the target (direct recipient
//           must exist and must not have blocked you - reported as "not found"
//           so a block is not revealed; or you must belong to a live group),
//           500 MB total stored per user, and at most 20 unfinished uploads.
//           claim/release/complete move an upload pending -> uploading -> ready
//           atomically, so two simultaneous uploads of the same file are
//           impossible. getAccessible returns a file only to its owner, its
//           direct recipient, or a group member who joined before it was
//           created. deleteFile allows the owner, or an admin of the file's
//           group. sweepFiles removes expired files and uploads left unfinished
//           for 30 minutes; existingIds lets the sweeper detect orphaned blobs.
// =============================================================================
import { query, withTransaction } from '../config/db.js';

export const MAX_FILE_BYTES = { file: 25 * 1024 * 1024, voice: 10 * 1024 * 1024 };
const MAX_STORED_BYTES = 500 * 1024 * 1024;
const MAX_UNFINISHED = 20;

export async function createUpload({ ownerId, kind, sizeBytes, recipientId, groupId, ttlSeconds }) {
  if (sizeBytes > MAX_FILE_BYTES[kind]) return { error: 'too_large' };

  return withTransaction(async (c) => {
    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`files:${ownerId}`]);

    if (recipientId) {
      const u = await c.query('SELECT 1 FROM users WHERE id = $1', [recipientId]);
      if (!u.rowCount) return { error: 'not_found' };
      const b = await c.query(
        `SELECT EXISTS (SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2) AS i_blocked,
                EXISTS (SELECT 1 FROM blocks WHERE blocker_id = $2 AND blocked_id = $1) AS blocked_me`,
        [ownerId, recipientId]
      );
      if (b.rows[0].blocked_me) return { error: 'not_found' };
      if (b.rows[0].i_blocked) return { error: 'unblock_first' };
    } else {
      const g = await c.query(
        `SELECT 1 FROM group_members gm JOIN chat_groups g ON g.id = gm.group_id
         WHERE gm.group_id = $1 AND gm.user_id = $2 AND (g.expires_at IS NULL OR g.expires_at > now())`,
        [groupId, ownerId]
      );
      if (!g.rowCount) return { error: 'not_found' };
    }

    const q = await c.query(
      `SELECT COALESCE(SUM(size_bytes), 0)::float8 AS used,
              (count(*) FILTER (WHERE status <> 'ready'))::int AS unfinished
       FROM files WHERE owner_id = $1 AND expires_at > now()`,
      [ownerId]
    );
    if (q.rows[0].used + sizeBytes > MAX_STORED_BYTES) return { error: 'quota' };
    if (q.rows[0].unfinished >= MAX_UNFINISHED) return { error: 'limit' };

    const ins = await c.query(
      `INSERT INTO files (owner_id, recipient_id, group_id, kind, size_bytes, expires_at)
       VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6::double precision))
       RETURNING id, expires_at`,
      [ownerId, recipientId ?? null, groupId ?? null, kind, sizeBytes, ttlSeconds]
    );
    return { file: ins.rows[0] };
  });
}

// pending -> uploading. Returns { id, size_bytes, kind } or null (not yours, not pending, or expired).
export async function claimUpload(id, ownerId) {
  const { rows } = await query(
    `UPDATE files SET status = 'uploading'
     WHERE id = $1 AND owner_id = $2 AND status = 'pending' AND expires_at > now()
     RETURNING id, kind, size_bytes::float8 AS size_bytes`,
    [id, ownerId]
  );
  return rows[0] || null;
}

// uploading -> pending (the upload failed and may be retried).
export async function releaseUpload(id) {
  await query("UPDATE files SET status = 'pending' WHERE id = $1 AND status = 'uploading'", [id]);
}

// uploading -> ready. Returns false if the row disappeared meanwhile (the caller then deletes the bytes).
export async function completeUpload(id, ownerId) {
  const { rowCount } = await query(
    "UPDATE files SET status = 'ready' WHERE id = $1 AND owner_id = $2 AND status = 'uploading'",
    [id, ownerId]
  );
  return rowCount > 0;
}

export async function getAccessible(id, userId) {
  const { rows } = await query(
    `SELECT f.id, f.kind, f.size_bytes::float8 AS size_bytes
     FROM files f
     WHERE f.id = $1 AND f.status = 'ready' AND f.expires_at > now()
       AND (f.owner_id = $2
            OR f.recipient_id = $2
            OR (f.group_id IS NOT NULL AND EXISTS (
                  SELECT 1 FROM group_members gm
                  WHERE gm.group_id = f.group_id AND gm.user_id = $2 AND gm.joined_at <= f.created_at)))`,
    [id, userId]
  );
  return rows[0] || null;
}

export async function deleteFile(id, actorId) {
  const { rows } = await query(
    `DELETE FROM files f
     WHERE f.id = $1
       AND (f.owner_id = $2
            OR (f.group_id IS NOT NULL AND EXISTS (
                  SELECT 1 FROM group_members gm
                  WHERE gm.group_id = f.group_id AND gm.user_id = $2 AND gm.role = 'admin')))
     RETURNING f.id`,
    [id, actorId]
  );
  return rows[0] || null;
}

// Deletes expired files and uploads unfinished for 30 minutes. Returns the ids so their bytes can be removed.
export async function sweepFiles() {
  const { rows } = await query(
    `DELETE FROM files
     WHERE expires_at <= now() OR (status <> 'ready' AND created_at < now() - interval '30 minutes')
     RETURNING id`
  );
  return rows.map((r) => r.id);
}

export async function existingIds(ids) {
  if (ids.length === 0) return [];
  const { rows } = await query('SELECT id FROM files WHERE id = ANY($1::uuid[])', [ids]);
  return rows.map((r) => r.id);
}

// File: server/src/models/Attachment.js
// End of file