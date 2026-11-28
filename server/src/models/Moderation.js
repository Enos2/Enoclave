// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/Moderation.js
// Purpose : Data-access layer for reports, suspensions and the moderation audit
//           trail. REPORTING (createReport): runs in one transaction under a
//           per-reporter lock, so parallel requests cannot dodge the limits
//           (10 reports per hour, 50 open at once, and a reporter with 10+
//           dismissed reports in 30 days is paused). The target is resolved
//           and VERIFIED here: a user (not yourself); a direct message (only
//           its recipient may report it); a group message (only a member who
//           could see it, never your own). For messages the SERVER snapshots
//           ciphertext, iv, epoch and send time, so unsending cannot erase the
//           evidence and the sender attribution is trustworthy; any plaintext
//           the reporter adds is stored separately and stays unverified. After
//           inserting, the anti-brigading rule flags every open report against
//           a user once 5 different people reported them within 24 hours.
//           ADMIN functions: list/filter reports, read one, resolve or dismiss
//           (once), search users with their open-report counts, list actions.
//           suspendUser (transaction, row lock) refuses to suspend yourself or
//           another admin, sets the suspension, bumps token_version, revokes
//           every session, optionally closes the linked report and logs the
//           action; unsuspendUser reverses it. sweepModeration deletes resolved
//           reports after 180 days and actions after 1 year. All queries are
//           parameterised.
// =============================================================================
import { query, withTransaction } from '../config/db.js';

export const REASONS = ['spam', 'harassment', 'scam', 'illegal', 'impersonation', 'other'];
const LIMITS = { perHour: 10, open: 50, dismissed30d: 10, brigadeReporters: 5 };

// Finds and verifies what is being reported. Returns the target facts or { error }.
async function resolveTarget(c, { reporterId, type, targetUserId, messageId }) {
  if (type === 'user') {
    if (targetUserId === reporterId) return { error: 'self' };
    const u = await c.query('SELECT id, username FROM users WHERE id = $1', [targetUserId]);
    if (!u.rowCount) return { error: 'not_found' };
    return { userId: u.rows[0].id, username: u.rows[0].username };
  }

  if (type === 'message') {
    const m = await c.query(
      `SELECT m.from_id, m.ciphertext, m.iv, m.created_at, u.username
       FROM messages m JOIN users u ON u.id = m.from_id
       WHERE m.id = $1 AND m.to_id = $2 AND (m.expires_at IS NULL OR m.expires_at > now())`,
      [messageId, reporterId]
    );
    if (!m.rowCount) return { error: 'not_found' };
    const r = m.rows[0];
    return { userId: r.from_id, username: r.username, ciphertext: r.ciphertext, iv: r.iv, sentAt: r.created_at };
  }

  const m = await c.query(
    `SELECT m.from_id, m.group_id, m.epoch, m.ciphertext, m.iv, m.created_at, u.username
     FROM group_messages m
     JOIN group_members gm ON gm.group_id = m.group_id AND gm.user_id = $2
     JOIN users u ON u.id = m.from_id
     WHERE m.id = $1 AND m.created_at >= gm.joined_at AND (m.expires_at IS NULL OR m.expires_at > now())`,
    [messageId, reporterId]
  );
  if (!m.rowCount) return { error: 'not_found' };
  const r = m.rows[0];
  if (r.from_id === reporterId) return { error: 'self' };
  return {
    userId: r.from_id,
    username: r.username,
    groupId: r.group_id,
    epoch: r.epoch,
    ciphertext: r.ciphertext,
    iv: r.iv,
    sentAt: r.created_at,
  };
}

// Returns { report } or { error: 'limit' | 'restricted' | 'self' | 'not_found' }.
// A duplicate open report raises a unique-violation error (code 23505) for the route to map to 409.
export async function createReport({ reporterId, type, targetUserId, messageId, reason, note, evidence }) {
  return withTransaction(async (c) => {
    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`reports:${reporterId}`]);

    const s = await c.query(
      `SELECT (count(*) FILTER (WHERE created_at > now() - interval '1 hour'))::int AS hour,
              (count(*) FILTER (WHERE status = 'open'))::int AS open,
              (count(*) FILTER (WHERE status = 'dismissed' AND created_at > now() - interval '30 days'))::int AS dismissed
       FROM reports WHERE reporter_id = $1`,
      [reporterId]
    );
    const { hour, open, dismissed } = s.rows[0];
    if (dismissed >= LIMITS.dismissed30d) return { error: 'restricted' };
    if (hour >= LIMITS.perHour || open >= LIMITS.open) return { error: 'limit' };

    const t = await resolveTarget(c, { reporterId, type, targetUserId, messageId });
    if (t.error) return t;

    const ins = await c.query(
      `INSERT INTO reports (reporter_id, reported_user_id, reported_username, target_type, message_id, group_id,
                            reason, note, evidence_text, evidence_ciphertext, evidence_iv, evidence_epoch, evidence_sent_at)
       VALUES ($1, $2, $3, $4, $5::uuid, $6::uuid, $7, $8, $9, $10, $11, $12::integer, $13::timestamptz)
       RETURNING id, status, created_at`,
      [
        reporterId,
        t.userId,
        t.username,
        type,
        messageId ?? null,
        t.groupId ?? null,
        reason,
        note ?? null,
        evidence ?? null,
        t.ciphertext ?? null,
        t.iv ?? null,
        t.epoch ?? null,
        t.sentAt ?? null,
      ]
    );

    await c.query(
      `UPDATE reports SET flagged = true
       WHERE reported_user_id = $1 AND status = 'open' AND flagged = false
         AND (SELECT count(DISTINCT reporter_id) FROM reports
              WHERE reported_user_id = $1 AND status = 'open' AND created_at > now() - interval '24 hours') >= $2`,
      [t.userId, LIMITS.brigadeReporters]
    );
    return { report: ins.rows[0] };
  });
}

export async function listMyReports(reporterId) {
  const { rows } = await query(
    `SELECT id, target_type, reason, status, created_at
     FROM reports WHERE reporter_id = $1 ORDER BY created_at DESC LIMIT 50`,
    [reporterId]
  );
  return rows;
}

export async function adminListReports({ status, flagged, limit, before }) {
  const { rows } = await query(
    `SELECT r.id, r.target_type, r.reason, r.status, r.flagged, r.created_at, r.resolved_at,
            r.reporter_id, ru.username AS reporter_username,
            r.reported_user_id, r.reported_username,
            (SELECT count(*)::int FROM reports x WHERE x.reported_user_id = r.reported_user_id AND x.status = 'open') AS open_against
     FROM reports r LEFT JOIN users ru ON ru.id = r.reporter_id
     WHERE ($1::text IS NULL OR r.status = $1)
       AND ($2::boolean IS NULL OR r.flagged = $2)
       AND ($3::timestamptz IS NULL OR r.created_at < $3)
     ORDER BY r.created_at DESC
     LIMIT $4`,
    [status ?? null, flagged ?? null, before ?? null, limit]
  );
  return rows;
}

export async function adminGetReport(id) {
  const { rows } = await query(
    `SELECT r.*, ru.username AS reporter_username,
            (SELECT (suspended_until IS NOT NULL AND suspended_until > now()) FROM users WHERE id = r.reported_user_id) AS reported_suspended,
            (SELECT count(*)::int FROM reports x WHERE x.reported_user_id = r.reported_user_id AND x.status = 'open') AS open_against
     FROM reports r LEFT JOIN users ru ON ru.id = r.reporter_id
     WHERE r.id = $1`,
    [id]
  );
  return rows[0] || null;
}

// Returns 'ok' | 'not_found' | 'resolved' (already closed). Closing is final.
export async function resolveReport({ reportId, adminId, status, note }) {
  return withTransaction(async (c) => {
    const r = await c.query(
      `UPDATE reports SET status = $2, resolved_by = $3, resolution_note = $4, resolved_at = now()
       WHERE id = $1 AND status = 'open'
       RETURNING reported_user_id, reported_username`,
      [reportId, status, adminId, note ?? null]
    );
    if (!r.rowCount) {
      const exists = await c.query('SELECT 1 FROM reports WHERE id = $1', [reportId]);
      return exists.rowCount ? 'resolved' : 'not_found';
    }
    await c.query(
      `INSERT INTO moderation_actions (admin_id, target_user_id, target_username, action, reason, report_id)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [adminId, r.rows[0].reported_user_id, r.rows[0].reported_username, status === 'actioned' ? 'resolve' : 'dismiss', note ?? null, reportId]
    );
    return 'ok';
  });
}

// seconds = null means permanent. Returns { username, until } or { error: 'not_found' | 'forbidden' }.
export async function suspendUser({ adminId, userId, seconds, reason, reportId }) {
  return withTransaction(async (c) => {
    const t = await c.query('SELECT id, is_admin FROM users WHERE id = $1 FOR UPDATE', [userId]);
    if (!t.rowCount) return { error: 'not_found' };
    if (t.rows[0].id === adminId || t.rows[0].is_admin) return { error: 'forbidden' };

    const up = await c.query(
      `UPDATE users
       SET suspended_until = CASE WHEN $2::double precision IS NULL THEN 'infinity'::timestamptz
                                  ELSE now() + make_interval(secs => $2::double precision) END,
           suspension_reason = $3, token_version = token_version + 1, updated_at = now()
       WHERE id = $1
       RETURNING username, suspended_until`,
      [userId, seconds, reason]
    );
    await c.query('UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL', [userId]);
    if (reportId) {
      await c.query(
        `UPDATE reports SET status = 'actioned', resolved_by = $2, resolution_note = $3, resolved_at = now()
         WHERE id = $1 AND status = 'open'`,
        [reportId, adminId, reason]
      );
    }
    await c.query(
      `INSERT INTO moderation_actions (admin_id, target_user_id, target_username, action, reason, until, report_id)
       VALUES ($1, $2, $3, 'suspend', $4, $5, $6)`,
      [adminId, userId, up.rows[0].username, reason, up.rows[0].suspended_until, reportId ?? null]
    );
    return { username: up.rows[0].username, until: up.rows[0].suspended_until };
  });
}

// Returns 'ok' | 'not_found' (no such user, or not suspended).
export async function unsuspendUser({ adminId, userId }) {
  return withTransaction(async (c) => {
    const r = await c.query(
      `UPDATE users SET suspended_until = NULL, suspension_reason = NULL, updated_at = now()
       WHERE id = $1 AND suspended_until IS NOT NULL
       RETURNING username`,
      [userId]
    );
    if (!r.rowCount) return 'not_found';
    await c.query(
      `INSERT INTO moderation_actions (admin_id, target_user_id, target_username, action)
       VALUES ($1, $2, $3, 'unsuspend')`,
      [adminId, userId, r.rows[0].username]
    );
    return 'ok';
  });
}

export async function adminSearchUsers(prefix) {
  const pattern = `${prefix.replace(/_/g, '\\_')}%`;
  const { rows } = await query(
    `SELECT u.id, u.username, u.is_admin,
            (u.suspended_until IS NOT NULL AND u.suspended_until > now()) AS suspended,
            u.suspended_until, u.suspension_reason,
            (SELECT count(*)::int FROM reports r WHERE r.reported_user_id = u.id AND r.status = 'open') AS open_reports
     FROM users u WHERE u.username LIKE $1 ESCAPE '\\'
     ORDER BY u.username LIMIT 20`,
    [pattern]
  );
  return rows;
}

export async function listActions(limit) {
  const { rows } = await query(
    `SELECT a.id, a.action, a.target_user_id, a.target_username, a.reason, a.until, a.report_id, a.created_at,
            u.username AS admin_username
     FROM moderation_actions a LEFT JOIN users u ON u.id = a.admin_id
     ORDER BY a.id DESC LIMIT $1`,
    [limit]
  );
  return rows;
}

export async function sweepModeration() {
  await query("DELETE FROM reports WHERE status <> 'open' AND resolved_at < now() - interval '180 days'");
  await query("DELETE FROM moderation_actions WHERE created_at < now() - interval '365 days'");
}

// File: server/src/models/Moderation.js
// End of file