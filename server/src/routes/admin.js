// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/admin.js
// Purpose : The moderation API for administrators, auto-mounted at /api/admin.
//           Every route requires a valid session AND is_admin (checked in the
//           database on each request); non-admins get 404 so the API cannot be
//           discovered. Reports: GET /reports (filters: status, flagged,
//           before, limit), GET /reports/:id (full detail; evidence shows the
//           server-verified ciphertext snapshot separately from the
//           reporter-supplied, unverified text), POST /reports/:id/resolve
//           { status: actioned | dismissed, note } (final: a closed report
//           cannot be reopened). Users: GET /users?q= (search with open-report
//           counts), POST /users/:id/suspend { durationSeconds (60 to one
//           year, or null for permanent - the field is REQUIRED so a permanent
//           ban is never accidental), reason, reportId? } and DELETE
//           /users/:id/suspension. Suspending revokes all of the user's
//           sessions and cuts their sockets after sending them an
//           'account:suspended' event; admins cannot be suspended. GET /actions
//           returns the audit trail. All bodies use strict zod schemas.
// =============================================================================
import { Router } from 'express';
import { z } from 'zod';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { adminLimiter } from '../middleware/security.js';
import { isUuid } from '../utils/serialize.js';
import {
  adminListReports,
  adminGetReport,
  resolveReport,
  suspendUser,
  unsuspendUser,
  adminSearchUsers,
  listActions,
} from '../models/Moderation.js';

const router = Router();
router.use(requireAuth, requireAdmin, adminLimiter);

const uuid = z.string().refine(isUuid);
const reason = z
  .string()
  .trim()
  .min(1)
  .max(300)
  .refine((s) => !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(s));

const resolveSchema = z
  .object({ status: z.enum(['actioned', 'dismissed']), note: reason.optional() })
  .strict();
const suspendSchema = z
  .object({
    durationSeconds: z.number().int().min(60).max(31_536_000).nullable(),
    reason,
    reportId: uuid.optional(),
  })
  .strict();

const clampLimit = (v, max) => Math.min(Math.max(parseInt(v, 10) || 50, 1), max);

router.get('/reports', async (req, res, next) => {
  try {
    const status = ['open', 'actioned', 'dismissed'].includes(req.query.status) ? req.query.status : null;
    const flagged = req.query.flagged === 'true' ? true : req.query.flagged === 'false' ? false : null;
    const raw = typeof req.query.before === 'string' ? Date.parse(req.query.before) : NaN;
    const before = Number.isNaN(raw) ? null : new Date(raw).toISOString();
    const limit = clampLimit(req.query.limit, 100);
    const rows = await adminListReports({ status, flagged, before, limit });
    res.json({
      reports: rows.map((r) => ({
        id: r.id,
        type: r.target_type,
        reason: r.reason,
        status: r.status,
        flagged: r.flagged,
        createdAt: r.created_at,
        resolvedAt: r.resolved_at,
        reporter: { id: r.reporter_id, username: r.reporter_username },
        reported: { id: r.reported_user_id, username: r.reported_username },
        openAgainstReported: r.open_against,
      })),
      nextBefore: rows.length === limit ? rows[rows.length - 1].created_at : null,
    });
  } catch (err) {
    next(err);
  }
});

router.get('/reports/:id', async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const r = await adminGetReport(req.params.id);
    if (!r) return res.status(404).json({ error: 'Not found' });
    res.json({
      report: {
        id: r.id,
        type: r.target_type,
        reason: r.reason,
        note: r.note,
        status: r.status,
        flagged: r.flagged,
        createdAt: r.created_at,
        resolvedAt: r.resolved_at,
        resolutionNote: r.resolution_note,
        reporter: { id: r.reporter_id, username: r.reporter_username },
        reported: { id: r.reported_user_id, username: r.reported_username, suspended: Boolean(r.reported_suspended) },
        openAgainstReported: r.open_against,
        messageId: r.message_id,
        groupId: r.group_id,
        evidence: {
          // Snapshot taken by the server at report time: sender, time and ciphertext are trustworthy.
          ciphertext: r.evidence_ciphertext,
          iv: r.evidence_iv,
          epoch: r.evidence_epoch,
          messageSentAt: r.evidence_sent_at,
          // Written by the reporter: the server cannot verify it.
          reporterSuppliedText: r.evidence_text,
        },
      },
    });
  } catch (err) {
    next(err);
  }
});

router.post('/reports/:id/resolve', validate(resolveSchema), async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const r = await resolveReport({
      reportId: req.params.id,
      adminId: req.user.id,
      status: req.body.status,
      note: req.body.note,
    });
    if (r === 'not_found') return res.status(404).json({ error: 'Not found' });
    if (r === 'resolved') return res.status(409).json({ error: 'This report is already closed' });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.get('/users', async (req, res, next) => {
  try {
    const q = typeof req.query.q === 'string' ? req.query.q.trim().toLowerCase() : '';
    if (!/^[a-z0-9_]{2,24}$/.test(q)) return res.json({ users: [] });
    const rows = await adminSearchUsers(q);
    res.json({
      users: rows.map((u) => ({
        id: u.id,
        username: u.username,
        isAdmin: u.is_admin,
        suspended: u.suspended,
        suspendedUntil: u.suspended_until instanceof Date ? u.suspended_until.toISOString() : null,
        permanent: u.suspended && !(u.suspended_until instanceof Date),
        suspensionReason: u.suspension_reason,
        openReports: u.open_reports,
      })),
    });
  } catch (err) {
    next(err);
  }
});

router.post('/users/:id/suspend', validate(suspendSchema), async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const r = await suspendUser({
      adminId: req.user.id,
      userId: req.params.id,
      seconds: req.body.durationSeconds,
      reason: req.body.reason,
      reportId: req.body.reportId,
    });
    if (r.error === 'forbidden') return res.status(403).json({ error: 'Admins cannot be suspended' });
    if (r.error) return res.status(404).json({ error: 'Not found' });

    const io = req.app.get('io');
    io?.to(`user:${req.params.id}`).emit('account:suspended', {});
    io?.in(`user:${req.params.id}`).disconnectSockets(true);
    const until = r.until instanceof Date ? r.until.toISOString() : null;
    res.json({ ok: true, permanent: until === null, until });
  } catch (err) {
    next(err);
  }
});

router.delete('/users/:id/suspension', async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const r = await unsuspendUser({ adminId: req.user.id, userId: req.params.id });
    if (r !== 'ok') return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.get('/actions', async (req, res, next) => {
  try {
    const rows = await listActions(clampLimit(req.query.limit, 200));
    res.json({
      actions: rows.map((a) => ({
        id: a.id,
        action: a.action,
        admin: a.admin_username,
        target: { id: a.target_user_id, username: a.target_username },
        reason: a.reason,
        until: a.until instanceof Date ? a.until.toISOString() : null,
        reportId: a.report_id,
        createdAt: a.created_at,
      })),
    });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/admin.js
// End of file