// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/reports.js
// Purpose : HTTP API for ordinary users to report abuse, auto-mounted at
//           /api/reports. POST / files a report: type 'user' needs
//           targetUserId; types 'message' (a direct message you received) and
//           'group_message' need messageId. reason is one of spam, harassment,
//           scam, illegal, impersonation, other; note (max 1000 chars) and
//           evidence (max 4000 chars, the plaintext the reporter saw - stored
//           as UNVERIFIED) are optional. The body is validated with a strict
//           zod schema (unknown fields rejected, control characters refused).
//           The server verifies the target and snapshots the ciphertext (see
//           models/Moderation.js). GET /mine lists the caller's own reports and
//           their status. The reported user is never told. Errors: 400 invalid
//           or reporting yourself, 404 target not visible to you, 409 already
//           reported, 429 too many reports, 403 reporting paused for accounts
//           whose reports are repeatedly dismissed. Session required.
// =============================================================================
import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { reportLimiter, socialLimiter } from '../middleware/security.js';
import { isUuid } from '../utils/serialize.js';
import { REASONS, createReport, listMyReports } from '../models/Moderation.js';

const router = Router();
router.use(requireAuth);

const uuid = z.string().refine(isUuid);
const text = (max) =>
  z
    .string()
    .trim()
    .max(max)
    .refine((s) => !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(s));

const reportSchema = z
  .object({
    type: z.enum(['user', 'message', 'group_message']),
    targetUserId: uuid.optional(),
    messageId: uuid.optional(),
    reason: z.enum(REASONS),
    note: text(1000).optional(),
    evidence: text(4000).optional(),
  })
  .strict()
  .refine((b) => (b.type === 'user' ? Boolean(b.targetUserId) && !b.messageId : Boolean(b.messageId) && !b.targetUserId), {
    message: 'Invalid target',
  });

const ERRORS = {
  self: [400, 'Invalid input'],
  not_found: [404, 'Not found'],
  limit: [429, 'Too many reports. Try again later'],
  restricted: [403, 'Reporting is unavailable for your account right now'],
};

router.post('/', reportLimiter, validate(reportSchema), async (req, res, next) => {
  try {
    const r = await createReport({ reporterId: req.user.id, ...req.body });
    if (r.error) {
      const [status, error] = ERRORS[r.error];
      return res.status(status).json({ error });
    }
    return res.status(201).json({ report: { id: r.report.id, status: r.report.status, createdAt: r.report.created_at } });
  } catch (err) {
    if (err?.code === '23505') return res.status(409).json({ error: 'You already reported this' });
    return next(err);
  }
});

router.get('/mine', socialLimiter, async (req, res, next) => {
  try {
    const rows = await listMyReports(req.user.id);
    res.json({
      reports: rows.map((r) => ({ id: r.id, type: r.target_type, reason: r.reason, status: r.status, createdAt: r.created_at })),
    });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/reports.js
// End of file