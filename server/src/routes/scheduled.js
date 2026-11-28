// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/scheduled.js
// Purpose : HTTP API for scheduled (time-locked) direct messages, auto-mounted
//           at /api/scheduled. POST / schedules a message { to, ciphertext, iv,
//           deliverAt (ISO 8601 with timezone), ttlSeconds?,
//           burnAfterReadSeconds? }: the client encrypts it exactly like a
//           normal message; the server stores ciphertext only and delivers it
//           at the chosen time (10 seconds to 30 days ahead, judged by the
//           server clock) through the delivery job. Disappearing and burn
//           timers start at DELIVERY. GET / lists your pending scheduled
//           messages (never their ciphertext). DELETE /:id cancels one (only
//           the sender can). Limits: 50 pending per user; you cannot schedule to
//           yourself or to someone you blocked. Errors: 400 invalid or time out
//           of range, 404 unknown recipient, 409 blocked or limit reached. The
//           body uses a strict zod schema; session required; rate limited.
//           Delivery results arrive over realtime (see jobs/scheduledDelivery.js).
// =============================================================================
import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { socialLimiter } from '../middleware/security.js';
import { isUuid } from '../utils/serialize.js';
import { createScheduled, listScheduled, cancelScheduled } from '../models/Scheduled.js';

const router = Router();
router.use(requireAuth, socialLimiter);

const base64 = /^[A-Za-z0-9+/=]+$/;
const createSchema = z
  .object({
    to: z.string().refine(isUuid),
    ciphertext: z.string().min(1).max(20000).regex(base64),
    iv: z.string().min(16).max(32).regex(base64),
    deliverAt: z.string().datetime({ offset: true }),
    ttlSeconds: z.number().int().min(5).max(604800).optional(),
    burnAfterReadSeconds: z.number().int().min(3).max(3600).optional(),
  })
  .strict();

const ERRORS = {
  not_found: [404, 'Not found'],
  unblock_first: [409, 'You blocked this user. Unblock them first'],
  limit: [409, 'You have too many scheduled messages'],
  bad_time: [400, 'Delivery time must be between 10 seconds and 30 days from now'],
};

router.post('/', validate(createSchema), async (req, res, next) => {
  try {
    const { to, ciphertext, iv, deliverAt, ttlSeconds, burnAfterReadSeconds } = req.body;
    if (to === req.user.id) return res.status(400).json({ error: 'Invalid input' });
    const r = await createScheduled({
      from: req.user.id,
      to,
      ciphertext,
      iv,
      deliverAt: new Date(deliverAt).toISOString(),
      ttlSeconds,
      burnSeconds: burnAfterReadSeconds,
    });
    if (r.error) {
      const [status, error] = ERRORS[r.error];
      return res.status(status).json({ error });
    }
    return res.status(201).json({ scheduled: { id: r.scheduled.id, to: r.scheduled.to_id, deliverAt: r.scheduled.deliver_at } });
  } catch (err) {
    return next(err);
  }
});

router.get('/', async (req, res, next) => {
  try {
    const rows = await listScheduled(req.user.id);
    res.json({
      scheduled: rows.map((s) => ({
        id: s.id,
        to: s.to_id,
        toUsername: s.to_username,
        deliverAt: s.deliver_at,
        ttlSeconds: s.ttl_seconds,
        burnAfterReadSeconds: s.burn_after_read_seconds,
        createdAt: s.created_at,
      })),
    });
  } catch (err) {
    next(err);
  }
});

router.delete('/:id', async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    if (!(await cancelScheduled(req.params.id, req.user.id))) return res.status(404).json({ error: 'Not found' });
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
});

export default router;

// File: server/src/routes/scheduled.js
// End of file