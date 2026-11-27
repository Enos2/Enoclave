// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/rooms.js
// Purpose : HTTP API for self-destruct rooms, auto-mounted at /api/rooms.
//           GET /api/rooms/:id returns the room's expiry time and the server
//           clock (so the client can render an accurate countdown). PUT
//           /api/rooms/:id/lifespan lets a group admin set a lifespan of 10
//           seconds to 30 days, or null to remove it. Every route needs a
//           valid session and is rate limited. The body is validated with zod
//           (.strict(): unknown fields are rejected). Non-members always get
//           404, never 403, so room ids cannot be probed. After a change, all
//           members are notified over realtime ('group:updated' of type
//           lifespan_changed, carrying the new expiry). The room itself is
//           destroyed by the room sweeper job, not by this file.
// =============================================================================
import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { socialLimiter } from '../middleware/security.js';
import { isUuid } from '../utils/serialize.js';
import { notifyGroup } from '../utils/realtime.js';
import { MIN_LIFESPAN_SECONDS, MAX_LIFESPAN_SECONDS, setLifespan, getLifespan } from '../models/GroupRoom.js';

const router = Router();
router.use(requireAuth, socialLimiter);

const lifespanSchema = z
  .object({ lifespanSeconds: z.number().int().min(MIN_LIFESPAN_SECONDS).max(MAX_LIFESPAN_SECONDS).nullable() })
  .strict();

router.get('/:id', async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const room = await getLifespan(req.params.id, req.user.id);
    if (!room) return res.status(404).json({ error: 'Not found' });
    res.json({ room: { expiresAt: room.expires_at, serverTime: room.server_time } });
  } catch (err) {
    next(err);
  }
});

router.put('/:id/lifespan', validate(lifespanSchema), async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const r = await setLifespan({
      groupId: req.params.id,
      actorId: req.user.id,
      lifespanSeconds: req.body.lifespanSeconds,
    });
    if (r.error === 'forbidden') return res.status(403).json({ error: 'Only group admins can do this' });
    if (r.error) return res.status(404).json({ error: 'Not found' });
    await notifyGroup(req.app.get('io'), req.params.id, 'lifespan_changed', { expiresAt: r.expiresAt });
    res.json({ ok: true, expiresAt: r.expiresAt });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/rooms.js
// End of file