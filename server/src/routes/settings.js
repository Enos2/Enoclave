// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/settings.js
// Purpose : HTTP API for the logged-in user's privacy settings, auto-mounted at
//           /api/settings. GET returns showPresence, showTyping, readReceipts
//           and status. PUT changes any of them (at least one field; unknown
//           fields or an invalid status such as "invisible" are rejected with
//           400, via a strict zod schema). Side effects, so changes take effect
//           immediately everywhere: switching read receipts OFF deletes all of
//           the user's stored read cursors; any change re-runs presence
//           (people who may no longer see the user are told they went offline,
//           everyone allowed is sent the new status, and the user's own devices
//           get a fresh snapshot). Rate limited, session required.
// =============================================================================
import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { socialLimiter } from '../middleware/security.js';
import { getSettings, updateSettings, clearReceipts } from '../models/Settings.js';
import { visiblePeers } from '../models/Presence.js';
import { refreshPresence } from '../utils/presenceTracker.js';

const router = Router();
router.use(requireAuth, socialLimiter);

const updateSchema = z
  .object({
    showPresence: z.boolean().optional(),
    showTyping: z.boolean().optional(),
    readReceipts: z.boolean().optional(),
    status: z.enum(['available', 'focus', 'away']).optional(),
  })
  .strict()
  .refine((b) => Object.keys(b).length > 0, { message: 'Nothing to update' });

const shape = (s) => ({
  showPresence: s.show_presence,
  showTyping: s.show_typing,
  readReceipts: s.read_receipts,
  status: s.status,
});

router.get('/', async (req, res, next) => {
  try {
    res.json({ settings: shape(await getSettings(req.user.id)) });
  } catch (err) {
    next(err);
  }
});

router.put('/', validate(updateSchema), async (req, res, next) => {
  try {
    const uid = req.user.id;
    const before = await getSettings(uid);
    const previousPeerIds = (await visiblePeers(uid)).map((p) => p.id);
    const after = await updateSettings(uid, req.body);
    if (before.read_receipts && !after.read_receipts) await clearReceipts(uid);
    await refreshPresence(req.app.get('io'), uid, previousPeerIds);
    res.json({ settings: shape(after) });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/settings.js
// End of file