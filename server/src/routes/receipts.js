// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/receipts.js
// Purpose : HTTP API to LOAD read state when a conversation is opened (live
//           updates arrive over realtime, see socket/handlers/receipts.js).
//           Auto-mounted at /api/receipts. GET /direct/:peerId returns
//           { mine, theirs }: my own "read up to" time and the peer's, where
//           theirs is null whenever either side has receipts off or a block
//           exists (no way to tell which). GET /group/:id returns the "read up
//           to" time of each other member who has receipts on, provided I have
//           them on too; non-members get 404. Responses are marked no-store.
//           Rate limited, session required, ids validated as UUIDs.
// =============================================================================
import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { socialLimiter } from '../middleware/security.js';
import { isUuid } from '../utils/serialize.js';
import { getMembership } from '../models/Group.js';
import { directCursors, groupCursors } from '../models/Signal.js';

const router = Router();
router.use(requireAuth, socialLimiter);

router.get('/direct/:peerId', async (req, res, next) => {
  try {
    if (!isUuid(req.params.peerId)) return res.status(400).json({ error: 'Invalid input' });
    const c = await directCursors(req.user.id, req.params.peerId);
    res.set('Cache-Control', 'no-store');
    res.json({ mine: c.mine, theirs: c.theirs });
  } catch (err) {
    next(err);
  }
});

router.get('/group/:id', async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    if (!(await getMembership(req.params.id, req.user.id))) return res.status(404).json({ error: 'Not found' });
    const rows = await groupCursors(req.params.id, req.user.id);
    res.set('Cache-Control', 'no-store');
    res.json({ members: rows.map((r) => ({ userId: r.user_id, lastReadAt: r.last_read_at })) });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/receipts.js
// End of file