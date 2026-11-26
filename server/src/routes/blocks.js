// File: server/src/routes/blocks.js
// Purpose: List, add and remove blocked users.
import { Router } from 'express';
import { z } from 'zod';
import { listBlocks, blockUser, unblockUser } from '../models/Block.js';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { socialLimiter } from '../middleware/security.js';
import { isUuid } from '../utils/serialize.js';

const router = Router();
router.use(requireAuth, socialLimiter);

const bodySchema = z.object({ userId: z.string().refine(isUuid) }).strict();

router.get('/', async (req, res, next) => {
  try {
    const rows = await listBlocks(req.user.id);
    res.json({ blocks: rows.map((b) => ({ id: b.id, username: b.username, blockedAt: b.created_at })) });
  } catch (err) {
    next(err);
  }
});

router.post('/', validate(bodySchema), async (req, res, next) => {
  try {
    const { userId } = req.body;
    if (userId === req.user.id) return res.status(400).json({ error: 'Invalid input' });
    const result = await blockUser(req.user.id, userId);
    if (result === 'limit') return res.status(409).json({ error: 'Block limit reached' });
    res.status(result === 'blocked' ? 201 : 200).json({ ok: true });
  } catch (err) {
    if (err?.code === '23503') return res.status(404).json({ error: 'Not found' });
    next(err);
  }
});

router.delete('/:id', async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const done = await unblockUser(req.user.id, req.params.id);
    if (!done) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/blocks.js
// End of file