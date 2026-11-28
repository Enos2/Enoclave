// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/contacts.js
// Purpose : HTTP API under /api/contacts. GET / lists the logged-in user's
//           contacts, POST / adds one ({ userId }; you cannot add yourself,
//           someone you blocked, or exceed 500 contacts), DELETE /:id
//           removes one. Adding a contact is private: the other person is
//           not told, and presence is visible only when both people added
//           each other. The body is validated with a strict zod schema; ids
//           are UUIDs; session required and rate limited.
// =============================================================================
import { Router } from 'express';
import { z } from 'zod';
import { listContacts, addContact, removeContact } from '../models/Contact.js';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { socialLimiter } from '../middleware/security.js';
import { isUuid } from '../utils/serialize.js';

const router = Router();
router.use(requireAuth, socialLimiter);

const bodySchema = z.object({ userId: z.string().refine(isUuid) }).strict();

router.get('/', async (req, res, next) => {
  try {
    const rows = await listContacts(req.user.id);
    res.json({ contacts: rows.map((c) => ({ id: c.id, username: c.username, addedAt: c.created_at })) });
  } catch (err) {
    next(err);
  }
});

router.post('/', validate(bodySchema), async (req, res, next) => {
  try {
    const { userId } = req.body;
    if (userId === req.user.id) return res.status(400).json({ error: 'Invalid input' });
    const result = await addContact(req.user.id, userId);
    if (result === 'blocked') return res.status(409).json({ error: 'Unblock this user first' });
    if (result === 'limit') return res.status(409).json({ error: 'Contact limit reached' });
    res.status(result === 'added' ? 201 : 200).json({ ok: true });
  } catch (err) {
    if (err?.code === '23503') return res.status(404).json({ error: 'Not found' });
    next(err);
  }
});

router.delete('/:id', async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const done = await removeContact(req.user.id, req.params.id);
    if (!done) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/contacts.js
// End of file