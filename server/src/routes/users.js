// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/users.js
// Purpose : HTTP endpoints under /api/users for the logged-in user: username
//           search (hides users who blocked you), public-key lookup, key
//           rotation and account deletion. Rotation and deletion both need the
//           account password (re-checked with bcrypt) and are rate-limited on
//           failed attempts. Rotation writes an audit-log entry and tells every
//           affected group, over realtime, that a new group key is needed.
//           Deletion removes the user from all groups before deleting the
//           account and tells the remaining members.
// =============================================================================
import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import {
  findUserById,
  getPasswordHash,
  searchUsers,
  updatePublicKey,
  deleteUser,
} from '../models/User.js';
import { logEvent } from '../models/AuthEvent.js';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { strictLimiter, searchLimiter } from '../middleware/security.js';
import { publicKeySchema } from '../utils/schemas.js';
import { isUuid, publicUser } from '../utils/serialize.js';
import { clientInfo } from '../utils/device.js';
import { clearAuthCookie } from '../utils/token.js';
import { notifyGroup } from '../utils/realtime.js';

const router = Router();
router.use(requireAuth);

const rotateSchema = z
  .object({ publicKey: publicKeySchema, password: z.string().min(1).max(72) })
  .strict();
const deleteSchema = z.object({ password: z.string().min(1).max(72) }).strict();

router.get('/search', searchLimiter, async (req, res, next) => {
  try {
    const q = typeof req.query.q === 'string' ? req.query.q.trim().toLowerCase() : '';
    if (!/^[a-z0-9_]{2,24}$/.test(q)) return res.json({ users: [] });
    const found = await searchUsers(q, req.user.id);
    res.json({ users: found.map((u) => ({ id: u.id, username: u.username })) });
  } catch (err) {
    next(err);
  }
});

// A key change is security-relevant: it is audited and every group of the user is flagged for rekey.
router.put('/me/key', strictLimiter, validate(rotateSchema), async (req, res, next) => {
  try {
    const hash = await getPasswordHash(req.user.id);
    const ok = hash && (await bcrypt.compare(req.body.password, hash));
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const { user, groupIds } = await updatePublicKey(req.user.id, req.body.publicKey);
    await logEvent({ userId: req.user.id, username: req.user.username, event: 'key_rotated', ...clientInfo(req) });
    const io = req.app.get('io');
    for (const groupId of groupIds) await notifyGroup(io, groupId, 'rekey_needed');
    res.json({ user: publicUser(user) });
  } catch (err) {
    next(err);
  }
});

// Permanently deletes the account; messages, sessions, contacts, blocks and events cascade.
router.delete('/me', strictLimiter, validate(deleteSchema), async (req, res, next) => {
  try {
    const hash = await getPasswordHash(req.user.id);
    const ok = hash && (await bcrypt.compare(req.body.password, hash));
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const affected = await deleteUser(req.user.id);
    const io = req.app.get('io');
    io?.in(`user:${req.user.id}`).disconnectSockets(true);
    for (const g of affected) if (!g.deleted) await notifyGroup(io, g.groupId, 'member_left');
    clearAuthCookie(res);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.get('/:id/key', async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const user = await findUserById(req.params.id);
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json({ user: publicUser(user) });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/users.js
// End of file