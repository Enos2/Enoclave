// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/reactions.js
// Purpose : HTTP API for message reactions, auto-mounted at /api/reactions.
//           PUT /direct/:messageId { reaction } and DELETE /direct/:messageId
//           set or remove the caller's reaction on a direct message they
//           participate in; PUT /group/:messageId and DELETE /group/:messageId
//           do the same for a group message the caller could see. reaction must
//           be one of: thumbs_up, heart, laugh, wow, sad, pray, fire,
//           thumbs_down (anything else is 400; unknown body fields are 400).
//           One reaction per person per message: a new one replaces the old.
//           GET /conversation/:peerId and GET /groups/:groupId return the
//           reactions on the latest 100 visible messages, grouped by message id
//           ({ reactions: { "<messageId>": [{ userId, reaction }] } }), for
//           loading when a chat is opened. Live changes are pushed as
//           'reaction:update' { kind, messageId, userId, reaction | null,
//           groupId? } to both people (direct) or all members (group); a
//           removal carries reaction: null. Privacy and block rules: see
//           models/Reaction.js (a user who is blocked gets a normal-looking
//           success but nothing is stored or sent). Messages the caller cannot
//           see give 404. Session required; rate limited.
// =============================================================================
import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { socialLimiter } from '../middleware/security.js';
import { isUuid } from '../utils/serialize.js';
import { emitToUsers } from '../utils/realtime.js';
import { getMembership, listMemberIds } from '../models/Group.js';
import {
  REACTIONS,
  setDirectReaction,
  setGroupReaction,
  listDirectReactions,
  listGroupReactions,
} from '../models/Reaction.js';

const router = Router();
router.use(requireAuth, socialLimiter);

const putSchema = z.object({ reaction: z.enum(REACTIONS) }).strict();

const grouped = (rows) => {
  const out = {};
  for (const r of rows) (out[r.message_id] ??= []).push({ userId: r.user_id, reaction: r.reaction });
  return out;
};

async function applyDirect(req, res, next, reaction) {
  try {
    const { messageId } = req.params;
    if (!isUuid(messageId)) return res.status(400).json({ error: 'Invalid input' });
    const r = await setDirectReaction({ messageId, userId: req.user.id, reaction });
    if (r.error === 'not_found') return res.status(404).json({ error: 'Not found' });
    if (r.error === 'unblock_first') return res.status(409).json({ error: 'Unblock this user first' });
    if (r.changed && !r.silent) {
      req.app
        .get('io')
        ?.to(`user:${req.user.id}`)
        .to(`user:${r.peer}`)
        .emit('reaction:update', { kind: 'direct', messageId, userId: req.user.id, reaction });
    }
    return res.json({ ok: true });
  } catch (err) {
    if (err?.code === '23503') return res.status(404).json({ error: 'Not found' }); // message vanished meanwhile
    return next(err);
  }
}

async function applyGroup(req, res, next, reaction) {
  try {
    const { messageId } = req.params;
    if (!isUuid(messageId)) return res.status(400).json({ error: 'Invalid input' });
    const r = await setGroupReaction({ messageId, userId: req.user.id, reaction });
    if (r.error) return res.status(404).json({ error: 'Not found' });
    if (r.changed) {
      emitToUsers(req.app.get('io'), await listMemberIds(r.groupId), 'reaction:update', {
        kind: 'group',
        groupId: r.groupId,
        messageId,
        userId: req.user.id,
        reaction,
      });
    }
    return res.json({ ok: true });
  } catch (err) {
    if (err?.code === '23503') return res.status(404).json({ error: 'Not found' });
    return next(err);
  }
}

router.put('/direct/:messageId', validate(putSchema), (req, res, next) => applyDirect(req, res, next, req.body.reaction));
router.delete('/direct/:messageId', (req, res, next) => applyDirect(req, res, next, null));
router.put('/group/:messageId', validate(putSchema), (req, res, next) => applyGroup(req, res, next, req.body.reaction));
router.delete('/group/:messageId', (req, res, next) => applyGroup(req, res, next, null));

router.get('/conversation/:peerId', async (req, res, next) => {
  try {
    if (!isUuid(req.params.peerId)) return res.status(400).json({ error: 'Invalid input' });
    res.json({ reactions: grouped(await listDirectReactions(req.user.id, req.params.peerId, 100)) });
  } catch (err) {
    next(err);
  }
});

router.get('/groups/:groupId', async (req, res, next) => {
  try {
    if (!isUuid(req.params.groupId)) return res.status(400).json({ error: 'Invalid input' });
    if (!(await getMembership(req.params.groupId, req.user.id))) return res.status(404).json({ error: 'Not found' });
    res.json({ reactions: grouped(await listGroupReactions(req.params.groupId, req.user.id, 100)) });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/reactions.js
// End of file