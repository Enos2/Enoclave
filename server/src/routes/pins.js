// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/pins.js
// Purpose : HTTP API for pinned messages, auto-mounted at /api/pins.
//           PUT /direct/:messageId and DELETE /direct/:messageId pin or unpin a
//           message of a 1-to-1 conversation you take part in (either person
//           can; at most 3 pins per conversation, else 409; shared by both).
//           PUT /group/:messageId and DELETE /group/:messageId pin or unpin a
//           group message (group ADMINS only: 403 for ordinary members, 404 for
//           non-members; at most 5 pins per group, else 409). GET
//           /conversation/:peerId and GET /groups/:groupId return the pins,
//           newest first, each as { messageId, pinnedBy, pinnedAt, message }
//           where message is the normal message object with its ciphertext, so
//           clients can show pins without loading the history (404 for groups
//           you are not in). Changes are pushed live as 'pin:update' { kind:
//           'direct'|'group', groupId?, messageId, pinned, by } to both people
//           or all members. Pins vanish with their message. Block rules: see
//           models/Pin.js (a user who is blocked gets a normal-looking success
//           but nothing is stored or sent). Session required; rate limited.
// =============================================================================
import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { socialLimiter } from '../middleware/security.js';
import { isUuid, serializeMessage, serializeGroupMessage } from '../utils/serialize.js';
import { emitToUsers } from '../utils/realtime.js';
import { getMembership, listMemberIds } from '../models/Group.js';
import { MAX_DIRECT_PINS, MAX_GROUP_PINS, setDirectPin, setGroupPin, listDirectPins, listGroupPins } from '../models/Pin.js';

const router = Router();
router.use(requireAuth, socialLimiter);

const ERRORS = {
  not_found: [404, 'Not found'],
  forbidden: [403, 'Only group admins can do this'],
  unblock_first: [409, 'Unblock this user first'],
  limit: [409, 'Too many pinned messages'],
};

const fail = (res, code, extra = {}) => {
  const [status, error] = ERRORS[code] ?? [400, 'Invalid request'];
  return res.status(status).json({ error, ...extra });
};

async function applyDirect(req, res, next, pinned) {
  try {
    const { messageId } = req.params;
    if (!isUuid(messageId)) return res.status(400).json({ error: 'Invalid input' });
    const r = await setDirectPin({ messageId, userId: req.user.id, pinned });
    if (r.error) return fail(res, r.error, r.error === 'limit' ? { max: MAX_DIRECT_PINS } : {});
    if (r.changed && !r.silent) {
      req.app
        .get('io')
        ?.to(`user:${req.user.id}`)
        .to(`user:${r.peer}`)
        .emit('pin:update', { kind: 'direct', messageId, pinned, by: req.user.id });
    }
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

async function applyGroup(req, res, next, pinned) {
  try {
    const { messageId } = req.params;
    if (!isUuid(messageId)) return res.status(400).json({ error: 'Invalid input' });
    const r = await setGroupPin({ messageId, userId: req.user.id, pinned });
    if (r.error) return fail(res, r.error, r.error === 'limit' ? { max: MAX_GROUP_PINS } : {});
    if (r.changed) {
      emitToUsers(req.app.get('io'), await listMemberIds(r.groupId), 'pin:update', {
        kind: 'group',
        groupId: r.groupId,
        messageId,
        pinned,
        by: req.user.id,
      });
    }
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

router.put('/direct/:messageId', (req, res, next) => applyDirect(req, res, next, true));
router.delete('/direct/:messageId', (req, res, next) => applyDirect(req, res, next, false));
router.put('/group/:messageId', (req, res, next) => applyGroup(req, res, next, true));
router.delete('/group/:messageId', (req, res, next) => applyGroup(req, res, next, false));

router.get('/conversation/:peerId', async (req, res, next) => {
  try {
    if (!isUuid(req.params.peerId)) return res.status(400).json({ error: 'Invalid input' });
    const rows = await listDirectPins(req.user.id, req.params.peerId);
    res.json({
      pins: rows.map((r) => ({ messageId: r.id, pinnedBy: r.pinned_by, pinnedAt: r.pinned_at, message: serializeMessage(r) })),
    });
  } catch (err) {
    next(err);
  }
});

router.get('/groups/:groupId', async (req, res, next) => {
  try {
    if (!isUuid(req.params.groupId)) return res.status(400).json({ error: 'Invalid input' });
    if (!(await getMembership(req.params.groupId, req.user.id))) return res.status(404).json({ error: 'Not found' });
    const rows = await listGroupPins(req.params.groupId, req.user.id);
    res.json({
      pins: rows.map((r) => ({
        messageId: r.id,
        pinnedBy: r.pinned_by,
        pinnedAt: r.pinned_at,
        message: serializeGroupMessage(r),
      })),
    });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/pins.js
// End of file