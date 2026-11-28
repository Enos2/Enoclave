// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/edits.js
// Purpose : HTTP API for editing sent messages, auto-mounted at /api/edits.
//           The client encrypts the NEW text exactly like a normal message and
//           sends only ciphertext; the server never sees content.
//           PUT /direct/:id { ciphertext, iv } edits one of YOUR direct
//           messages; PUT /group/:id { epoch, ciphertext, iv } edits one of
//           YOUR group messages (epoch must be the message's original key
//           epoch). Rules: only the sender, within 15 minutes of sending
//           (server clock), at most 10 edits, never after a burn timer has
//           started or the message has expired (409/404). Blocks follow the
//           messaging rules: if you blocked the recipient the answer is 409; if
//           they blocked you it looks like success but nothing changes and
//           nothing is sent. On success every device of both people (or all
//           group members) receives 'message:edited' or 'group:message:edited'
//           carrying the full updated message including editedAt. Messages you
//           cannot edit - someone else's, unknown, expired - all give the same
//           404. Strict zod schemas; session required; rate limited.
// =============================================================================
import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { socialLimiter } from '../middleware/security.js';
import { isUuid, serializeMessage, serializeGroupMessage } from '../utils/serialize.js';
import { emitToUsers } from '../utils/realtime.js';
import { listMemberIds } from '../models/Group.js';
import { editMessage } from '../models/Message.js';
import { editGroupMessage } from '../models/GroupMessage.js';

const router = Router();
router.use(requireAuth, socialLimiter);

const base64 = /^[A-Za-z0-9+/=]+$/;
const cipher = z.string().min(1).max(20000).regex(base64);
const ivField = z.string().min(16).max(32).regex(base64);

const directSchema = z.object({ ciphertext: cipher, iv: ivField }).strict();
const groupSchema = z.object({ epoch: z.number().int().min(1), ciphertext: cipher, iv: ivField }).strict();

const ERRORS = {
  not_found: [404, 'Not found'],
  too_late: [409, 'Messages can only be edited within 15 minutes of sending'],
  burning: [409, 'A message that is burning can no longer be edited'],
  edit_limit: [409, 'This message has been edited too many times'],
  unblock_first: [409, 'You blocked this user. Unblock them first'],
  epoch_mismatch: [409, 'The message must be re-encrypted with its original group key'],
};

const fail = (res, code) => {
  const [status, error] = ERRORS[code] ?? [400, 'Invalid request'];
  return res.status(status).json({ error });
};

router.put('/direct/:id', validate(directSchema), async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const r = await editMessage({ id: req.params.id, userId: req.user.id, ...req.body });
    if (r.error) return fail(res, r.error);
    if (r.message) {
      req.app
        .get('io')
        ?.to(`user:${req.user.id}`)
        .to(`user:${r.peer}`)
        .emit('message:edited', serializeMessage(r.message));
    }
    return res.json({ ok: true, editedAt: r.message ? r.message.edited_at : new Date().toISOString() });
  } catch (err) {
    return next(err);
  }
});

router.put('/group/:id', validate(groupSchema), async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const r = await editGroupMessage({ messageId: req.params.id, userId: req.user.id, ...req.body });
    if (r.error) return fail(res, r.error);
    emitToUsers(
      req.app.get('io'),
      await listMemberIds(r.message.group_id),
      'group:message:edited',
      serializeGroupMessage(r.message)
    );
    return res.json({ ok: true, editedAt: r.message.edited_at });
  } catch (err) {
    return next(err);
  }
});

export default router;

// File: server/src/routes/edits.js
// End of file