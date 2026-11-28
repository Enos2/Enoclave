// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/chats.js
// Purpose : HTTP API for the user's private per-conversation preferences,
//           auto-mounted at /api/chats. GET /prefs lists every non-default
//           preference. PUT /prefs/direct/:peerId and PUT /prefs/group/:groupId
//           change any of: pinned (boolean; at most 5 pinned chats, else 409),
//           archived (boolean), mutedUntil (ISO 8601 time between one second
//           and ten years ahead, or null to unmute) and defaultTtlSeconds
//           (5 to 604800, or null for none), which the client applies as the
//           disappearing timer when sending. Omitted fields are left unchanged;
//           when everything returns to its default the stored row is deleted.
//           Preferences are private: nobody else can see them. They are stored
//           for the user's clients (muting does not stop the server from
//           delivering). A successful change is pushed to ALL of the user's own
//           devices as 'prefs:updated' so they stay in sync. Errors: 400
//           invalid (including targeting yourself), 404 unknown peer or a
//           group you are not a member of, 409 pin limit. Strict zod schema;
//           session required; rate limited.
// =============================================================================
import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { socialLimiter } from '../middleware/security.js';
import { isUuid } from '../utils/serialize.js';
import { listPrefs, setPref, MAX_PINNED } from '../models/ChatPrefs.js';

const router = Router();
router.use(requireAuth, socialLimiter);

const TEN_YEARS_MS = 10 * 365 * 24 * 3600 * 1000;

const patchSchema = z
  .object({
    pinned: z.boolean().optional(),
    archived: z.boolean().optional(),
    mutedUntil: z.string().datetime({ offset: true }).nullable().optional(),
    defaultTtlSeconds: z.number().int().min(5).max(604800).nullable().optional(),
  })
  .strict()
  .refine((b) => Object.keys(b).length > 0, { message: 'Nothing to update' });

const iso = (d) => (d instanceof Date ? d.toISOString() : null);

const shape = (p) => ({
  kind: p.peer_id ? 'direct' : 'group',
  targetId: p.peer_id ?? p.group_id,
  name: p.peer_username ?? p.group_name,
  pinned: p.pinned,
  archived: p.archived,
  mutedUntil: iso(p.muted_until),
  defaultTtlSeconds: p.default_ttl_seconds,
});

const DEFAULTS = { pinned: false, archived: false, mutedUntil: null, defaultTtlSeconds: null };

router.get('/prefs', async (req, res, next) => {
  try {
    res.json({ prefs: (await listPrefs(req.user.id)).map(shape) });
  } catch (err) {
    next(err);
  }
});

async function apply(req, res, next, kind) {
  try {
    const targetId = kind === 'direct' ? req.params.peerId : req.params.groupId;
    if (!isUuid(targetId)) return res.status(400).json({ error: 'Invalid input' });
    if (kind === 'direct' && targetId === req.user.id) return res.status(400).json({ error: 'Invalid input' });

    if (typeof req.body.mutedUntil === 'string') {
      const t = Date.parse(req.body.mutedUntil);
      if (!(t > Date.now() + 1000 && t < Date.now() + TEN_YEARS_MS)) {
        return res.status(400).json({ error: 'mutedUntil must be a future time within ten years' });
      }
    }

    const r = await setPref({
      userId: req.user.id,
      peerId: kind === 'direct' ? targetId : undefined,
      groupId: kind === 'group' ? targetId : undefined,
      patch: req.body,
    });
    if (r.error === 'not_found') return res.status(404).json({ error: 'Not found' });
    if (r.error === 'pin_limit') return res.status(409).json({ error: `You can pin at most ${MAX_PINNED} chats` });

    const prefs = r.pref ? shape(r.pref) : { kind, targetId, name: null, ...DEFAULTS };
    req.app.get('io')?.to(`user:${req.user.id}`).emit('prefs:updated', { kind, targetId, prefs });
    return res.json({ prefs });
  } catch (err) {
    return next(err);
  }
}

router.put('/prefs/direct/:peerId', validate(patchSchema), (req, res, next) => apply(req, res, next, 'direct'));
router.put('/prefs/group/:groupId', validate(patchSchema), (req, res, next) => apply(req, res, next, 'group'));

export default router;

// File: server/src/routes/chats.js
// End of file