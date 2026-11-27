// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/invites.js
// Purpose : HTTP API for invite links and join requests, mounted at /api.
//           Admin routes (under /groups/:id): create, list and revoke invites;
//           list, approve and deny join requests. Any-user routes:
//           POST /invites/preview and POST /invites/redeem.
//           Tokens are sent in a POST body, never in a URL, so they stay out of
//           access logs and browser history (the frontend should keep them in
//           the URL fragment, which browsers never send to servers). Responses
//           that carry a token are marked Cache-Control: no-store. Preview and
//           redeem use the failed-attempt rate limiter, so guessing tokens is
//           throttled. Every body is validated with zod (.strict()). Any
//           invalid link yields the same 404 whatever the reason. Redeeming
//           notifies the group's admins over realtime; approving notifies the
//           group and the newcomer.
// =============================================================================
import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { socialLimiter, strictLimiter } from '../middleware/security.js';
import { isUuid } from '../utils/serialize.js';
import { emitToUsers, notifyGroup } from '../utils/realtime.js';
import {
  createInvite,
  listInvites,
  revokeInvite,
  previewInvite,
  redeemInvite,
  listJoinRequests,
  approveJoinRequest,
  denyJoinRequest,
  listAdminIds,
} from '../models/GroupInvite.js';

const router = Router();
const guard = [requireAuth, socialLimiter];

const b64 = /^[A-Za-z0-9+/=]+$/;
const tokenSchema = z.object({ token: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).strict();
const createSchema = z
  .object({
    ttlSeconds: z.number().int().min(60).max(604800).default(86400),
    maxUses: z.number().int().min(1).max(50).default(1),
  })
  .strict();
const approveSchema = z
  .object({
    wrappedKey: z.string().min(1).max(200).regex(b64),
    iv: z.string().min(16).max(32).regex(b64),
  })
  .strict();

const ERRORS = {
  not_found: [404, 'Not found'],
  target_missing: [404, 'Not found'],
  invalid: [404, 'Invalid or expired invite'],
  forbidden: [403, 'Only group admins can do this'],
  limit: [409, 'Limit reached. Try again later'],
  full: [409, 'The group is full'],
  needs_rekey: [409, 'The group needs a new encryption key first'],
  cannot_add: [409, 'This user cannot be added'],
};

function fail(res, code) {
  const [status, error] = ERRORS[code] || [400, 'Invalid request'];
  return res.status(status).json({ error });
}

const badId = (...ids) => ids.some((id) => !isUuid(id));

// ---- Admin: invites ---------------------------------------------------------

router.post('/groups/:id/invites', ...guard, validate(createSchema), async (req, res, next) => {
  try {
    if (badId(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const r = await createInvite({
      groupId: req.params.id,
      actorId: req.user.id,
      ttlSeconds: req.body.ttlSeconds,
      maxUses: req.body.maxUses,
    });
    if (r.error) return fail(res, r.error);
    res.set('Cache-Control', 'no-store');
    res.status(201).json({
      invite: { id: r.invite.id, maxUses: r.invite.max_uses, expiresAt: r.invite.expires_at },
      token: r.token, // shown once; only its hash is stored
    });
  } catch (err) {
    next(err);
  }
});

router.get('/groups/:id/invites', ...guard, async (req, res, next) => {
  try {
    if (badId(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const r = await listInvites(req.params.id, req.user.id);
    if (r.error) return fail(res, r.error);
    res.json({
      invites: r.invites.map((i) => ({
        id: i.id,
        maxUses: i.max_uses,
        uses: i.uses,
        expiresAt: i.expires_at,
        createdAt: i.created_at,
        createdBy: i.created_by_name,
      })),
    });
  } catch (err) {
    next(err);
  }
});

router.delete('/groups/:id/invites/:inviteId', ...guard, async (req, res, next) => {
  try {
    if (badId(req.params.id, req.params.inviteId)) return res.status(400).json({ error: 'Invalid input' });
    const r = await revokeInvite({ groupId: req.params.id, actorId: req.user.id, inviteId: req.params.inviteId });
    if (r !== 'ok') return fail(res, r);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// ---- Admin: join requests -----------------------------------------------------

router.get('/groups/:id/join-requests', ...guard, async (req, res, next) => {
  try {
    if (badId(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const r = await listJoinRequests(req.params.id, req.user.id);
    if (r.error) return fail(res, r.error);
    res.json({
      requests: r.requests.map((u) => ({
        id: u.id,
        username: u.username,
        publicKey: u.public_key,
        requestedAt: u.created_at,
      })),
    });
  } catch (err) {
    next(err);
  }
});

router.post('/groups/:id/join-requests/:userId/approve', ...guard, validate(approveSchema), async (req, res, next) => {
  try {
    if (badId(req.params.id, req.params.userId)) return res.status(400).json({ error: 'Invalid input' });
    const r = await approveJoinRequest({
      groupId: req.params.id,
      actorId: req.user.id,
      userId: req.params.userId,
      envelope: { wrappedKey: req.body.wrappedKey, iv: req.body.iv },
    });
    if (r !== 'added') return fail(res, r);
    const io = req.app.get('io');
    emitToUsers(io, [req.params.userId], 'group:joined', { groupId: req.params.id });
    await notifyGroup(io, req.params.id, 'member_added');
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.delete('/groups/:id/join-requests/:userId', ...guard, async (req, res, next) => {
  try {
    if (badId(req.params.id, req.params.userId)) return res.status(400).json({ error: 'Invalid input' });
    const r = await denyJoinRequest({ groupId: req.params.id, actorId: req.user.id, userId: req.params.userId });
    if (r !== 'ok') return fail(res, r);
    emitToUsers(req.app.get('io'), [req.params.userId], 'group:join_denied', { groupId: req.params.id });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// ---- Any logged-in user: preview and redeem ------------------------------------

router.post('/invites/preview', requireAuth, strictLimiter, validate(tokenSchema), async (req, res, next) => {
  try {
    const p = await previewInvite(req.body.token, req.user.id);
    if (!p) return fail(res, 'invalid');
    res.json({
      group: { name: p.name, memberCount: p.member_count },
      alreadyMember: p.already_member,
    });
  } catch (err) {
    next(err);
  }
});

router.post('/invites/redeem', requireAuth, strictLimiter, validate(tokenSchema), async (req, res, next) => {
  try {
    const r = await redeemInvite(req.body.token, req.user.id);
    if (r.error) return fail(res, r.error);
    if (r.status === 'pending') {
      const io = req.app.get('io');
      emitToUsers(io, await listAdminIds(r.groupId), 'group:join_request', { groupId: r.groupId });
    }
    res.json({ status: r.status, groupId: r.groupId });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/invites.js
// End of file