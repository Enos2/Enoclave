// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/groups.js
// Purpose : HTTP API under /api/groups. Covers: list/create groups, group
//           details (members and their public keys), rename, add/remove
//           members, leave, promote/demote admins, rekey, fetch my wrapped
//           keys, group message history and message deletion. Every route
//           requires a valid session and is rate limited. Every body is
//           validated with zod (.strict(): unknown fields are rejected).
//           A user who is not a member always gets 404, never 403, so group
//           ids cannot be probed. Permission and consistency rules are enforced
//           in the models; this file maps their result codes to HTTP statuses
//           and sends realtime notifications to the affected users.
// =============================================================================
import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { socialLimiter } from '../middleware/security.js';
import { isUuid, serializeGroupMessage } from '../utils/serialize.js';
import { emitToUsers, notifyGroup } from '../utils/realtime.js';
import {
  MAX_MEMBERS,
  listGroupsForUser,
  createGroup,
  getGroupForMember,
  getMembership,
  listMemberIds,
  renameGroup,
  addMember,
  removeMember,
  leaveGroup,
  setRole,
  rekey,
  listMyEnvelopes,
} from '../models/Group.js';
import { listGroupMessages, deleteGroupMessage } from '../models/GroupMessage.js';

const router = Router();
router.use(requireAuth, socialLimiter);

const b64 = /^[A-Za-z0-9+/=]+$/;
const uuid = z.string().refine(isUuid);
const nameSchema = z
  .string()
  .trim()
  .min(1)
  .max(64)
  .refine((s) => !/[\u0000-\u001f\u007f]/.test(s));
const wrappedKey = z.string().min(1).max(200).regex(b64);
const ivSchema = z.string().min(16).max(32).regex(b64);
const envelopeSchema = z.object({ userId: uuid, wrappedKey, iv: ivSchema }).strict();

const createSchema = z
  .object({
    name: nameSchema,
    members: z.array(uuid).max(MAX_MEMBERS - 1),
    envelopes: z.array(envelopeSchema).min(1).max(MAX_MEMBERS),
  })
  .strict();
const renameSchema = z.object({ name: nameSchema }).strict();
const addSchema = z.object({ userId: uuid, wrappedKey, iv: ivSchema }).strict();
const roleSchema = z.object({ role: z.enum(['admin', 'member']) }).strict();
const rekeySchema = z
  .object({
    fromEpoch: z.number().int().min(1),
    envelopes: z.array(envelopeSchema).min(1).max(MAX_MEMBERS),
  })
  .strict();

const ERRORS = {
  not_found: [404, 'Not found'],
  target_missing: [404, 'Not found'],
  forbidden: [403, 'Only group admins can do this'],
  needs_rekey: [409, 'The group needs a new encryption key first'],
  full: [409, 'The group is full'],
  limit: [409, 'Group limit reached'],
  cannot_add: [409, 'One or more users cannot be added'],
  self: [400, 'Use leave instead'],
  last_admin: [409, 'A group must keep at least one admin'],
  stale: [409, 'The group key is out of date. Refresh and retry'],
};

function fail(res, code) {
  const [status, error] = ERRORS[code] || [400, 'Invalid request'];
  return res.status(status).json({ error });
}

const badId = (...ids) => ids.some((id) => !isUuid(id));
const badEnvelopes = (err, res) =>
  err?.code === 'BAD_ENVELOPES' ? res.status(400).json({ error: 'Invalid key envelopes' }) : null;

router.get('/', async (req, res, next) => {
  try {
    const rows = await listGroupsForUser(req.user.id);
    res.json({
      groups: rows.map((g) => ({
        id: g.id,
        name: g.name,
        role: g.role,
        epoch: g.epoch,
        needsRekey: g.needs_rekey,
        memberCount: g.member_count,
      })),
    });
  } catch (err) {
    next(err);
  }
});

router.post('/', validate(createSchema), async (req, res, next) => {
  try {
    const { name, members, envelopes } = req.body;
    if (new Set(members).size !== members.length || members.includes(req.user.id)) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const result = await createGroup({ creatorId: req.user.id, name, memberIds: members, envelopes });
    if (result.error) return fail(res, result.error);
    await notifyGroup(req.app.get('io'), result.group.id, 'created');
    res.status(201).json({ group: result.group });
  } catch (err) {
    if (badEnvelopes(err, res)) return;
    next(err);
  }
});

router.get('/:id', async (req, res, next) => {
  try {
    if (badId(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const data = await getGroupForMember(req.params.id, req.user.id);
    if (!data) return fail(res, 'not_found');
    const { group, members } = data;
    res.json({
      group: {
        id: group.id,
        name: group.name,
        epoch: group.epoch,
        needsRekey: group.needs_rekey,
        role: group.role,
        joinedAt: group.joined_at,
      },
      members: members.map((m) => ({
        id: m.id,
        username: m.username,
        role: m.role,
        joinedAt: m.joined_at,
        publicKey: m.public_key,
      })),
    });
  } catch (err) {
    next(err);
  }
});

router.put('/:id', validate(renameSchema), async (req, res, next) => {
  try {
    if (badId(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const r = await renameGroup({ groupId: req.params.id, actorId: req.user.id, name: req.body.name });
    if (r !== 'ok') return fail(res, r);
    await notifyGroup(req.app.get('io'), req.params.id, 'renamed');
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.post('/:id/members', validate(addSchema), async (req, res, next) => {
  try {
    if (badId(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const { userId, wrappedKey: wk, iv } = req.body;
    const r = await addMember({
      groupId: req.params.id,
      actorId: req.user.id,
      userId,
      envelope: { wrappedKey: wk, iv },
    });
    if (r === 'exists') return res.json({ ok: true });
    if (r !== 'added') return fail(res, r);
    await notifyGroup(req.app.get('io'), req.params.id, 'member_added');
    res.status(201).json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.delete('/:id/members/:userId', async (req, res, next) => {
  try {
    if (badId(req.params.id, req.params.userId)) return res.status(400).json({ error: 'Invalid input' });
    const r = await removeMember({ groupId: req.params.id, actorId: req.user.id, targetId: req.params.userId });
    if (r !== 'removed') return fail(res, r);
    const io = req.app.get('io');
    emitToUsers(io, [req.params.userId], 'group:removed', { groupId: req.params.id });
    await notifyGroup(io, req.params.id, 'member_removed');
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.post('/:id/leave', async (req, res, next) => {
  try {
    if (badId(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const r = await leaveGroup({ groupId: req.params.id, userId: req.user.id });
    if (!r) return fail(res, 'not_found');
    const io = req.app.get('io');
    emitToUsers(io, [req.user.id], 'group:removed', { groupId: req.params.id });
    if (!r.deleted) await notifyGroup(io, req.params.id, 'member_left');
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.put('/:id/members/:userId/role', validate(roleSchema), async (req, res, next) => {
  try {
    if (badId(req.params.id, req.params.userId)) return res.status(400).json({ error: 'Invalid input' });
    const r = await setRole({
      groupId: req.params.id,
      actorId: req.user.id,
      targetId: req.params.userId,
      role: req.body.role,
    });
    if (r !== 'ok') return fail(res, r);
    await notifyGroup(req.app.get('io'), req.params.id, 'role_changed');
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.post('/:id/rekey', validate(rekeySchema), async (req, res, next) => {
  try {
    if (badId(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const r = await rekey({
      groupId: req.params.id,
      actorId: req.user.id,
      fromEpoch: req.body.fromEpoch,
      envelopes: req.body.envelopes,
    });
    if (r.error) return fail(res, r.error);
    await notifyGroup(req.app.get('io'), req.params.id, 'rekeyed', { epoch: r.epoch });
    res.json({ ok: true, epoch: r.epoch });
  } catch (err) {
    if (badEnvelopes(err, res)) return;
    next(err);
  }
});

// The caller's own wrapped keys, one per epoch, with the wrapper's public key needed to unwrap.
router.get('/:id/keys', async (req, res, next) => {
  try {
    if (badId(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    if (!(await getMembership(req.params.id, req.user.id))) return fail(res, 'not_found');
    const rows = await listMyEnvelopes(req.params.id, req.user.id);
    res.json({
      envelopes: rows.map((e) => ({
        epoch: e.epoch,
        wrappedKey: e.wrapped_key,
        iv: e.iv,
        wrappedBy: e.wrapped_by,
        wrapperPublicKey: e.wrapper_public_key,
      })),
    });
  } catch (err) {
    next(err);
  }
});

router.get('/:id/messages', async (req, res, next) => {
  try {
    if (badId(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    if (!(await getMembership(req.params.id, req.user.id))) return fail(res, 'not_found');
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);
    const raw = typeof req.query.before === 'string' ? Date.parse(req.query.before) : NaN;
    const before = Number.isNaN(raw) ? null : new Date(raw).toISOString();
    const rows = await listGroupMessages({ groupId: req.params.id, userId: req.user.id, limit, before });
    res.json({ messages: rows.reverse().map(serializeGroupMessage) });
  } catch (err) {
    next(err);
  }
});

router.delete('/:id/messages/:messageId', async (req, res, next) => {
  try {
    if (badId(req.params.id, req.params.messageId)) return res.status(400).json({ error: 'Invalid input' });
    const del = await deleteGroupMessage({
      groupId: req.params.id,
      messageId: req.params.messageId,
      actorId: req.user.id,
    });
    if (!del) return fail(res, 'not_found');
    emitToUsers(req.app.get('io'), await listMemberIds(req.params.id), 'group:message:deleted', {
      groupId: del.group_id,
      id: del.id,
    });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/groups.js
// End of file