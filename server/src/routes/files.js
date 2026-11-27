// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/files.js
// Purpose : HTTP API for encrypted attachments, auto-mounted at /api/files.
//           The server only ever handles CIPHERTEXT: clients encrypt the file
//           with a random key, upload the result, and send the file id and key
//           inside the normal end-to-end encrypted message.
//           POST /init: validates the request (kind, declared size, exactly one
//           target - a recipient or a group, lifetime 1 minute to 30 days) and
//           checks permissions, blocks and quotas BEFORE any bytes are sent.
//           PUT /:id/content: streams the raw body (Content-Type
//           application/octet-stream). The size must match the declared size
//           exactly (checked from Content-Length and counted while streaming,
//           so an oversized or truncated upload is cut off). Data is written to
//           a temp file and renamed into place only when complete.
//           GET /:id/link: if the caller may access the file, returns a
//           60-second signed URL bound to that user. GET /:id/download: needs
//           the signed URL AND the session cookie, re-checks access, then
//           streams the ciphertext with no-store headers.
//           DELETE /:id: the owner (or, for group files, a group admin).
//           Every route needs a valid session. Non-members and unknown ids get
//           404, never 403, so files cannot be discovered by id.
// =============================================================================
import { Router } from 'express';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { rename, unlink } from 'node:fs/promises';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { socialLimiter } from '../middleware/security.js';
import { isUuid } from '../utils/serialize.js';
import { ensureStorage, blobPath, partPath, removeBlob } from '../utils/storage.js';
import { signDownload, verifyDownload } from '../utils/signedUrl.js';
import {
  createUpload,
  claimUpload,
  releaseUpload,
  completeUpload,
  getAccessible,
  deleteFile,
} from '../models/Attachment.js';

await ensureStorage();

const router = Router();
router.use(requireAuth);

const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many uploads. Slow down.' },
});

const uuid = z.string().refine(isUuid);
const initSchema = z
  .object({
    kind: z.enum(['file', 'voice']),
    sizeBytes: z.number().int().min(28).max(26214400),
    recipientId: uuid.optional(),
    groupId: uuid.optional(),
    ttlSeconds: z.number().int().min(60).max(2592000).default(604800),
  })
  .strict()
  .refine((b) => Boolean(b.recipientId) !== Boolean(b.groupId), { message: 'Exactly one target' });

const ERRORS = {
  not_found: [404, 'Not found'],
  unblock_first: [409, 'Unblock this user first'],
  too_large: [413, 'File too large for this type'],
  quota: [413, 'Storage quota exceeded'],
  limit: [429, 'Too many unfinished uploads'],
};

router.post('/init', socialLimiter, validate(initSchema), async (req, res, next) => {
  try {
    const { kind, sizeBytes, recipientId, groupId, ttlSeconds } = req.body;
    if (recipientId === req.user.id) return res.status(400).json({ error: 'Invalid input' });
    const r = await createUpload({ ownerId: req.user.id, kind, sizeBytes, recipientId, groupId, ttlSeconds });
    if (r.error) {
      const [status, error] = ERRORS[r.error];
      return res.status(status).json({ error });
    }
    res.status(201).json({
      file: { id: r.file.id, expiresAt: r.file.expires_at, uploadPath: `/api/files/${r.file.id}/content` },
    });
  } catch (err) {
    next(err);
  }
});

router.put('/:id/content', uploadLimiter, async (req, res, next) => {
  const id = req.params.id;
  if (!isUuid(id)) return res.status(400).json({ error: 'Invalid input' });
  let claimed = false;
  try {
    const f = await claimUpload(id, req.user.id);
    if (!f) return res.status(404).json({ error: 'Not found' });
    claimed = true;

    if (req.get('content-type') !== 'application/octet-stream') {
      await releaseUpload(id);
      return res.status(415).json({ error: 'Content-Type must be application/octet-stream' });
    }
    const declared = Number(req.get('content-length'));
    if (!Number.isInteger(declared)) {
      await releaseUpload(id);
      return res.status(411).json({ error: 'Content-Length required' });
    }
    if (declared !== f.size_bytes) {
      await releaseUpload(id);
      return res.status(400).json({ error: 'Size does not match the declared size' });
    }

    let received = 0;
    const counter = new Transform({
      transform(chunk, _enc, cb) {
        received += chunk.length;
        if (received > f.size_bytes) return cb(new Error('too_large'));
        cb(null, chunk);
      },
    });
    const tmp = partPath(id);
    try {
      await pipeline(req, counter, createWriteStream(tmp, { flags: 'w', mode: 0o600 }));
      if (received !== f.size_bytes) throw new Error('incomplete');
      await rename(tmp, blobPath(id));
    } catch (err) {
      await unlink(tmp).catch(() => {});
      await releaseUpload(id);
      claimed = false;
      if (res.headersSent) return undefined;
      const bad = err.message === 'too_large' || err.message === 'incomplete';
      return res.status(bad ? 400 : 500).json({ error: bad ? 'Upload size mismatch' : 'Upload failed' });
    }

    if (!(await completeUpload(id, req.user.id))) {
      await removeBlob(id); // the record vanished during the upload (for example the group was destroyed)
      return res.status(404).json({ error: 'Not found' });
    }
    claimed = false;
    return res.json({ ok: true });
  } catch (err) {
    if (claimed) await releaseUpload(id).catch(() => {});
    return next(err);
  }
});

router.get('/:id/link', socialLimiter, async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const f = await getAccessible(req.params.id, req.user.id);
    if (!f) return res.status(404).json({ error: 'Not found' });
    const { exp, sig } = signDownload(f.id, req.user.id);
    res.set('Cache-Control', 'no-store');
    res.json({
      url: `/api/files/${f.id}/download?e=${exp}&s=${sig}`,
      expiresAt: new Date(exp * 1000).toISOString(),
      sizeBytes: f.size_bytes,
    });
  } catch (err) {
    next(err);
  }
});

router.get('/:id/download', async (req, res, next) => {
  try {
    const id = req.params.id;
    if (!isUuid(id)) return res.status(400).json({ error: 'Invalid input' });
    const { e, s } = req.query;
    if (typeof e !== 'string' || typeof s !== 'string' || !verifyDownload(id, req.user.id, e, s)) {
      return res.status(403).json({ error: 'Invalid or expired link' });
    }
    const f = await getAccessible(id, req.user.id);
    if (!f) return res.status(404).json({ error: 'Not found' });

    const stream = createReadStream(blobPath(id));
    stream.once('open', () => {
      res.set({
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(f.size_bytes),
        'Content-Disposition': 'attachment; filename="encrypted.bin"',
        'Cache-Control': 'private, no-store',
        'X-Content-Type-Options': 'nosniff',
      });
      pipeline(stream, res).catch(() => res.destroy());
    });
    stream.once('error', (err) => {
      if (res.headersSent) return res.destroy();
      return res.status(err.code === 'ENOENT' ? 404 : 500).json({ error: err.code === 'ENOENT' ? 'Not found' : 'Server error' });
    });
  } catch (err) {
    next(err);
  }
});

router.delete('/:id', socialLimiter, async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const done = await deleteFile(req.params.id, req.user.id);
    if (!done) return res.status(404).json({ error: 'Not found' });
    await removeBlob(req.params.id);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/files.js
// End of file