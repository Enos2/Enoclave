// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/account.js
// Purpose : HTTP API for account self-service, auto-mounted at /api/account.
//           PUT /password { currentPassword, newPassword }: changes the
//           passphrase after re-checking the current one (bcrypt, constant
//           time). All of the user's OTHER sessions are revoked and their live
//           sockets cut (this device stays signed in), and the event is
//           audited. Encryption keys are device keys and are NOT affected.
//           POST /export { password }: re-confirms the passphrase, then returns
//           everything the server holds about the user as a JSON download
//           (Content-Disposition: attachment, Cache-Control: no-store; never
//           includes password hashes; message contents stay ciphertext).
//           Limited to 3 exports per hour per user. GET /security: a security
//           checkup - a 0-100 score from objective checks (signed-in devices,
//           recent failed logins, recent key changes, passphrase age, groups
//           waiting for a new key) plus informational notes about what the
//           privacy settings currently reveal. Passphrase checks are protected
//           against guessing even from a stolen session: after 5 failures in 15
//           minutes the user is answered 429 (Retry-After) whatever they send.
//           Every body uses a strict zod schema. Session required.
// =============================================================================
import { Router } from 'express';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { env } from '../config/env.js';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { strictLimiter, socialLimiter } from '../middleware/security.js';
import { passwordSchema } from '../utils/schemas.js';
import { clientInfo } from '../utils/device.js';
import { getPasswordHash } from '../models/User.js';
import { revokeOthers } from '../models/Session.js';
import { logEvent } from '../models/AuthEvent.js';
import { getSettings } from '../models/Settings.js';
import { setPassword, countRecentEvents, exportData, checkupFacts } from '../models/Account.js';

const router = Router();
router.use(requireAuth);

const MAX_FAILURES = 5;

const changeSchema = z
  .object({ currentPassword: z.string().min(1).max(72), newPassword: passwordSchema })
  .strict();
const exportSchema = z.object({ password: z.string().min(1).max(72) }).strict();

const exportLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 3 * (env.testMode ? 50 : 1),
  keyGenerator: (req) => req.user.id,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many exports. Try again later.' },
});

// Checks the passphrase with a per-user failure lockout. Sends the error response itself and returns false on failure.
async function confirmPassword(req, res, failEvent, password) {
  if ((await countRecentEvents(req.user.id, failEvent, 15)) >= MAX_FAILURES) {
    res.set('Retry-After', '900');
    res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
    return false;
  }
  const hash = await getPasswordHash(req.user.id);
  if (hash && (await bcrypt.compare(password, hash))) return true;
  await logEvent({ userId: req.user.id, username: req.user.username, event: failEvent, ...clientInfo(req) });
  res.status(401).json({ error: 'Invalid credentials' });
  return false;
}

router.put('/password', strictLimiter, validate(changeSchema), async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!(await confirmPassword(req, res, 'password_change_failed', currentPassword))) return;
    if (newPassword === currentPassword) return res.status(400).json({ error: 'Choose a different passphrase' });

    await setPassword(req.user.id, await bcrypt.hash(newPassword, 12));
    const revoked = await revokeOthers(req.user.id, req.user.session_id);
    const io = req.app.get('io');
    for (const id of revoked) io?.in(`session:${id}`).disconnectSockets(true);
    await logEvent({ userId: req.user.id, username: req.user.username, event: 'password_changed', ...clientInfo(req) });
    res.json({ ok: true, otherSessionsRevoked: revoked.length });
  } catch (err) {
    next(err);
  }
});

router.post('/export', strictLimiter, exportLimiter, validate(exportSchema), async (req, res, next) => {
  try {
    if (!(await confirmPassword(req, res, 'export_auth_failed', req.body.password))) return;
    const data = await exportData(req.user.id);
    await logEvent({ userId: req.user.id, username: req.user.username, event: 'data_exported', ...clientInfo(req) });
    const body = {
      exportedAt: new Date().toISOString(),
      notes:
        'Message contents are end-to-end encrypted: the server stores only ciphertext and cannot read it. ' +
        'Messages and group messages are limited to the most recent 2000 of each. Your passphrase hash is never included.',
      ...data,
    };
    res.set({
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': 'attachment; filename="enoclave-export.json"',
      'Cache-Control': 'no-store',
    });
    res.send(JSON.stringify(body, null, 2));
  } catch (err) {
    next(err);
  }
});

router.get('/security', socialLimiter, async (req, res, next) => {
  try {
    const [f, s] = await Promise.all([checkupFacts(req.user.id), getSettings(req.user.id)]);
    const checks = [];
    const add = (id, status, penalty, title, detail) => checks.push({ id, status, penalty, title, detail });

    if (f.active_sessions > 5) {
      add('sessions', 'warn', 10, 'Many signed-in devices', `${f.active_sessions} devices are signed in. Sign out the ones you do not use.`);
    } else {
      add('sessions', 'ok', 0, 'Signed-in devices', `${f.active_sessions} device(s) signed in.`);
    }

    if (f.failed_logins >= 5) {
      add('failed_logins', 'warn', 15, 'Repeated failed logins', `${f.failed_logins} failed login attempts in the last 7 days. Consider changing your passphrase.`);
    } else {
      add('failed_logins', 'ok', 0, 'Failed logins', 'No unusual failed login activity.');
    }

    if (f.key_changes >= 1) {
      add('key_changes', 'warn', 10, 'Encryption keys changed recently', 'If you did not sign in on a new device, change your passphrase and sign out other devices.');
    } else {
      add('key_changes', 'ok', 0, 'Encryption keys', 'No key changes in the last 7 days.');
    }

    if (f.password_age_days > 365) {
      add('password_age', 'warn', 10, 'Old passphrase', `Your passphrase is ${Math.floor(f.password_age_days)} days old. Consider changing it.`);
    } else {
      add('password_age', 'ok', 0, 'Passphrase age', 'Your passphrase was changed within the last year.');
    }

    if (f.rekey_pending > 0) {
      add('group_rekey', 'warn', 5, 'Groups waiting for a new key', `${f.rekey_pending} group(s) you administer need a new encryption key before anyone can send.`);
    } else {
      add('group_rekey', 'ok', 0, 'Group keys', 'All your groups have current keys.');
    }

    if (s.show_presence) add('presence', 'info', 0, 'Online status is visible', 'Mutual contacts can see when you are online.');
    if (s.show_typing) add('typing', 'info', 0, 'Typing indicator is on', 'People you chat with can see when you are typing.');
    if (s.read_receipts) add('receipts', 'info', 0, 'Read receipts are on', 'People you chat with can see when you have read their messages.');

    const score = Math.max(0, 100 - checks.reduce((sum, c) => sum + c.penalty, 0));
    res.json({
      score,
      rating: score >= 90 ? 'strong' : score >= 70 ? 'good' : 'needs attention',
      checks: checks.map(({ penalty, ...rest }) => rest),
    });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/account.js
// End of file