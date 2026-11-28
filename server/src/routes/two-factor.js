// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/two-factor.js
// Purpose : HTTP API for two-factor authentication, auto-mounted at
//           /api/two-factor. All routes need a valid session. GET /status:
//           { enabled, recoveryCodesRemaining }. POST /setup { password }:
//           re-confirms the passphrase, creates a new secret (encrypted before
//           it is stored) and returns it with an otpauth:// URL for a QR code;
//           2FA stays OFF until the next step proves the app works (409 if it
//           is already enabled). POST /enable { code }: verifies the first code
//           from the authenticator app, switches 2FA on and returns 10
//           single-use recovery codes - the ONLY time they are shown.
//           POST /disable { password, code | recoveryCode }: needs the
//           passphrase AND a valid second factor. POST /recovery-codes {
//           password, code }: needs the passphrase AND a current authenticator
//           code (a recovery code is not accepted), replaces all old codes and
//           returns 10 new ones once. Every response that carries a secret or
//           codes is Cache-Control: no-store. Brute-force protection: failures
//           (wrong passphrase OR wrong code) are logged as 'two_factor_failed';
//           after 5 in 15 minutes every route here answers 429, even to the
//           right answer. A code works only once (replay protection, see
//           models/TwoFactor.js). Enabling, disabling and regenerating are
//           written to the audit log. Strict zod schemas; rate limited.
// =============================================================================
import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { strictLimiter, socialLimiter } from '../middleware/security.js';
import { clientInfo } from '../utils/device.js';
import { logEvent } from '../models/AuthEvent.js';
import { confirmPassword, isLocked, recordFailure } from '../utils/passwordCheck.js';
import { newSecret, base32Encode, otpauthUrl, DIGITS, PERIOD } from '../utils/totp.js';
import {
  seal,
  newRecoveryCode,
  formatRecoveryCode,
  normalizeRecoveryCode,
  hashRecoveryCode,
} from '../utils/secretBox.js';
import {
  getTwoFactor,
  beginSetup,
  pendingStep,
  enableTwoFactor,
  checkSecondFactor,
  replaceRecoveryCodes,
  disableTwoFactor,
  remainingRecoveryCodes,
} from '../models/TwoFactor.js';

const router = Router();
router.use(requireAuth);

const FAIL_EVENT = 'two_factor_failed';
const codeField = z.string().regex(/^\d{6}$/);
const recoveryField = z.string().regex(/^[A-Za-z0-9]{6}-?[A-Za-z0-9]{6}$/);
const password = z.string().min(1).max(72);

const setupSchema = z.object({ password }).strict();
const enableSchema = z.object({ code: codeField }).strict();
const disableSchema = z
  .object({ password, code: codeField.optional(), recoveryCode: recoveryField.optional() })
  .strict()
  .refine((b) => Boolean(b.code) !== Boolean(b.recoveryCode), { message: 'Send exactly one second factor' });
const regenSchema = z.object({ password, code: codeField }).strict();

const audit = (req, event) =>
  logEvent({ userId: req.user.id, username: req.user.username, event, ...clientInfo(req) });

function makeRecoveryCodes() {
  const codes = Array.from({ length: 10 }, newRecoveryCode);
  return { shown: codes.map(formatRecoveryCode), hashes: codes.map((c) => hashRecoveryCode(normalizeRecoveryCode(c))) };
}

router.get('/status', socialLimiter, async (req, res, next) => {
  try {
    const record = await getTwoFactor(req.user.id);
    const enabled = Boolean(record?.enabled);
    res.json({ enabled, recoveryCodesRemaining: enabled ? await remainingRecoveryCodes(req.user.id) : 0 });
  } catch (err) {
    next(err);
  }
});

router.post('/setup', strictLimiter, validate(setupSchema), async (req, res, next) => {
  try {
    if (!(await confirmPassword(req, res, FAIL_EVENT, req.body.password))) return;
    const secret = newSecret();
    if (!(await beginSetup(req.user.id, seal(secret)))) {
      return res.status(409).json({ error: 'Two-factor authentication is already enabled' });
    }
    const secretBase32 = base32Encode(secret);
    res.set('Cache-Control', 'no-store');
    return res.json({
      secret: secretBase32,
      otpauthUrl: otpauthUrl({ issuer: 'Enoclave', account: req.user.username, secretBase32 }),
      digits: DIGITS,
      period: PERIOD,
    });
  } catch (err) {
    return next(err);
  }
});

router.post('/enable', strictLimiter, validate(enableSchema), async (req, res, next) => {
  try {
    if (await isLocked(req.user.id, FAIL_EVENT)) {
      res.set('Retry-After', '900');
      return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
    }
    const record = await getTwoFactor(req.user.id);
    if (!record) return res.status(400).json({ error: 'Start the setup first' });
    if (record.enabled) return res.status(409).json({ error: 'Two-factor authentication is already enabled' });

    const step = pendingStep(record, req.body.code);
    if (step === null) {
      await recordFailure(req, FAIL_EVENT);
      return res.status(400).json({ error: 'Invalid code' });
    }
    const codes = makeRecoveryCodes();
    if (!(await enableTwoFactor(req.user.id, step, codes.hashes))) {
      return res.status(409).json({ error: 'Two-factor authentication is already enabled' });
    }
    await audit(req, 'two_factor_enabled');
    res.set('Cache-Control', 'no-store');
    return res.json({ ok: true, recoveryCodes: codes.shown });
  } catch (err) {
    return next(err);
  }
});

router.post('/disable', strictLimiter, validate(disableSchema), async (req, res, next) => {
  try {
    if (!(await confirmPassword(req, res, FAIL_EVENT, req.body.password))) return;
    const result = await checkSecondFactor(req.user.id, { code: req.body.code, recoveryCode: req.body.recoveryCode });
    if (result === 'none') return res.status(409).json({ error: 'Two-factor authentication is not enabled' });
    if (result !== 'ok') {
      await recordFailure(req, FAIL_EVENT);
      return res.status(400).json({ error: 'Invalid code' });
    }
    await disableTwoFactor(req.user.id);
    await audit(req, 'two_factor_disabled');
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
});

router.post('/recovery-codes', strictLimiter, validate(regenSchema), async (req, res, next) => {
  try {
    if (!(await confirmPassword(req, res, FAIL_EVENT, req.body.password))) return;
    const result = await checkSecondFactor(req.user.id, { code: req.body.code });
    if (result === 'none') return res.status(409).json({ error: 'Two-factor authentication is not enabled' });
    if (result !== 'ok') {
      await recordFailure(req, FAIL_EVENT);
      return res.status(400).json({ error: 'Invalid code' });
    }
    const codes = makeRecoveryCodes();
    await replaceRecoveryCodes(req.user.id, codes.hashes);
    await audit(req, 'recovery_codes_regenerated');
    res.set('Cache-Control', 'no-store');
    return res.json({ ok: true, recoveryCodes: codes.shown });
  } catch (err) {
    return next(err);
  }
});

export default router;

// File: server/src/routes/two-factor.js
// End of file