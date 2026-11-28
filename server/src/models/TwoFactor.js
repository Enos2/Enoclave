// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/TwoFactor.js
// Purpose : Data-access layer for two-factor authentication. getTwoFactor reads
//           a user's record. beginSetup stores a fresh ENCRYPTED secret, but
//           only while 2FA is not yet enabled (an enabled account cannot be
//           silently re-seeded; it returns false). pendingStep checks a code
//           against the not-yet-enabled secret. enableTwoFactor switches it on
//           in one transaction: marks it enabled, stores the accepted time
//           step (so that exact code cannot be used again) and replaces the
//           recovery codes. consumeStep is the replay guard: ONE atomic UPDATE
//           that succeeds only if the new step is greater than the last
//           accepted one, so a code works once, concurrent attempts cannot both
//           win, and older codes are dead. Recovery codes are single-use:
//           consumeRecovery marks one as used atomically; remainingRecoveryCodes
//           counts the unused ones; replaceRecoveryCodes swaps the whole set.
//           disableTwoFactor removes the secret and every recovery code.
//           checkSecondFactor is what login uses. It returns 'none' (2FA is off,
//           nothing to check), 'missing' (2FA is on but no code was sent),
//           'ok' (a valid, unused code) or 'invalid' (anything else). Codes
//           are only ever compared inside this file and utils/totp.js.
// =============================================================================
import { query, withTransaction } from '../config/db.js';
import { verifyTotp } from '../utils/totp.js';
import { unseal, hashRecoveryCode, normalizeRecoveryCode } from '../utils/secretBox.js';

export async function getTwoFactor(userId) {
  const { rows } = await query('SELECT enabled, secret_enc, last_step FROM two_factor WHERE user_id = $1', [userId]);
  return rows[0] || null;
}

// Returns false when 2FA is already enabled (the secret is left untouched).
export async function beginSetup(userId, secretEnc) {
  const { rowCount } = await query(
    `INSERT INTO two_factor (user_id, secret_enc) VALUES ($1, $2)
     ON CONFLICT (user_id) DO UPDATE
       SET secret_enc = EXCLUDED.secret_enc, last_step = 0, created_at = now()
       WHERE two_factor.enabled = false`,
    [userId, secretEnc]
  );
  return rowCount > 0;
}

// The time step that matches, or null.
export function pendingStep(record, code) {
  return verifyTotp(unseal(record.secret_enc), code);
}

export async function enableTwoFactor(userId, step, codeHashes) {
  return withTransaction(async (c) => {
    const r = await c.query(
      'UPDATE two_factor SET enabled = true, enabled_at = now(), last_step = $2 WHERE user_id = $1 AND enabled = false',
      [userId, step]
    );
    if (!r.rowCount) return false;
    await c.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
    await c.query('INSERT INTO recovery_codes (user_id, code_hash) SELECT $1::uuid, h FROM unnest($2::text[]) AS h', [
      userId,
      codeHashes,
    ]);
    return true;
  });
}

export async function consumeStep(userId, step) {
  const { rowCount } = await query('UPDATE two_factor SET last_step = $2 WHERE user_id = $1 AND last_step < $2', [userId, step]);
  return rowCount > 0;
}

export async function consumeRecovery(userId, codeHash) {
  const { rowCount } = await query(
    'UPDATE recovery_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL',
    [userId, codeHash]
  );
  return rowCount > 0;
}

export async function remainingRecoveryCodes(userId) {
  const { rows } = await query('SELECT count(*)::int AS n FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL', [userId]);
  return rows[0].n;
}

export async function replaceRecoveryCodes(userId, codeHashes) {
  await withTransaction(async (c) => {
    await c.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
    await c.query('INSERT INTO recovery_codes (user_id, code_hash) SELECT $1::uuid, h FROM unnest($2::text[]) AS h', [
      userId,
      codeHashes,
    ]);
  });
}

export async function disableTwoFactor(userId) {
  await withTransaction(async (c) => {
    await c.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
    await c.query('DELETE FROM two_factor WHERE user_id = $1', [userId]);
  });
}

// 'none' | 'missing' | 'ok' | 'invalid'
export async function checkSecondFactor(userId, { code, recoveryCode } = {}) {
  const record = await getTwoFactor(userId);
  if (!record || !record.enabled) return 'none';
  if (!code && !recoveryCode) return 'missing';

  if (code) {
    const step = verifyTotp(unseal(record.secret_enc), code);
    if (step === null) return 'invalid';
    return (await consumeStep(userId, step)) ? 'ok' : 'invalid';
  }
  const hash = hashRecoveryCode(normalizeRecoveryCode(recoveryCode));
  return (await consumeRecovery(userId, hash)) ? 'ok' : 'invalid';
}

// File: server/src/models/TwoFactor.js
// End of file