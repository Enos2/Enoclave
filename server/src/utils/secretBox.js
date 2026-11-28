// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/utils/secretBox.js
// Purpose : Protects the secrets of the two-factor feature at rest, using keys
//           derived from JWT_SECRET with separate labels (so a key for one job
//           can never be used for another, or to forge login tokens).
//           seal(buffer) encrypts a TOTP secret with AES-256-GCM (random 12-byte
//           IV, authentication tag) and returns "iv.tag.ciphertext" in base64;
//           unseal reverses it and THROWS if anything was altered. A database
//           leak alone therefore does not reveal authenticator secrets.
//           Recovery codes: newRecoveryCode makes a 12-character code from an
//           alphabet without look-alike characters (about 60 bits), using the
//           cryptographic random generator; formatRecoveryCode shows it as
//           xxxxxx-xxxxxx; normalizeRecoveryCode makes user input comparable
//           (lowercase, dash removed); hashRecoveryCode stores it as a KEYED
//           HMAC-SHA256, so even an attacker holding the database cannot
//           brute-force the codes offline without the server's secret.
//           Note: changing JWT_SECRET makes every stored 2FA secret and
//           recovery-code hash unusable, so rotate it only with a migration plan.
// =============================================================================
import crypto from 'node:crypto';
import { env } from '../config/env.js';

const BOX_KEY = crypto.createHash('sha256').update(`enoclave-2fa-secrets:${env.jwtSecret}`).digest();
const MAC_KEY = crypto.createHash('sha256').update(`enoclave-recovery-codes:${env.jwtSecret}`).digest();
const RECOVERY_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789'; // 31 characters: no i, l, o, 0 or 1

export function seal(buffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', BOX_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return [iv, cipher.getAuthTag(), ciphertext].map((b) => b.toString('base64')).join('.');
}

export function unseal(sealed) {
  const [iv, tag, ciphertext] = String(sealed)
    .split('.')
    .map((part) => Buffer.from(part, 'base64'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', BOX_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function newRecoveryCode() {
  let code = '';
  for (let i = 0; i < 12; i += 1) code += RECOVERY_ALPHABET[crypto.randomInt(RECOVERY_ALPHABET.length)];
  return code;
}

export const formatRecoveryCode = (code) => `${code.slice(0, 6)}-${code.slice(6)}`;
export const normalizeRecoveryCode = (code) => String(code).toLowerCase().replace(/-/g, '');
export const hashRecoveryCode = (normalized) => crypto.createHmac('sha256', MAC_KEY).update(normalized).digest('hex');

// File: server/src/utils/secretBox.js
// End of file