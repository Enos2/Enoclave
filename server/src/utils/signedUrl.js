// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/utils/signedUrl.js
// Purpose : Short-lived, tamper-proof download links for encrypted files.
//           signDownload(fileId, userId) returns an expiry (60 seconds from
//           now) and an HMAC-SHA256 signature over "fileId, userId, expiry".
//           verifyDownload checks all three: the signature matches (compared
//           in constant time, so it cannot be guessed byte by byte), the
//           expiry has not passed, and the expiry is not unreasonably far in
//           the future. Because the user id is inside the signed data, a link
//           copied to another account is rejected. The signing key is derived
//           from JWT_SECRET with a separate label, so it can never be used to
//           forge login tokens. Links add defence in depth: the download route
//           ALSO requires the session cookie and re-checks file access.
// =============================================================================
import crypto from 'node:crypto';
import { env } from '../config/env.js';

const KEY = crypto.createHash('sha256').update(`enoclave-file-links:${env.jwtSecret}`).digest();
export const LINK_TTL_SECONDS = 60;

const mac = (fileId, userId, exp) =>
  crypto.createHmac('sha256', KEY).update(`file-download:${fileId}:${userId}:${exp}`).digest('base64url');

export function signDownload(fileId, userId) {
  const exp = Math.floor(Date.now() / 1000) + LINK_TTL_SECONDS;
  return { exp, sig: mac(fileId, userId, exp) };
}

export function verifyDownload(fileId, userId, exp, sig) {
  const e = Number(exp);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isInteger(e) || e < now || e > now + LINK_TTL_SECONDS + 5) return false;
  if (typeof sig !== 'string' || sig.length !== 43) return false;
  const a = Buffer.from(sig);
  const b = Buffer.from(mac(fileId, userId, e));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// File: server/src/utils/signedUrl.js
// End of file