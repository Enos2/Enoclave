// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/utils/totp.js
// Purpose : A dependency-free implementation of time-based one-time passwords
//           (TOTP, RFC 6238 / HOTP, RFC 4226) as used by Google Authenticator,
//           Authy, 1Password and similar apps: HMAC-SHA1, 6 digits, 30-second
//           steps. Contains only PURE functions (no environment, no database),
//           so it can be tested in isolation against the RFC test vectors.
//           base32Encode / base32Decode convert secrets to and from the text
//           form authenticator apps expect. hotp(secret, counter, digits)
//           computes one code. stepAt(ms) converts a time to its 30-second
//           step number. verifyTotp(secret, code, options) accepts the current
//           step plus or minus one (to forgive small clock differences),
//           compares every candidate in constant time without stopping at the
//           first match, and returns the MATCHING STEP NUMBER (or null) so the
//           caller can refuse to accept the same step twice. otpauthUrl builds
//           the otpauth:// link that authenticator apps turn into a QR code.
//           newSecret returns 20 random bytes (160 bits).
// =============================================================================
import crypto from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const PERIOD = 30;
export const DIGITS = 6;

export const newSecret = () => crypto.randomBytes(20);

export function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text) {
  const clean = String(text).replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('invalid base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function hotp(secret, counter, digits = DIGITS) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', secret).update(msg).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export const stepAt = (ms) => Math.floor(ms / 1000 / PERIOD);

// Returns the matching time step, or null. Checks every candidate so timing does not reveal which one matched.
export function verifyTotp(secret, code, { nowMs = Date.now(), window = 1 } = {}) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return null;
  const current = stepAt(nowMs);
  let matched = null;
  for (let step = current - window; step <= current + window; step += 1) {
    const expected = Buffer.from(hotp(secret, step));
    if (crypto.timingSafeEqual(expected, Buffer.from(code))) matched = step;
  }
  return matched;
}

export function otpauthUrl({ issuer, account, secretBase32 }) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  return `otpauth://totp/${label}?secret=${secretBase32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${PERIOD}`;
}

// File: server/src/utils/totp.js
// End of file