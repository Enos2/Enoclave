// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/middleware/security.js
// Purpose : The server's request-level defences. originGuard blocks every
//           state-changing request (POST, PUT, DELETE) whose Origin header is
//           not exactly CLIENT_ORIGIN; together with SameSite=Strict cookies
//           this stops cross-site request forgery. The rate limiters, each
//           returning a JSON 429 with standard RateLimit headers:
//           strictLimiter (20 FAILED attempts per 15 min - successful requests
//           do not count - for login, key rotation, account deletion, invite
//           redeem), registerLimiter (20 sign-ups per hour per network),
//           searchLimiter (30 per minute), socialLimiter (60 per minute, for
//           contacts, blocks, sessions, groups, rooms, files, settings),
//           reportLimiter (20 reports per hour) and adminLimiter (120 per
//           minute). In TEST_MODE every limit is multiplied by 50 so the
//           automated test suites can run repeatedly (the server refuses to
//           start with TEST_MODE in production). This file is final.
// =============================================================================
import rateLimit from 'express-rate-limit';
import { env } from '../config/env.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const scale = env.testMode ? 50 : 1;

export function originGuard(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();
  if (req.get('origin') !== env.clientOrigin) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

const make = (windowMs, limit, message, extra = {}) =>
  rateLimit({
    windowMs,
    limit: limit * scale,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: message },
    ...extra,
  });

export const strictLimiter = make(15 * 60 * 1000, 20, 'Too many attempts. Try again later.', {
  skipSuccessfulRequests: true,
});
export const registerLimiter = make(60 * 60 * 1000, 20, 'Too many sign-ups from this network. Try again later.');
export const searchLimiter = make(60 * 1000, 30, 'Too many searches. Slow down.');
export const socialLimiter = make(60 * 1000, 60, 'Too many requests. Slow down.');
export const reportLimiter = make(60 * 60 * 1000, 20, 'Too many reports. Try again later.');
export const adminLimiter = make(60 * 1000, 120, 'Too many requests. Slow down.');

// File: server/src/middleware/security.js
// End of file