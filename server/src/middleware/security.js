// File: server/src/middleware/security.js
// Purpose: Origin guard for state-changing requests plus rate limiters for sensitive routes.
import rateLimit from 'express-rate-limit';
import { env } from '../config/env.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

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
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: message },
    ...extra,
  });

// Counts only FAILED attempts, so brute force is blocked but normal use is not.
export const strictLimiter = make(15 * 60 * 1000, 20, 'Too many attempts. Try again later.', {
  skipSuccessfulRequests: true,
});

// Limits account creation per IP to slow down mass sign-ups.
export const registerLimiter = make(60 * 60 * 1000, 20, 'Too many sign-ups from this network. Try again later.');

export const searchLimiter = make(60 * 1000, 30, 'Too many searches. Slow down.');

// Contacts, blocks and session management.
export const socialLimiter = make(60 * 1000, 60, 'Too many requests. Slow down.');

// File: server/src/middleware/security.js
// End of file