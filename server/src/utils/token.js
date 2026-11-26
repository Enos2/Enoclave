// File: server/src/utils/token.js
// Purpose: Create/verify session-bound JWTs and manage the httpOnly auth cookie.
import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';

export const COOKIE_NAME = 'token';
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

const cookieOptions = () => ({
  httpOnly: true,
  secure: env.isProd,
  sameSite: 'strict',
  path: '/',
});

export function signToken(user, sessionId) {
  return jwt.sign({ sub: user.id, tv: user.token_version, sid: sessionId }, env.jwtSecret, {
    algorithm: 'HS256',
    expiresIn: Math.floor(SESSION_TTL_MS / 1000),
  });
}

export function verifyToken(token) {
  return jwt.verify(token, env.jwtSecret, { algorithms: ['HS256'] });
}

export function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, { ...cookieOptions(), maxAge: SESSION_TTL_MS });
}

export function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME, cookieOptions());
}

// File: server/src/utils/token.js
// End of file