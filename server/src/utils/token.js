// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/utils/token.js
// Purpose : Creates and verifies the session-bound login token (a JWT signed
//           with HS256 only, so algorithm-confusion attacks are impossible)
//           and manages the cookie that carries it. The token holds the user
//           id, the user token_version (bumping it invalidates every old
//           token at once) and the session id (revoking that one session
//           invalidates just this device). The cookie is httpOnly
//           (JavaScript cannot read it), SameSite=Strict (never sent on
//           cross-site requests) and Secure in production; sessions last 12
//           hours.
// =============================================================================
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