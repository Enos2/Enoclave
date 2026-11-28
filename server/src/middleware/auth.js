// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/middleware/auth.js
// Purpose : Decides WHO is making a request, for both HTTP and sockets.
//           authenticateToken(token) accepts a session-cookie JWT only if ALL
//           of these hold: the signature and expiry are valid, the user still
//           exists, the user's token_version matches (so "log out everywhere"
//           and suspensions invalidate old tokens instantly), the user is not
//           suspended, and the session row is not revoked or expired. It
//           returns the user plus session_id, or null - never an error that
//           says why. requireAuth is the Express middleware built on it (401
//           on failure; refreshes the session's last-seen time at most once a
//           minute). requireAdmin must run AFTER requireAuth: users who are not
//           admins get 404, not 403, so the admin API cannot be discovered.
//           The admin flag is read from the database on every request, never
//           from the token, so revoking admin rights takes effect at once.
//           This file is final.
// =============================================================================
import { findUserById } from '../models/User.js';
import { findActiveSession, touchSession } from '../models/Session.js';
import { COOKIE_NAME, verifyToken } from '../utils/token.js';
import { isUuid } from '../utils/serialize.js';

export async function authenticateToken(token) {
  if (!token) return null;
  try {
    const payload = verifyToken(token);
    if (!isUuid(payload.sub) || !isUuid(payload.sid)) return null;
    const user = await findUserById(payload.sub);
    if (!user || user.token_version !== payload.tv || user.suspended) return null;
    const session = await findActiveSession(payload.sid, user.id);
    if (!session) return null;
    return { ...user, session_id: session.id };
  } catch {
    return null;
  }
}

export async function requireAuth(req, res, next) {
  const user = await authenticateToken(req.cookies?.[COOKIE_NAME]);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  req.user = user;
  touchSession(user.session_id).catch(() => {});
  next();
}

export function requireAdmin(req, res, next) {
  if (!req.user?.is_admin) return res.status(404).json({ error: 'Not found' });
  next();
}

// File: server/src/middleware/auth.js
// End of file