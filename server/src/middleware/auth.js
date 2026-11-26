// File: server/src/middleware/auth.js
// Purpose: Authenticate requests and sockets via the session-bound cookie; revoked or expired sessions are rejected.
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
    if (!user || user.token_version !== payload.tv) return null;
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

// File: server/src/middleware/auth.js
// End of file