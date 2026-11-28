// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/auth.js
// Purpose : HTTP API under /api/auth for accounts and sessions. POST /register
//           creates an account (username, passphrase, and the PUBLIC half of
//           the user's encryption key; the private key never leaves the
//           device) and starts a session. POST /login checks the passphrase
//           with bcrypt in constant time (unknown usernames cost the same time
//           as wrong passwords, and both give the same generic error), applies
//           the brute-force lockout (5 failures per username+network or 25 per
//           username in 15 minutes -> 429 with Retry-After), and refuses
//           suspended accounts with 403. GET /me returns the current user
//           (including isAdmin). POST /logout revokes only the current session
//           and always clears the cookie. POST /logout-all revokes every
//           session and invalidates all existing tokens. Sessions are capped
//           at 10 per user (the oldest is evicted and its sockets cut). Every
//           security-relevant event is written to the audit log, which stores
//           a keyed hash of the network address, never the address itself.
// =============================================================================
import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { createUser, findUserWithHash, bumpTokenVersion } from '../models/User.js';
import { createSession, revokeSession, revokeAll } from '../models/Session.js';
import { logEvent, lockoutSeconds } from '../models/AuthEvent.js';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { strictLimiter, registerLimiter } from '../middleware/security.js';
import { usernameSchema, passwordSchema, publicKeySchema } from '../utils/schemas.js';
import { publicUser, isUuid } from '../utils/serialize.js';
import { clientInfo } from '../utils/device.js';
import { COOKIE_NAME, signToken, verifyToken, setAuthCookie, clearAuthCookie } from '../utils/token.js';

const router = Router();

const registerSchema = z
  .object({ username: usernameSchema, password: passwordSchema, publicKey: publicKeySchema })
  .strict();
const loginSchema = z
  .object({ username: usernameSchema, password: z.string().min(1).max(72) })
  .strict();

// Used so that unknown usernames take the same time as wrong passwords.
const DUMMY_HASH = bcrypt.hashSync('enoclave-timing-equaliser', 12);

// Creates a session row, sets the cookie and disconnects any session evicted by the 10-session cap.
async function startSession(req, res, user, info) {
  const { session, evicted } = await createSession({ userId: user.id, ...info });
  setAuthCookie(res, signToken(user, session.id));
  const io = req.app.get('io');
  for (const id of evicted) io?.in(`session:${id}`).disconnectSockets(true);
}

router.post('/register', registerLimiter, validate(registerSchema), async (req, res, next) => {
  try {
    const { username, password, publicKey } = req.body;
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await createUser({ username, passwordHash, publicKey });
    const info = clientInfo(req);
    await startSession(req, res, user, info);
    await logEvent({ userId: user.id, username, event: 'register', ...info });
    res.status(201).json({ user: publicUser(user) });
  } catch (err) {
    if (err?.code === '23505') return res.status(409).json({ error: 'Username unavailable' });
    next(err);
  }
});

router.post('/login', strictLimiter, validate(loginSchema), async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const info = clientInfo(req);

    const wait = await lockoutSeconds(username, info.ipHash);
    if (wait > 0) {
      res.set('Retry-After', String(wait));
      return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
    }

    const user = await findUserWithHash(username);
    const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !ok) {
      await logEvent({ userId: user?.id ?? null, username, event: 'login_failed', ...info });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.suspended) {
      await logEvent({ userId: user.id, username, event: 'login_blocked_suspended', ...info });
      const until = user.suspended_until instanceof Date ? user.suspended_until.toISOString() : null;
      return res.status(403).json({ error: 'Account suspended', permanent: until === null, until });
    }

    await startSession(req, res, user, info);
    await logEvent({ userId: user.id, username, event: 'login_success', ...info });
    res.json({ user: publicUser(user) });
  } catch (err) {
    next(err);
  }
});

router.get('/me', requireAuth, (req, res) => {
  res.json({ user: { ...publicUser(req.user), isAdmin: Boolean(req.user.is_admin) } });
});

// Revokes only the current session; always clears the cookie, even if the token is already invalid.
router.post('/logout', async (req, res, next) => {
  try {
    const token = req.cookies?.[COOKIE_NAME];
    if (token) {
      try {
        const p = verifyToken(token);
        if (isUuid(p.sid) && isUuid(p.sub) && (await revokeSession(p.sid, p.sub))) {
          req.app.get('io')?.in(`session:${p.sid}`).disconnectSockets(true);
          await logEvent({ userId: p.sub, event: 'logout', ...clientInfo(req) });
        }
      } catch {
        /* expired or malformed token: nothing to revoke */
      }
    }
    clearAuthCookie(res);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.post('/logout-all', requireAuth, async (req, res, next) => {
  try {
    await revokeAll(req.user.id);
    await bumpTokenVersion(req.user.id);
    req.app.get('io')?.in(`user:${req.user.id}`).disconnectSockets(true);
    await logEvent({ userId: req.user.id, username: req.user.username, event: 'logout_all', ...clientInfo(req) });
    clearAuthCookie(res);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/auth.js
// End of file