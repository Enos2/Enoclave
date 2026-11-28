// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/sessions.js
// Purpose : HTTP API under /api/sessions for managing logged-in devices and
//           reviewing account security. GET / lists active sessions and
//           marks the current one; GET /events returns the last 50 security
//           events (logins, logouts, key changes); DELETE /:id revokes one
//           session (and logs this browser out if it is the current one);
//           DELETE / revokes every OTHER session. Revoking disconnects that
//           device's live sockets immediately. Session required; rate
//           limited; ids validated as UUIDs.
// =============================================================================
import { Router } from 'express';
import { listSessions, revokeSession, revokeOthers } from '../models/Session.js';
import { logEvent, recentEvents } from '../models/AuthEvent.js';
import { requireAuth } from '../middleware/auth.js';
import { socialLimiter } from '../middleware/security.js';
import { isUuid } from '../utils/serialize.js';
import { clientInfo } from '../utils/device.js';
import { clearAuthCookie } from '../utils/token.js';

const router = Router();
router.use(requireAuth, socialLimiter);

const kick = (req, ids) => {
  const io = req.app.get('io');
  for (const id of ids) io?.in(`session:${id}`).disconnectSockets(true);
};

router.get('/', async (req, res, next) => {
  try {
    const rows = await listSessions(req.user.id);
    res.json({
      sessions: rows.map((s) => ({
        id: s.id,
        device: s.device_label,
        createdAt: s.created_at,
        lastSeenAt: s.last_seen_at,
        expiresAt: s.expires_at,
        current: s.id === req.user.session_id,
      })),
    });
  } catch (err) {
    next(err);
  }
});

router.get('/events', async (req, res, next) => {
  try {
    const rows = await recentEvents(req.user.id, 50);
    res.json({
      events: rows.map((e) => ({ event: e.event, device: e.device_label, at: e.created_at })),
    });
  } catch (err) {
    next(err);
  }
});

// Revoke every session except the current one.
router.delete('/', async (req, res, next) => {
  try {
    const ids = await revokeOthers(req.user.id, req.user.session_id);
    kick(req, ids);
    if (ids.length) {
      await logEvent({ userId: req.user.id, username: req.user.username, event: 'session_revoked', ...clientInfo(req) });
    }
    res.json({ ok: true, revoked: ids.length });
  } catch (err) {
    next(err);
  }
});

// Revoke one session. Revoking the current one also logs this browser out.
router.delete('/:id', async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const done = await revokeSession(req.params.id, req.user.id);
    if (!done) return res.status(404).json({ error: 'Not found' });
    kick(req, [req.params.id]);
    await logEvent({ userId: req.user.id, username: req.user.username, event: 'session_revoked', ...clientInfo(req) });
    if (req.params.id === req.user.session_id) clearAuthCookie(res);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/sessions.js
// End of file