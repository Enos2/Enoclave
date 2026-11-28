// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/utils/passwordCheck.js
// Purpose : Re-confirms the logged-in user's passphrase before a sensitive
//           action, with a per-USER failure lockout - so even someone holding a
//           stolen session cookie cannot guess the passphrase or the second
//           factor. isLocked(userId, event) is true after 5 failed attempts
//           logged under that event name in the last 15 minutes.
//           recordFailure(req, event) writes one failure to the audit log.
//           confirmPassword(req, res, event, password) does the whole job: if
//           the user is locked it answers 429 (with Retry-After); if the
//           passphrase is wrong it records a failure and answers 401; in both
//           cases it has ALREADY sent the response and returns false, so the
//           caller just does "if (!(await confirmPassword(...))) return;".
//           Returns true only for a correct passphrase. Used by the two-factor
//           routes; the account routes keep their own equivalent copy.
// =============================================================================
import bcrypt from 'bcryptjs';
import { getPasswordHash } from '../models/User.js';
import { countRecentEvents } from '../models/Account.js';
import { logEvent } from '../models/AuthEvent.js';
import { clientInfo } from './device.js';

const MAX_FAILURES = 5;

export async function isLocked(userId, event) {
  return (await countRecentEvents(userId, event, 15)) >= MAX_FAILURES;
}

export async function recordFailure(req, event) {
  await logEvent({ userId: req.user.id, username: req.user.username, event, ...clientInfo(req) });
}

export async function confirmPassword(req, res, event, password) {
  if (await isLocked(req.user.id, event)) {
    res.set('Retry-After', '900');
    res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
    return false;
  }
  const hash = await getPasswordHash(req.user.id);
  if (hash && (await bcrypt.compare(password, hash))) return true;
  await recordFailure(req, event);
  res.status(401).json({ error: 'Invalid credentials' });
  return false;
}

// File: server/src/utils/passwordCheck.js
// End of file