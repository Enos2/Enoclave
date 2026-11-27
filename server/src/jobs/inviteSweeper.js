// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/jobs/inviteSweeper.js
// Purpose : Background cleanup for invite links, started once at boot and run
//           every five minutes. Deletes invites that expired more than a day
//           ago, were revoked more than a week ago, or were used up more than a
//           week ago, and deletes join requests that nobody answered within
//           seven days. (Inactive invites are already rejected at lookup time;
//           this job only keeps the tables small.) Failures are logged and
//           never crash the server; the timer is unref'd so it cannot keep the
//           process alive on shutdown.
// =============================================================================
import { query } from '../config/db.js';

export function startInviteSweeper() {
  const run = async () => {
    try {
      await query(
        `DELETE FROM group_invites
         WHERE expires_at < now() - interval '1 day'
            OR (revoked_at IS NOT NULL AND revoked_at < now() - interval '7 days')
            OR (uses >= max_uses AND created_at < now() - interval '7 days')`
      );
      await query("DELETE FROM group_join_requests WHERE created_at < now() - interval '7 days'");
    } catch (err) {
      console.error('[jobs] invite sweep failed:', err.message);
    }
  };
  run();
  const timer = setInterval(run, 5 * 60_000);
  timer.unref();
  return timer;
}

// File: server/src/jobs/inviteSweeper.js
// End of file