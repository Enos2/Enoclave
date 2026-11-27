// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/jobs/roomSweeper.js
// Purpose : Background job, started automatically at boot and run every 10
//           seconds. It does two things. (1) Destroys self-destruct rooms whose
//           lifespan has ended (the database cascade deletes their messages,
//           keys and invites) and sends every former member a 'group:destroyed'
//           event. (2) Starts the burn-on-read timers of group messages that are
//           now fully read - for example when the last unread member left the
//           group - and tells the group's members with a 'group:burning' event.
//           A guard flag stops a slow run from overlapping the next one, and
//           all errors are caught and logged so the job can never crash the
//           server. The timer is unref'd so it does not block shutdown.
// =============================================================================
import { destroyExpiredGroups } from '../models/GroupRoom.js';
import { startDueBurns } from '../models/GroupMessage.js';
import { listMemberIds } from '../models/Group.js';
import { emitToUsers } from '../utils/realtime.js';

export function startRoomSweeper({ io } = {}) {
  let running = false;

  const run = async () => {
    if (running) return;
    running = true;
    try {
      for (const room of await destroyExpiredGroups()) {
        emitToUsers(io, room.user_ids, 'group:destroyed', { groupId: room.id });
      }

      const members = new Map();
      for (const m of await startDueBurns(null)) {
        if (!members.has(m.group_id)) members.set(m.group_id, await listMemberIds(m.group_id));
        emitToUsers(io, members.get(m.group_id), 'group:burning', {
          groupId: m.group_id,
          id: m.id,
          expiresAt: m.expires_at,
        });
      }
    } catch (err) {
      console.error('[jobs] room sweep failed:', err.message);
    } finally {
      running = false;
    }
  };

  run();
  const timer = setInterval(run, 10_000);
  timer.unref();
  return timer;
}

// File: server/src/jobs/roomSweeper.js
// End of file