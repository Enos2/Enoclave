// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/jobs/scheduledDelivery.js
// Purpose : Background job, started automatically at boot and run every 5
//           seconds, that delivers scheduled direct messages whose time has
//           come. models/Scheduled.js does the work inside a database
//           transaction (so nothing is duplicated or lost, even if the server
//           crashes mid-run, and two server processes never take the same
//           message); this file only notifies people AFTER the commit. For each
//           delivered message both people's devices receive the normal
//           'message:new' event, and the sender additionally receives
//           'scheduled:delivered' { id, messageId }. If the sender had blocked
//           the recipient by delivery time the sender receives
//           'scheduled:failed' { id, reason: "blocked" }. Messages dropped
//           because the recipient blocked the sender (or the sender was
//           suspended) produce NO event, so a blocked sender cannot tell. If
//           the server was offline at the delivery time, overdue messages are
//           delivered on the next start. A guard flag stops a slow run from
//           overlapping the next, errors are caught and logged, and the timer
//           is unref'd so it does not block shutdown.
// =============================================================================
import { deliverDue } from '../models/Scheduled.js';
import { serializeMessage } from '../utils/serialize.js';
import { logger } from '../utils/logger.js';

const BATCH = 50;

export function startScheduledDelivery({ io } = {}) {
  let running = false;

  const run = async () => {
    if (running) return;
    running = true;
    try {
      let batch;
      do {
        batch = await deliverDue(BATCH);
        for (const r of batch) {
          if (r.type === 'delivered') {
            io?.to(`user:${r.message.from_id}`)
              .to(`user:${r.message.to_id}`)
              .emit('message:new', serializeMessage(r.message));
            io?.to(`user:${r.message.from_id}`).emit('scheduled:delivered', { id: r.id, messageId: r.message.id });
          } else if (r.type === 'failed') {
            io?.to(`user:${r.fromId}`).emit('scheduled:failed', { id: r.id, reason: r.reason });
          }
        }
      } while (batch.length === BATCH);
    } catch (err) {
      logger.error('scheduled delivery failed', { err });
    } finally {
      running = false;
    }
  };

  run();
  const timer = setInterval(run, 5000);
  timer.unref();
  return timer;
}

// File: server/src/jobs/scheduledDelivery.js
// End of file