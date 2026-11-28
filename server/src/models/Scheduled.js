// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/Scheduled.js
// Purpose : Data-access layer for scheduled (time-locked) direct messages. The
//           server stores ciphertext only and never learns the content.
//           createScheduled runs in one transaction under a per-user lock (so
//           parallel requests cannot exceed the cap of 50 pending messages) and
//           checks: the recipient exists, YOU have not blocked them (if THEY
//           blocked you the schedule is accepted and silently dropped at
//           delivery, so a blocked sender learns nothing), and the delivery
//           time is between 10 seconds and 30 days from the SERVER's clock
//           (checked inside SQL, so a wrong client clock cannot cheat).
//           listScheduled returns a user's pending items WITHOUT their
//           ciphertext; cancelScheduled lets only the sender cancel.
//           deliverDue is called by the delivery job: in ONE transaction it
//           locks the due rows (SKIP LOCKED, so two processes never take the
//           same row), and for each one applies the rules - sender blocked the
//           recipient: failed; recipient blocked the sender or the sender is
//           suspended: dropped silently; otherwise the message is inserted (its
//           disappearing and burn timers start NOW, at delivery) - and deletes
//           the schedule row. Insert and delete share a transaction, so a crash
//           can never duplicate or lose a message. It returns the outcomes so
//           the caller can notify people AFTER the commit.
// =============================================================================
import { query, withTransaction } from '../config/db.js';

const MAX_PENDING = 50;

export async function createScheduled({ from, to, ciphertext, iv, deliverAt, ttlSeconds, burnSeconds }) {
  return withTransaction(async (c) => {
    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`scheduled:${from}`]);

    const exists = await c.query('SELECT 1 FROM users WHERE id = $1', [to]);
    if (!exists.rowCount) return { error: 'not_found' };

    const blocked = await c.query('SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [from, to]);
    if (blocked.rowCount) return { error: 'unblock_first' };

    const n = await c.query('SELECT count(*)::int AS n FROM scheduled_messages WHERE from_id = $1', [from]);
    if (n.rows[0].n >= MAX_PENDING) return { error: 'limit' };

    const ins = await c.query(
      `INSERT INTO scheduled_messages (from_id, to_id, ciphertext, iv, deliver_at, ttl_seconds, burn_after_read_seconds)
       SELECT $1::uuid, $2::uuid, $3::text, $4::text, $5::timestamptz, $6::integer, $7::integer
       WHERE $5::timestamptz >= now() + interval '10 seconds'
         AND $5::timestamptz <= now() + interval '30 days'
       RETURNING id, to_id, deliver_at`,
      [from, to, ciphertext, iv, deliverAt, ttlSeconds ?? null, burnSeconds ?? null]
    );
    if (!ins.rowCount) return { error: 'bad_time' };
    return { scheduled: ins.rows[0] };
  });
}

export async function listScheduled(userId) {
  const { rows } = await query(
    `SELECT s.id, s.to_id, u.username AS to_username, s.deliver_at, s.ttl_seconds,
            s.burn_after_read_seconds, s.created_at
     FROM scheduled_messages s JOIN users u ON u.id = s.to_id
     WHERE s.from_id = $1
     ORDER BY s.deliver_at`,
    [userId]
  );
  return rows;
}

export async function cancelScheduled(id, userId) {
  const { rowCount } = await query('DELETE FROM scheduled_messages WHERE id = $1 AND from_id = $2', [id, userId]);
  return rowCount > 0;
}

// Returns [{ type: 'delivered', id, message } | { type: 'failed', id, fromId, reason } | { type: 'dropped', id }]
export async function deliverDue(limit = 50) {
  return withTransaction(async (c) => {
    const due = await c.query(
      `SELECT id, from_id, to_id, ciphertext, iv, ttl_seconds, burn_after_read_seconds
       FROM scheduled_messages
       WHERE deliver_at <= now()
       ORDER BY deliver_at
       LIMIT $1
       FOR UPDATE SKIP LOCKED`,
      [limit]
    );

    const results = [];
    for (const s of due.rows) {
      const state = await c.query(
        `SELECT EXISTS (SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2) AS i_blocked,
                EXISTS (SELECT 1 FROM blocks WHERE blocker_id = $2 AND blocked_id = $1) AS blocked_me,
                EXISTS (SELECT 1 FROM users WHERE id = $1 AND suspended_until IS NOT NULL AND suspended_until > now()) AS suspended`,
        [s.from_id, s.to_id]
      );
      const st = state.rows[0];

      if (st.i_blocked) {
        results.push({ type: 'failed', id: s.id, fromId: s.from_id, reason: 'blocked' });
      } else if (st.blocked_me || st.suspended) {
        results.push({ type: 'dropped', id: s.id });
      } else {
        const ins = await c.query(
          `INSERT INTO messages (from_id, to_id, ciphertext, iv, expires_at, burn_after_read_seconds)
           VALUES ($1, $2, $3, $4,
             CASE WHEN $5::double precision IS NULL THEN NULL
                  ELSE now() + make_interval(secs => $5::double precision) END,
             $6::integer)
           RETURNING id, from_id, to_id, ciphertext, iv, created_at, expires_at, burn_after_read_seconds`,
          [s.from_id, s.to_id, s.ciphertext, s.iv, s.ttl_seconds, s.burn_after_read_seconds]
        );
        results.push({ type: 'delivered', id: s.id, message: ins.rows[0] });
      }
      await c.query('DELETE FROM scheduled_messages WHERE id = $1', [s.id]);
    }
    return results;
  });
}

// File: server/src/models/Scheduled.js
// End of file