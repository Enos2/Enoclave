// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/config/db.js
// Purpose : Owns the single PostgreSQL (Neon) connection pool used by the whole
//           server. Exposes query() for one-off statements and
//           withTransaction() for multi-statement operations that must
//           succeed or fail together (group changes, account deletion).
//           Also runs the background sweeper, once a minute: it deletes
//           expired disappearing messages (direct and group), dead and
//           revoked login sessions, and audit-log rows older than 90 days.
//           The pool error handler is required: Neon drops idle connections,
//           and an unhandled pool error would otherwise crash the process.
// =============================================================================
import pg from 'pg';
import { env } from './env.js';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: env.databaseUrl,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 15_000, // Neon may need a few seconds to wake a suspended compute
});

pool.on('error', (err) => console.error('[db] idle client error:', err.message));

export const query = (text, params) => pool.query(text, params);

export async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      /* connection already gone */
    }
    throw err;
  } finally {
    client.release();
  }
}

export async function connectDB() {
  await pool.query('SELECT 1');
  console.log('[db] connected');
}

export function startExpirySweeper() {
  const run = async () => {
    try {
      await pool.query('DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= now()');
      await pool.query('DELETE FROM group_messages WHERE expires_at IS NOT NULL AND expires_at <= now()');
      await pool.query(
        `DELETE FROM sessions
         WHERE expires_at < now() - interval '1 day'
            OR (revoked_at IS NOT NULL AND revoked_at < now() - interval '7 days')`
      );
      await pool.query("DELETE FROM auth_events WHERE created_at < now() - interval '90 days'");
    } catch (err) {
      console.error('[db] sweep failed:', err.message);
    }
  };
  run();
  const timer = setInterval(run, 60_000);
  timer.unref();
  return timer;
}

// File: server/src/config/db.js
// End of file