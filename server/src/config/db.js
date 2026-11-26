// File: server/src/config/db.js
// Purpose: PostgreSQL (Neon) connection pool, query helper, transaction helper and background cleanup sweeper.
import pg from 'pg';
import { env } from './env.js';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: env.databaseUrl,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 15_000, // Neon may need a few seconds to wake a suspended compute
});

// Neon closes idle connections; without this handler a dropped idle client would crash the process.
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

// Runs every minute: removes expired disappearing messages, dead sessions and audit events older than 90 days.
export function startExpirySweeper() {
  const run = async () => {
    try {
      await pool.query('DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= now()');
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