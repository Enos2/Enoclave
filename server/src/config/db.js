// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/config/db.js
// Purpose : Owns the single PostgreSQL (Neon) connection pool used by the whole
//           server. query() runs one statement (and logs any query slower than
//           750 ms, with the SQL text trimmed and NEVER the parameters, so no
//           user data reaches logs); withTransaction() runs several statements
//           that must succeed or fail together; checkDb() is the readiness
//           probe (answers within 3 seconds or fails); closePool() is used by
//           graceful shutdown. The pool has a client-side query timeout of 25 s
//           so a hung connection cannot hold a request forever, and an error
//           handler: Neon drops idle connections and an unhandled pool error
//           would crash the process. startExpirySweeper() runs every minute:
//           it deletes expired disappearing messages (direct and group), dead
//           and revoked login sessions, and audit-log rows older than 90 days.
//           This file is final.
// =============================================================================
import pg from 'pg';
import { env } from './env.js';
import { logger } from '../utils/logger.js';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: env.databaseUrl,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 15_000, // Neon may need a few seconds to wake a suspended compute
  query_timeout: 25_000,
});

pool.on('error', (err) => logger.error('idle database client error', { err }));

export async function query(text, params) {
  const started = Date.now();
  try {
    return await pool.query(text, params);
  } finally {
    const ms = Date.now() - started;
    if (ms > 750) logger.warn('slow query', { ms, sql: text.replace(/\s+/g, ' ').trim().slice(0, 120) });
  }
}

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
  logger.info('database connected');
}

export async function checkDb() {
  await Promise.race([
    pool.query('SELECT 1'),
    new Promise((_, reject) => setTimeout(() => reject(new Error('database check timed out')), 3000).unref()),
  ]);
}

export const closePool = () => pool.end();

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
      logger.error('expiry sweep failed', { err });
    }
  };
  run();
  const timer = setInterval(run, 60_000);
  timer.unref();
  return timer;
}

// File: server/src/config/db.js
// End of file