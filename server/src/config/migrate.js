// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/config/migrate.js
// Purpose : Database migration runner, executed on every server start. It reads
//           the numbered files in ./migrations (001_base.js, 002_..., in order),
//           and applies each one exactly once, recording the name in the
//           schema_migrations table. Each migration runs inside its own
//           transaction, so a failure rolls back cleanly and leaves the
//           database unchanged, and the server refuses to start. A Postgres
//           advisory lock makes this safe if two server instances boot at the
//           same moment. To change the schema in future, add a new numbered
//           file to ./migrations; never edit one that has already been applied.
// =============================================================================
import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { pool } from './db.js';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'migrations');
const LOCK_ID = 727274;

export async function migrate() {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
       name       text PRIMARY KEY,
       applied_at timestamptz NOT NULL DEFAULT now()
     )`
  );

  const files = readdirSync(dir)
    .filter((f) => /^\d{3}_[a-z0-9_]+\.js$/.test(f))
    .sort();

  for (const file of files) {
    const mod = await import(pathToFileURL(path.join(dir, file)).href);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock($1)', [LOCK_ID]);
      const done = await client.query('SELECT 1 FROM schema_migrations WHERE name = $1', [mod.name]);
      if (!done.rowCount) {
        await client.query(mod.sql);
        await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [mod.name]);
        console.log(`[db] applied migration ${mod.name}`);
      }
      await client.query('COMMIT');
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
  console.log('[db] schema ready');
}

// File: server/src/config/migrate.js
// End of file