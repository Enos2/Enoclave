// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/scripts/make-admin.mjs
// Purpose : Command-line tool to grant or remove administrator rights. This is
//           the ONLY way to create an admin, on purpose: it needs access to the
//           server's database credentials, so no one can promote themselves
//           through the API. The flag is stored on the user's row, not tied to
//           a username, so re-registering a deleted admin's name gives nothing.
//           Usage (run inside the server folder, after the server has started
//           once so the migrations exist):
//             node scripts/make-admin.mjs <username>            grant
//             node scripts/make-admin.mjs <username> --revoke   remove
//           In Docker: docker compose exec api node scripts/make-admin.mjs <username>
//           The change takes effect on the user's next request (the flag is
//           read from the database every time, never from a token).
// =============================================================================
import { query, closePool } from '../src/config/db.js';

const [username, flag] = process.argv.slice(2);

if (!username || !/^[a-z0-9_]{3,24}$/.test(username) || (flag && flag !== '--revoke')) {
  console.error('Usage: node scripts/make-admin.mjs <username> [--revoke]');
  process.exit(1);
}

const grant = flag !== '--revoke';
try {
  const { rowCount } = await query('UPDATE users SET is_admin = $2 WHERE username = $1', [username, grant]);
  if (!rowCount) {
    console.error(`No user named "${username}".`);
    process.exitCode = 1;
  } else {
    console.log(`${grant ? 'Granted admin to' : 'Removed admin from'} ${username}.`);
  }
} catch (err) {
  console.error('Failed:', err.message);
  process.exitCode = 1;
} finally {
  await closePool();
}

// File: server/scripts/make-admin.mjs
// End of file