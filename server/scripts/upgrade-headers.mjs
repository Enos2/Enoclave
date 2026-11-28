// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/scripts/upgrade-headers.mjs
// Purpose : One-time tool that upgrades the short headers written on Days 1-2
//           to the full project-standard header (project name, file path and a
//           detailed multi-line purpose), so you do not have to open twelve
//           files by hand. For each file listed below it replaces the leading
//           block of "//" comment lines with the new header and touches
//           NOTHING else. It is safe to run more than once: files that already
//           have the new header are skipped, missing files are reported, and
//           the original line endings (Windows or Unix) are preserved.
//           Run it from the server folder:  node scripts/upgrade-headers.mjs
// =============================================================================
import { readFileSync, writeFileSync, existsSync } from 'node:fs';

const HEADERS = {
  'src/middleware/validate.js':
    'Express middleware factory that validates req.body against a zod schema BEFORE any route logic runs. validate(schema) returns a middleware: if the body does not match (wrong types, missing fields, unknown fields when the schema is .strict(), values out of range) it answers 400 "Invalid input" without revealing which rule failed; otherwise it replaces req.body with the parsed, trimmed and type-coerced result, so handlers only ever see clean data. Used on every route that accepts a JSON body.',
  'src/utils/schemas.js':
    'Shared zod schemas for the data every account route accepts. usernameSchema: 3-24 characters, lowercase letters, digits and underscore, trimmed and lowercased. passwordSchema: 10-72 characters (72 is the most bcrypt can use). publicKeySchema: a strict EC P-256 public JWK - kty, crv and two 43-character base64url coordinates, nothing else. Keeping them in one place guarantees registration, login and key rotation apply identical rules.',
  'src/utils/token.js':
    'Creates and verifies the session-bound login token (a JWT signed with HS256 only, so algorithm-confusion attacks are impossible) and manages the cookie that carries it. The token holds the user id, the user token_version (bumping it invalidates every old token at once) and the session id (revoking that one session invalidates just this device). The cookie is httpOnly (JavaScript cannot read it), SameSite=Strict (never sent on cross-site requests) and Secure in production; sessions last 12 hours.',
  'src/utils/device.js':
    'Privacy-preserving client information for the device list and security log. hashIp turns a network address into a keyed HMAC-SHA256 hash (key derived from JWT_SECRET), so the same network can be recognised for lockouts WITHOUT the real address ever being stored. deviceLabel reduces a User-Agent string to a short label such as "Chrome on Windows". clientInfo(req) returns both for a request. Raw IP addresses and full User-Agents are never written to the database or the logs.',
  'src/models/Session.js':
    'Data-access layer for login sessions, which are what the "devices" list shows. createSession adds a session and evicts the oldest ones beyond 10 per user (returning the evicted ids so their sockets can be cut). findActiveSession confirms a session is neither revoked nor expired. touchSession updates last-seen at most once a minute to avoid a database write on every request. listSessions, revokeSession, revokeOthers and revokeAll back the session-management endpoints. Every query is parameterised and scoped to the owning user.',
  'src/models/AuthEvent.js':
    'The security audit log and brute-force lockout. logEvent records register, login success/failure, logout, key rotation and similar events with a keyed network hash and a device label (never a raw IP); it swallows its own errors so a logging problem can never break login. lockoutSeconds counts recent failures per username+network (limit 5) and per username overall (limit 25) over a 15-minute window and returns how many seconds remain until the limit lifts, which the login route returns as Retry-After. recentEvents feeds the account security timeline.',
  'src/models/Contact.js':
    'Data-access layer for each user\'s contact list. listContacts returns a user\'s contacts; addContact runs in a transaction under a per-user advisory lock, so parallel requests cannot exceed the 500-contact cap, and refuses to add someone you have blocked; removeContact deletes one. Contacts are one-directional records; presence is shown only between MUTUAL contacts (both added each other), which models/Presence.js enforces. Every query is parameterised.',
  'src/models/Block.js':
    'Data-access layer for blocking. blockUser adds a block (capped at 500 per user, under an advisory lock) and, in the same transaction, removes the target from the blocker\'s contacts; unblockUser reverses it; listBlocks returns a user\'s blocks. getBlockState tells the message handlers whether I blocked someone or they blocked me. A blocked user\'s messages are silently dropped while the sender still sees success, so nobody can learn they were blocked. Every query is parameterised.',
  'src/routes/sessions.js':
    'HTTP API under /api/sessions for managing logged-in devices and reviewing account security. GET / lists active sessions and marks the current one; GET /events returns the last 50 security events (logins, logouts, key changes); DELETE /:id revokes one session (and logs this browser out if it is the current one); DELETE / revokes every OTHER session. Revoking disconnects that device\'s live sockets immediately. Session required; rate limited; ids validated as UUIDs.',
  'src/routes/contacts.js':
    'HTTP API under /api/contacts. GET / lists the logged-in user\'s contacts, POST / adds one ({ userId }; you cannot add yourself, someone you blocked, or exceed 500 contacts), DELETE /:id removes one. Adding a contact is private: the other person is not told, and presence is visible only when both people added each other. The body is validated with a strict zod schema; ids are UUIDs; session required and rate limited.',
  'src/routes/blocks.js':
    'HTTP API under /api/blocks. GET / lists blocked users, POST / blocks one ({ userId }; this also removes them from your contacts), DELETE /:id unblocks. Blocked users cannot message you, cannot see your presence, typing or read receipts, and do not find you in search - and they are never told. The body is validated with a strict zod schema; ids are UUIDs; session required and rate limited.',
  'src/routes/messages.js':
    'HTTP API under /api/messages for 1-to-1 chats. GET / lists conversations; GET /:userId returns up to 100 messages of one conversation (ciphertext only; expired and burned messages are excluded); DELETE /item/:id lets the SENDER unsend one message for both people; DELETE /:userId clears a whole conversation for BOTH people. Sending is done over the realtime socket (socket/handlers/messages.js), not here. Realtime events keep every device in sync. Session required; ids validated as UUIDs.',
};

const LINE = '// =============================================================================';
const PREFIX = '// Purpose : ';
const INDENT = '//           ';

function wrap(text, width = 64) {
  const lines = [];
  let line = '';
  for (const word of text.split(' ')) {
    if ((line + ' ' + word).trim().length > width) {
      lines.push(line);
      line = word;
    } else {
      line = (line + ' ' + word).trim();
    }
  }
  if (line) lines.push(line);
  return lines;
}

const buildHeader = (file, purpose) =>
  [
    LINE,
    '// Project : Enoclave - private, end-to-end encrypted web chat',
    `// File    : server/${file}`,
    ...wrap(purpose).map((l, i) => (i === 0 ? PREFIX : INDENT) + l),
    LINE,
  ].join('\n');

for (const [file, purpose] of Object.entries(HEADERS)) {
  if (!existsSync(file)) {
    console.log(`MISSING  ${file}`);
    continue;
  }
  const text = readFileSync(file, 'utf8');
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const lines = text.split(/\r?\n/);
  if (lines[0].startsWith('// ====')) {
    console.log(`ok       ${file} (already upgraded)`);
    continue;
  }
  if (!lines[0].startsWith('// File:')) {
    console.log(`SKIPPED  ${file} (unexpected first line)`);
    continue;
  }
  let i = 0;
  while (i < lines.length && lines[i].startsWith('//')) i += 1;
  const next = buildHeader(file, purpose).split('\n').concat(lines.slice(i)).join(eol);
  writeFileSync(file, next);
  console.log(`UPGRADED ${file}`);
}

// File: server/scripts/upgrade-headers.mjs
// End of file