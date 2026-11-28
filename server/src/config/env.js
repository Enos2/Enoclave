// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/config/env.js
// Purpose : Loads and strictly validates every environment variable BEFORE the
//           server does anything else; any problem stops the process with a
//           clear message instead of failing later in a confusing way.
//           Required: DATABASE_URL (a PostgreSQL connection string), JWT_SECRET
//           (at least 32 characters and not a leftover placeholder) and
//           CLIENT_ORIGIN (the exact browser origin allowed to call the API,
//           for example https://app.example.com - no path, no trailing slash,
//           and https in production).
//           Optional: PORT (default 5000), NODE_ENV, TRUST_PROXY (how many
//           reverse proxies sit in front, 0-5; default 1 in production, else 0),
//           LOG_LEVEL (debug, info, warn or error; default info), UPLOAD_DIR
//           (read by utils/storage.js) and TEST_MODE=1, which raises rate
//           limits so the automated tests can run repeatedly. TEST_MODE is
//           refused in production. The exported env object is frozen, so no
//           other code can change configuration at runtime. This file is final.
// =============================================================================
import 'dotenv/config';

const fail = (message) => {
  console.error(`[env] ${message}`);
  process.exit(1);
};

for (const key of ['DATABASE_URL', 'JWT_SECRET', 'CLIENT_ORIGIN']) {
  if (!process.env[key]) fail(`Missing required variable: ${key}`);
}

const isProd = process.env.NODE_ENV === 'production';
const testMode = process.env.TEST_MODE === '1';
if (testMode && isProd) fail('TEST_MODE must never be enabled in production.');

if (!/^postgres(ql)?:\/\//.test(process.env.DATABASE_URL)) {
  fail('DATABASE_URL must be a PostgreSQL connection string (postgresql://...).');
}
if (process.env.JWT_SECRET.length < 32 || /paste|replace/i.test(process.env.JWT_SECRET)) {
  fail('JWT_SECRET must be a random string of at least 32 characters.');
}

let clientOrigin = '';
try {
  const u = new URL(process.env.CLIENT_ORIGIN);
  if (!['http:', 'https:'].includes(u.protocol) || u.origin !== process.env.CLIENT_ORIGIN) throw new Error('bad origin');
  if (isProd && u.protocol !== 'https:') fail('CLIENT_ORIGIN must use https in production.');
  clientOrigin = u.origin;
} catch {
  fail('CLIENT_ORIGIN must be a bare origin such as https://app.example.com (no path, no trailing slash).');
}

const trustProxy = Number.parseInt(process.env.TRUST_PROXY ?? (isProd ? '1' : '0'), 10);
if (!Number.isInteger(trustProxy) || trustProxy < 0 || trustProxy > 5) fail('TRUST_PROXY must be a number from 0 to 5.');

const logLevel = ['debug', 'info', 'warn', 'error'].includes(process.env.LOG_LEVEL) ? process.env.LOG_LEVEL : 'info';

if (isProd && !/sslmode=/.test(process.env.DATABASE_URL)) {
  console.warn('[env] DATABASE_URL has no sslmode setting; use sslmode=verify-full for Neon.');
}

export const env = Object.freeze({
  port: Number(process.env.PORT) || 5000,
  databaseUrl: process.env.DATABASE_URL,
  jwtSecret: process.env.JWT_SECRET,
  clientOrigin,
  isProd,
  testMode,
  trustProxy,
  logLevel,
});

// File: server/src/config/env.js
// End of file