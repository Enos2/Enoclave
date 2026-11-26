// File: server/src/config/env.js
// Purpose: Load and validate environment variables; fail fast if any are missing or weak.
import 'dotenv/config';

const required = ['DATABASE_URL', 'JWT_SECRET', 'CLIENT_ORIGIN'];
for (const key of required) {
  if (!process.env[key]) {
    console.error(`[env] Missing required variable: ${key}`);
    process.exit(1);
  }
}
if (process.env.JWT_SECRET.length < 32) {
  console.error('[env] JWT_SECRET must be at least 32 characters.');
  process.exit(1);
}

export const env = Object.freeze({
  port: Number(process.env.PORT) || 5000,
  databaseUrl: process.env.DATABASE_URL,
  jwtSecret: process.env.JWT_SECRET,
  clientOrigin: process.env.CLIENT_ORIGIN,
  isProd: process.env.NODE_ENV === 'production',
});

// File: server/src/config/env.js
// End of file