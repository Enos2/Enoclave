// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/utils/logger.js
// Purpose : The server's single logger. Writes one JSON object per line (time,
//           level, message and fields) to stdout, or to stderr for warnings
//           and errors, which is what Docker, systemd and every hosting
//           platform's log collector expect. Respects LOG_LEVEL (debug, info,
//           warn, error). Pass an Error as the "err" field and it is converted
//           to its message (plus the stack trace outside production). Privacy
//           rule for everyone who logs: never put passwords, tokens, message
//           contents, key material, IP addresses or URLs with query strings
//           into a log field. Use it as: logger.info('what happened', { id }).
// =============================================================================
import { env } from '../config/env.js';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const threshold = LEVELS[env.logLevel] ?? LEVELS.info;

function toFields(fields) {
  const out = { ...fields };
  if (out.err !== undefined) {
    out.error = out.err instanceof Error ? out.err.message : String(out.err);
    if (out.err instanceof Error && !env.isProd) out.stack = out.err.stack;
    delete out.err;
  }
  return out;
}

function write(level, msg, fields = {}) {
  if (LEVELS[level] < threshold) return;
  const line = JSON.stringify({ time: new Date().toISOString(), level, msg, ...toFields(fields) });
  (LEVELS[level] >= LEVELS.warn ? process.stderr : process.stdout).write(`${line}\n`);
}

export const logger = {
  debug: (msg, fields) => write('debug', msg, fields),
  info: (msg, fields) => write('info', msg, fields),
  warn: (msg, fields) => write('warn', msg, fields),
  error: (msg, fields) => write('error', msg, fields),
};

// File: server/src/utils/logger.js
// End of file