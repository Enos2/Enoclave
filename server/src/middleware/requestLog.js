// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/middleware/requestLog.js
// Purpose : The first middleware in the chain. Gives every request a random
//           UUID (req.id), returns it to the client in the X-Request-Id header
//           (so a user can quote it in a bug report and you can find that exact
//           request in the logs), and when the response finishes writes one
//           JSON access-log line: request id, method, path, status, duration in
//           ms and the user id if the request was authenticated. Privacy: the
//           path is logged WITHOUT its query string (signed download links
//           carry a signature there), and no IP address, cookie, header or body
//           is ever logged. Status 5xx logs at error level, 4xx at warn,
//           everything else at info. Health and readiness probes are not logged
//           so they do not drown the real traffic.
// =============================================================================
import crypto from 'node:crypto';
import { logger } from '../utils/logger.js';

const QUIET = new Set(['/api/health', '/api/ready']);

export function requestLog(req, res, next) {
  req.id = crypto.randomUUID();
  res.set('X-Request-Id', req.id);
  const path = req.originalUrl.split('?')[0];
  const started = process.hrtime.bigint();

  res.on('finish', () => {
    if (QUIET.has(path)) return;
    const ms = Math.round(Number(process.hrtime.bigint() - started) / 1e6);
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
    logger[level]('request', { id: req.id, method: req.method, path, status: res.statusCode, ms, user: req.user?.id });
  });
  next();
}

// File: server/src/middleware/requestLog.js
// End of file