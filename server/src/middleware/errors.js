// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/middleware/errors.js
// Purpose : The last two middlewares in the chain. notFound answers any
//           unmatched URL with a JSON 404. errorHandler turns every error into
//           a safe JSON response: an oversized body becomes 413, malformed JSON
//           becomes 400 (instead of the default HTML stack trace), other 4xx
//           errors keep their status with a generic message, and anything else
//           becomes a 500 that says only "Server error" plus the request id.
//           Error details (message, stack outside production) go to the log
//           only, never to the client, so internals cannot leak.
// =============================================================================
import { logger } from '../utils/logger.js';

export function notFound(req, res) {
  res.status(404).json({ error: 'Not found' });
}

// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, next) {
  if (res.headersSent) return res.destroy();
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large' });
  if (err.type === 'entity.parse.failed' || err instanceof SyntaxError) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }
  if (err.status && err.status >= 400 && err.status < 500) return res.status(err.status).json({ error: 'Bad request' });
  logger.error('unhandled error', { id: req.id, path: req.originalUrl.split('?')[0], err });
  return res.status(500).json({ error: 'Server error', requestId: req.id });
}

// File: server/src/middleware/errors.js
// End of file