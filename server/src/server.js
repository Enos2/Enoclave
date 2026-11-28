// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/server.js
// Purpose : Application entry point, final. Builds the Express app with its
//           defences in order: request id + JSON access log (no IPs, no query
//           strings), Helmet (strict CSP for a JSON API, no framing, HSTS),
//           CORS locked to one origin, a 50 KB JSON body limit, cookie parsing,
//           the Origin check on state-changing requests and a global rate
//           limit. GET /api/health (liveness) and GET /api/ready (readiness:
//           checks the database; returns 503 while shutting down) are mounted
//           before the rate limiter so load balancers are never throttled.
//           Startup order: connect PostgreSQL, apply migrations, auto-mount
//           every file in ./routes, start the sweeper and every job in ./jobs,
//           attach Socket.IO (which auto-loads ./socket/handlers). Production
//           behaviour: HTTP timeouts against slow-client attacks, a logged
//           crash on uncaught exceptions (state is unknown, so the process
//           exits and the supervisor restarts it), and graceful shutdown on
//           SIGINT/SIGTERM (stop accepting, drain connections, close the
//           database pool, hard-exit after 15 seconds). New features never edit
//           this file: add a migration, a route, a socket handler or a job.
// =============================================================================
import http from 'node:http';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { env } from './config/env.js';
import { connectDB, checkDb, startExpirySweeper, closePool } from './config/db.js';
import { migrate } from './config/migrate.js';
import { logger } from './utils/logger.js';
import { requestLog } from './middleware/requestLog.js';
import { notFound, errorHandler } from './middleware/errors.js';
import { originGuard } from './middleware/security.js';
import { mountRoutes } from './utils/loadRoutes.js';
import { startJobs } from './utils/loadJobs.js';
import { initSocket } from './socket/index.js';

process.on('unhandledRejection', (reason) => logger.error('unhandled rejection', { err: reason }));
process.on('uncaughtException', (err) => {
  logger.error('uncaught exception, exiting', { err });
  setTimeout(() => process.exit(1), 100).unref();
});

let shuttingDown = false;

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', env.trustProxy);

app.use(requestLog);
app.use(
  helmet({
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
    crossOriginResourcePolicy: { policy: 'same-site' },
  })
);
app.use(cors({ origin: env.clientOrigin, credentials: true, methods: ['GET', 'POST', 'PUT', 'DELETE'] }));

app.get('/api/health', (req, res) => res.json({ ok: true }));
app.get('/api/ready', async (req, res) => {
  if (shuttingDown) return res.status(503).json({ ok: false });
  try {
    await checkDb();
    return res.json({ ok: true });
  } catch {
    return res.status(503).json({ ok: false });
  }
});

app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
app.use(originGuard);
app.use(
  '/api',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: env.testMode ? 6000 : 600,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
  })
);

await connectDB();
await migrate();
await mountRoutes(app);

app.use(notFound);
app.use(errorHandler);

startExpirySweeper();

const server = http.createServer(app);
server.headersTimeout = 20_000;
server.requestTimeout = 5 * 60_000; // large encrypted uploads need time; slow-loris still bounded
server.keepAliveTimeout = 65_000; // longer than the usual 60 s proxy idle timeout

const io = await initSocket(server);
app.set('io', io);
await startJobs({ io });

server.listen(env.port, () => logger.info('server listening', { port: env.port, env: env.isProd ? 'production' : 'development' }));

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info('shutting down', { signal });
  setTimeout(() => process.exit(1), 15_000).unref();
  io.close(async () => {
    try {
      await closePool();
    } finally {
      process.exit(0);
    }
  });
  server.closeIdleConnections?.();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// File: server/src/server.js
// End of file