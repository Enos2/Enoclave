// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/server.js
// Purpose : Application entry point, final. Builds the Express app with its
//           security layers in order: Helmet headers, CORS locked to one
//           origin, a 50 KB JSON body limit, cookie parsing, an Origin check on
//           every state-changing request, and a global rate limit. Then it
//           connects PostgreSQL, applies pending migrations, auto-mounts every
//           file in ./routes (see utils/loadRoutes.js), adds 404 and error
//           handlers that never leak internals, starts the background sweeper
//           and every job in ./jobs (see utils/loadJobs.js), and attaches
//           Socket.IO, which auto-loads every file in ./socket/handlers.
//           Also handles production concerns: logs unhandled errors instead of
//           dying silently, and shuts down gracefully on SIGINT/SIGTERM
//           (closes connections, drains the database pool). New features never
//           need an edit here: add a migration, a route file, a socket handler
//           or a job file and it is picked up automatically.
// =============================================================================
import http from 'node:http';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { env } from './config/env.js';
import { connectDB, startExpirySweeper, pool } from './config/db.js';
import { migrate } from './config/migrate.js';
import { originGuard } from './middleware/security.js';
import { mountRoutes } from './utils/loadRoutes.js';
import { startJobs } from './utils/loadJobs.js';
import { initSocket } from './socket/index.js';

process.on('unhandledRejection', (reason) => console.error('[process] unhandled rejection:', reason));
process.on('uncaughtException', (err) => console.error('[process] uncaught exception:', err));

const app = express();
app.disable('x-powered-by');
if (env.isProd) app.set('trust proxy', 1);

app.use(helmet());
app.use(
  cors({ origin: env.clientOrigin, credentials: true, methods: ['GET', 'POST', 'PUT', 'DELETE'] })
);
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
app.use(originGuard);
app.use(
  '/api',
  rateLimit({ windowMs: 15 * 60 * 1000, limit: 600, standardHeaders: 'draft-7', legacyHeaders: false })
);

app.get('/api/health', (req, res) => res.json({ ok: true }));

await connectDB();
await migrate();
await mountRoutes(app);

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[error]', err.message);
  const status = err.status && err.status < 500 ? err.status : 500;
  res.status(status).json({ error: status === 500 ? 'Server error' : 'Bad request' });
});

startExpirySweeper();

const server = http.createServer(app);
const io = await initSocket(server);
app.set('io', io);
await startJobs({ io });

server.listen(env.port, () => console.log(`[server] listening on port ${env.port}`));

function shutdown(signal) {
  console.log(`[server] ${signal} received, shutting down`);
  setTimeout(() => process.exit(1), 10_000).unref();
  io.close(() => pool.end().finally(() => process.exit(0)));
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// File: server/src/server.js
// End of file