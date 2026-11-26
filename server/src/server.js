// File: server/src/server.js
// Purpose: Entry point. Builds the hardened Express app, connects PostgreSQL and starts HTTP + Socket.IO.
import http from 'node:http';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { env } from './config/env.js';
import { connectDB, startExpirySweeper } from './config/db.js';
import { migrate } from './config/migrate.js';
import { originGuard } from './middleware/security.js';
import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import messageRoutes from './routes/messages.js';
import sessionRoutes from './routes/sessions.js';
import contactRoutes from './routes/contacts.js';
import blockRoutes from './routes/blocks.js';
import { initSocket } from './socket/index.js';

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
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/sessions', sessionRoutes);
app.use('/api/contacts', contactRoutes);
app.use('/api/blocks', blockRoutes);

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[error]', err.message);
  const status = err.status && err.status < 500 ? err.status : 500;
  res.status(status).json({ error: status === 500 ? 'Server error' : 'Bad request' });
});

await connectDB();
await migrate();
startExpirySweeper();

const server = http.createServer(app);
app.set('io', initSocket(server));
server.listen(env.port, () => console.log(`[server] listening on port ${env.port}`));

// File: server/src/server.js
// End of file