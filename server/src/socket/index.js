// File: server/src/socket/index.js
// Purpose: Authenticated realtime messaging over Socket.IO with origin check, validation and per-socket rate limiting.
import { Server } from 'socket.io';
import { z } from 'zod';
import { env } from '../config/env.js';
import { authenticateToken } from '../middleware/auth.js';
import { COOKIE_NAME } from '../utils/token.js';
import { userExists } from '../models/User.js';
import { createMessage } from '../models/Message.js';
import { isUuid, serializeMessage } from '../utils/serialize.js';

const base64 = /^[A-Za-z0-9+/=]+$/;
const sendSchema = z
  .object({
    to: z.string().refine(isUuid),
    ciphertext: z.string().min(1).max(20000).regex(base64),
    iv: z.string().min(16).max(32).regex(base64),
    ttlSeconds: z.number().int().min(5).max(604800).optional(),
  })
  .strict();

// Minimal cookie parser: no external dependency, no prototype pollution, first value wins.
function parseCookies(header = '') {
  const out = Object.create(null);
  if (typeof header !== 'string' || header.length > 4096) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    const name = part.slice(0, i).trim();
    let value = part.slice(i + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    try {
      value = decodeURIComponent(value);
    } catch {
      /* keep the raw value if it is not valid percent-encoding */
    }
    if (!(name in out)) out[name] = value;
  }
  return out;
}

function allowed(socket) {
  const now = Date.now();
  const win = (socket.data.window ??= []);
  while (win.length && now - win[0] > 10_000) win.shift();
  if (win.length >= 30) return false;
  win.push(now);
  return true;
}

export function initSocket(httpServer) {
  const io = new Server(httpServer, {
    cors: { origin: env.clientOrigin, credentials: true },
    maxHttpBufferSize: 100_000,
  });

  io.use(async (socket, next) => {
    if (socket.handshake.headers.origin !== env.clientOrigin) return next(new Error('forbidden'));
    const cookies = parseCookies(socket.handshake.headers.cookie);
    const user = await authenticateToken(cookies[COOKIE_NAME]);
    if (!user) return next(new Error('unauthorized'));
    socket.data.user = user;
    next();
  });

  io.on('connection', (socket) => {
    const me = socket.data.user.id;
    socket.join(`user:${me}`);

    socket.on('message:send', async (payload, ack) => {
      const reply = typeof ack === 'function' ? ack : () => {};
      try {
        if (!allowed(socket)) return reply({ ok: false, error: 'Slow down' });
        const parsed = sendSchema.safeParse(payload);
        if (!parsed.success) return reply({ ok: false, error: 'Invalid message' });
        const { to, ciphertext, iv, ttlSeconds } = parsed.data;
        if (to === me) return reply({ ok: false, error: 'Invalid recipient' });
        if (!(await userExists(to))) return reply({ ok: false, error: 'Invalid recipient' });

        const msg = await createMessage({ from: me, to, ciphertext, iv, ttlSeconds });
        io.to(`user:${me}`).to(`user:${to}`).emit('message:new', serializeMessage(msg));
        reply({ ok: true });
      } catch (err) {
        console.error('[socket] send failed:', err.message);
        reply({ ok: false, error: 'Server error' });
      }
    });
  });

  return io;
}

// File: server/src/socket/index.js
// End of file