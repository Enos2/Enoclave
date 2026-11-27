// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/socket/index.js
// Purpose : The realtime core (Socket.IO). A connection is accepted only if its
//           Origin matches the configured client AND its httpOnly cookie holds
//           a valid, non-revoked session. Each socket joins a per-user room
//           (shared by all of that user's devices) and a per-session room (so
//           one device can be disconnected when its session is revoked).
//           It also owns the per-socket rate limiter (30 events per 10
//           seconds), shared by every handler.
//           Features do NOT live here. Every file in ./handlers is loaded
//           automatically at startup and must export a default function
//           register({ io, socket, allowed }) that attaches its own events.
//           To add a realtime feature, add a file to ./handlers - this file
//           never needs editing again.
// =============================================================================
import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Server } from 'socket.io';
import { env } from '../config/env.js';
import { authenticateToken } from '../middleware/auth.js';
import { COOKIE_NAME } from '../utils/token.js';

const HANDLERS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'handlers');

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

// Sliding-window limiter: at most 30 events per socket in any 10 seconds.
function allowed(socket) {
  const now = Date.now();
  const win = (socket.data.window ??= []);
  while (win.length && now - win[0] > 10_000) win.shift();
  if (win.length >= 30) return false;
  win.push(now);
  return true;
}

export async function initSocket(httpServer) {
  const io = new Server(httpServer, {
    cors: { origin: env.clientOrigin, credentials: true },
    maxHttpBufferSize: 100_000,
  });

  const handlers = [];
  const files = readdirSync(HANDLERS_DIR)
    .filter((f) => /^[a-zA-Z0-9_-]+\.js$/.test(f))
    .sort();
  for (const file of files) {
    const mod = await import(pathToFileURL(path.join(HANDLERS_DIR, file)).href);
    if (typeof mod.default === 'function') handlers.push(mod.default);
  }

  io.use(async (socket, next) => {
    if (socket.handshake.headers.origin !== env.clientOrigin) return next(new Error('forbidden'));
    const cookies = parseCookies(socket.handshake.headers.cookie);
    const user = await authenticateToken(cookies[COOKIE_NAME]);
    if (!user) return next(new Error('unauthorized'));
    socket.data.user = user;
    next();
  });

  io.on('connection', (socket) => {
    socket.join(`user:${socket.data.user.id}`);
    socket.join(`session:${socket.data.user.session_id}`);
    for (const register of handlers) register({ io, socket, allowed });
  });

  console.log(`[socket] ${handlers.length} handler modules loaded`);
  return io;
}

// File: server/src/socket/index.js
// End of file