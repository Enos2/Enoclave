// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/utils/presenceTracker.js
// Purpose : Keeps track of who is online and tells the right people. It holds,
//           in memory, which sockets belong to which user (a user with several
//           tabs or devices counts as online until the LAST one disconnects),
//           plus a 5-second grace timer so a page refresh does not flash
//           "offline". It never records when anyone was last online: presence
//           is a live fact and nothing is stored. Helpers: snapshotFor (the
//           online state of a user's visible peers), announce (broadcast
//           online/offline to the peers allowed to see this user) and
//           refreshPresence (re-compute after a privacy change: peers who may
//           no longer see you are told you went offline; the user gets a fresh
//           snapshot). Who may see whom is decided by models/Presence.js
//           (mutual contacts only, both with presence enabled, no blocks).
//           Single-process by design; running several server instances would
//           need a shared store such as Redis.
// =============================================================================
import { getSettings } from '../models/Settings.js';
import { visiblePeers } from '../models/Presence.js';
import { emitToUsers } from './realtime.js';

const sockets = new Map(); // userId -> Set of socket ids
const timers = new Map(); // userId -> pending "offline" timer

export const isOnline = (userId) => (sockets.get(userId)?.size ?? 0) > 0;

// Returns true when this is the user's first connection (they just came online).
export function trackConnect(userId, socketId) {
  let set = sockets.get(userId);
  if (!set) {
    set = new Set();
    sockets.set(userId, set);
  }
  const first = set.size === 0;
  set.add(socketId);
  return first;
}

// Returns true when that was the user's last connection.
export function trackDisconnect(userId, socketId) {
  const set = sockets.get(userId);
  if (!set) return false;
  set.delete(socketId);
  if (set.size === 0) {
    sockets.delete(userId);
    return true;
  }
  return false;
}

// Returns true if an offline timer was pending (the user reconnected inside the grace period).
export function cancelOffline(userId) {
  const t = timers.get(userId);
  if (!t) return false;
  clearTimeout(t);
  timers.delete(userId);
  return true;
}

export function scheduleOffline(userId, fn, ms = 5000) {
  cancelOffline(userId);
  const t = setTimeout(() => {
    timers.delete(userId);
    fn();
  }, ms);
  t.unref();
  timers.set(userId, t);
}

export async function snapshotFor(userId) {
  const peers = await visiblePeers(userId);
  return {
    peers: peers.map((p) => {
      const on = isOnline(p.id);
      return { userId: p.id, online: on, status: on ? p.status : null };
    }),
  };
}

export async function announce(io, userId, online) {
  const [me, peers] = await Promise.all([getSettings(userId), visiblePeers(userId)]);
  emitToUsers(io, peers.map((p) => p.id), 'presence:update', {
    userId,
    online,
    status: online ? me.status : null,
  });
}

// previousPeerIds: who could see this user BEFORE the settings change.
export async function refreshPresence(io, userId, previousPeerIds) {
  const peers = await visiblePeers(userId);
  const now = new Set(peers.map((p) => p.id));
  emitToUsers(
    io,
    previousPeerIds.filter((id) => !now.has(id)),
    'presence:update',
    { userId, online: false, status: null }
  );
  if (isOnline(userId)) {
    const me = await getSettings(userId);
    emitToUsers(io, [...now], 'presence:update', { userId, online: true, status: me.status });
  }
  io.to(`user:${userId}`).emit('presence:snapshot', await snapshotFor(userId));
}

// File: server/src/utils/presenceTracker.js
// End of file