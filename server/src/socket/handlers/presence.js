// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/socket/handlers/presence.js
// Purpose : Realtime presence (auto-loaded by socket/index.js). When a socket
//           connects, the user is marked online; if it is their FIRST device
//           and they were not just refreshing the page, the peers allowed to
//           see them get 'presence:update' { userId, online, status }. The
//           connecting socket receives 'presence:snapshot' { peers: [{ userId,
//           online, status }] } for the people it may see. Clients should
//           register their listeners BEFORE connecting, and can emit
//           'presence:sync' at any time (for example after adding a contact) to
//           get a fresh snapshot. When the LAST device disconnects, a 5-second
//           grace period runs before peers are told the user is offline, so a
//           page reload does not flicker. Who may see whom (mutual contacts,
//           presence enabled on both sides, no blocks) is decided in
//           models/Presence.js. Nothing is stored: there is no "last seen".
// =============================================================================
import {
  trackConnect,
  trackDisconnect,
  cancelOffline,
  scheduleOffline,
  isOnline,
  announce,
  snapshotFor,
} from '../../utils/presenceTracker.js';

export default function register({ io, socket, allowed }) {
  const me = socket.data.user.id;

  // Tracking happens synchronously so a quick disconnect cannot be missed.
  const first = trackConnect(me, socket.id);
  const wasPending = cancelOffline(me);

  (async () => {
    try {
      if (first && !wasPending) await announce(io, me, true);
      socket.emit('presence:snapshot', await snapshotFor(me));
    } catch (err) {
      console.error('[socket] presence connect failed:', err.message);
    }
  })();

  socket.on('presence:sync', async (_payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    try {
      if (!allowed(socket)) return reply({ ok: false, error: 'Slow down' });
      socket.emit('presence:snapshot', await snapshotFor(me));
      reply({ ok: true });
    } catch (err) {
      console.error('[socket] presence:sync failed:', err.message);
      reply({ ok: false, error: 'Server error' });
    }
  });

  socket.on('disconnect', () => {
    if (!trackDisconnect(me, socket.id)) return;
    scheduleOffline(me, async () => {
      if (isOnline(me)) return;
      try {
        await announce(io, me, false);
      } catch (err) {
        console.error('[socket] presence offline failed:', err.message);
      }
    });
  });
}

// File: server/src/socket/handlers/presence.js
// End of file