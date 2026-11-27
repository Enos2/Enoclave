// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/socket/handlers/typing.js
// Purpose : Realtime typing indicators (auto-loaded by socket/index.js). The
//           client emits 'typing:set' { to, typing } for a direct chat or
//           { groupId, typing } for a group (exactly one target, validated with
//           a strict zod schema). Allowed recipients get 'typing:update' { from,
//           typing } or { from, groupId, typing }. Direct signals pass only if
//           the pair has exchanged messages, both have typing enabled and
//           neither has blocked the other; group signals go to the other
//           members who have typing enabled, and only if the sender is a member
//           with typing enabled (all enforced in models/Signal.js). The handler
//           ALWAYS answers { ok:true } and silently drops anything not
//           permitted, so it cannot be used to learn about blocks, privacy
//           settings or group membership. It has its own limit of 10 events per
//           10 seconds per socket, so typing cannot eat the message budget.
//           Nothing is stored. Clients should send "typing: true" at most every
//           few seconds, send "typing: false" when done, and hide the indicator
//           after about 6 seconds without an update.
// =============================================================================
import { z } from 'zod';
import { canType, groupTypingAudience } from '../../models/Signal.js';
import { isUuid } from '../../utils/serialize.js';
import { emitToUsers } from '../../utils/realtime.js';

const uuid = z.string().refine(isUuid);
const typingSchema = z
  .object({ to: uuid.optional(), groupId: uuid.optional(), typing: z.boolean() })
  .strict()
  .refine((b) => Boolean(b.to) !== Boolean(b.groupId));

export default function register({ io, socket }) {
  const me = socket.data.user.id;
  const recent = [];

  const withinLimit = () => {
    const now = Date.now();
    while (recent.length && now - recent[0] > 10_000) recent.shift();
    if (recent.length >= 10) return false;
    recent.push(now);
    return true;
  };

  socket.on('typing:set', async (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    try {
      if (!withinLimit()) return reply({ ok: false, error: 'Slow down' });
      const parsed = typingSchema.safeParse(payload);
      if (!parsed.success) return reply({ ok: false, error: 'Invalid request' });
      const { to, groupId, typing } = parsed.data;

      if (to) {
        if (to !== me && (await canType(me, to))) {
          io.to(`user:${to}`).emit('typing:update', { from: me, typing });
        }
      } else {
        const audience = await groupTypingAudience(groupId, me);
        emitToUsers(io, audience, 'typing:update', { from: me, groupId, typing });
      }
      reply({ ok: true });
    } catch (err) {
      console.error('[socket] typing:set failed:', err.message);
      reply({ ok: false, error: 'Server error' });
    }
  });
}

// File: server/src/socket/handlers/typing.js
// End of file