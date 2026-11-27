// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/socket/handlers/receipts.js
// Purpose : Realtime read receipts (auto-loaded by socket/index.js). When a
//           user has DISPLAYED messages, the client emits 'receipt:read' {
//           peerId, upTo } for a direct chat or 'receipt:group_read' { groupId,
//           upTo }, where upTo is the id of the newest message now read. The
//           server stores one "read up to" cursor (the time is taken from the
//           message itself, never from the client, and only if the message
//           truly belongs to this conversation and is visible to the reader).
//           Interested parties then receive 'receipt:read' { by, upTo, readAt }
//           (direct) or 'receipt:group_read' { groupId, by, upTo, readAt }
//           (group). Privacy: if the reader has receipts off nothing is stored
//           or sent; the other side is told only if THEY have receipts on too
//           (reciprocal) and, for direct chats, no block exists. The handler
//           always answers { ok:true } so it cannot be used to probe message
//           ids, settings or blocks. Payloads are validated with strict zod
//           schemas. Uses the shared per-socket rate limiter.
// =============================================================================
import { z } from 'zod';
import { markDirectRead, markGroupCursor, groupReceiptAudience } from '../../models/Signal.js';
import { isUuid } from '../../utils/serialize.js';
import { emitToUsers } from '../../utils/realtime.js';

const uuid = z.string().refine(isUuid);
const directSchema = z.object({ peerId: uuid, upTo: uuid }).strict();
const groupSchema = z.object({ groupId: uuid, upTo: uuid }).strict();

export default function register({ io, socket, allowed }) {
  const me = socket.data.user.id;

  socket.on('receipt:read', async (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    try {
      if (!allowed(socket)) return reply({ ok: false, error: 'Slow down' });
      const parsed = directSchema.safeParse(payload);
      if (!parsed.success) return reply({ ok: false, error: 'Invalid request' });
      const { peerId, upTo } = parsed.data;

      const r = peerId === me ? null : await markDirectRead(me, peerId, upTo);
      if (r?.notify) {
        io.to(`user:${peerId}`).emit('receipt:read', { by: me, upTo, readAt: r.lastReadAt });
      }
      reply({ ok: true });
    } catch (err) {
      console.error('[socket] receipt:read failed:', err.message);
      reply({ ok: false, error: 'Server error' });
    }
  });

  socket.on('receipt:group_read', async (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    try {
      if (!allowed(socket)) return reply({ ok: false, error: 'Slow down' });
      const parsed = groupSchema.safeParse(payload);
      if (!parsed.success) return reply({ ok: false, error: 'Invalid request' });
      const { groupId, upTo } = parsed.data;

      const readAt = await markGroupCursor(groupId, me, upTo);
      if (readAt) {
        emitToUsers(io, await groupReceiptAudience(groupId, me), 'receipt:group_read', {
          groupId,
          by: me,
          upTo,
          readAt,
        });
      }
      reply({ ok: true });
    } catch (err) {
      console.error('[socket] receipt:group_read failed:', err.message);
      reply({ ok: false, error: 'Server error' });
    }
  });
}

// File: server/src/socket/handlers/receipts.js
// End of file