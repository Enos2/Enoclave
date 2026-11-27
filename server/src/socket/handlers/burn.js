// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/socket/handlers/burn.js
// Purpose : Realtime handler for burn-on-read (auto-loaded by socket/index.js).
//           The client emits 'message:read' { id } when it has DISPLAYED a
//           direct message, or 'group:read' { groupId, id } for a group
//           message. For messages that have a burn setting, this starts the
//           countdown: direct messages start when the recipient reads (the
//           sender cannot start it); group messages start when every member who
//           could see the message has read it. When a countdown starts, both
//           sides (or all members) receive 'message:burning' or 'group:burning'
//           with { id, expiresAt } so the interface can show a timer. The
//           handler always answers { ok:true } whatever happened, so it cannot
//           be used to find out whether a message id exists. Messages WITHOUT
//           a burn setting are ignored here: nothing about read state is stored
//           for them (general read receipts, with privacy toggles, arrive
//           separately on Day 4). Payloads are validated with zod (.strict()).
// =============================================================================
import { z } from 'zod';
import { markBurn } from '../../models/Message.js';
import { markGroupRead } from '../../models/GroupMessage.js';
import { listMemberIds } from '../../models/Group.js';
import { isUuid } from '../../utils/serialize.js';
import { emitToUsers } from '../../utils/realtime.js';

const uuid = z.string().refine(isUuid);
const readSchema = z.object({ id: uuid }).strict();
const groupReadSchema = z.object({ groupId: uuid, id: uuid }).strict();

export default function register({ io, socket, allowed }) {
  const me = socket.data.user.id;

  socket.on('message:read', async (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    try {
      if (!allowed(socket)) return reply({ ok: false, error: 'Slow down' });
      const parsed = readSchema.safeParse(payload);
      if (!parsed.success) return reply({ ok: false, error: 'Invalid request' });

      const started = await markBurn(parsed.data.id, me);
      if (started) {
        io.to(`user:${started.from_id}`)
          .to(`user:${started.to_id}`)
          .emit('message:burning', {
            id: started.id,
            from: started.from_id,
            to: started.to_id,
            expiresAt: started.expires_at,
          });
      }
      reply({ ok: true });
    } catch (err) {
      console.error('[socket] message:read failed:', err.message);
      reply({ ok: false, error: 'Server error' });
    }
  });

  socket.on('group:read', async (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    try {
      if (!allowed(socket)) return reply({ ok: false, error: 'Slow down' });
      const parsed = groupReadSchema.safeParse(payload);
      if (!parsed.success) return reply({ ok: false, error: 'Invalid request' });
      const { groupId, id } = parsed.data;

      const started = await markGroupRead({ groupId, messageId: id, userId: me });
      if (started.length > 0) {
        const members = await listMemberIds(groupId);
        for (const m of started) {
          emitToUsers(io, members, 'group:burning', { groupId, id: m.id, expiresAt: m.expires_at });
        }
      }
      reply({ ok: true });
    } catch (err) {
      console.error('[socket] group:read failed:', err.message);
      reply({ ok: false, error: 'Server error' });
    }
  });
}

// File: server/src/socket/handlers/burn.js
// End of file