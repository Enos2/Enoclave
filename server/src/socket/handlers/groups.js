// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/socket/handlers/groups.js
// Purpose : Realtime handler for encrypted group messages (auto-loaded by
//           socket/index.js). Event 'group:send' accepts { groupId, epoch,
//           ciphertext, iv, ttlSeconds?, burnAfterReadSeconds? }; the answer
//           comes through the acknowledgement callback. The payload is
//           validated with zod (.strict()). Membership, the current key epoch,
//           the "group is waiting for a new key" state and room expiry are all
//           enforced atomically INSIDE the database insert, so a member removed
//           a moment ago, a stale client, or a message into an expired room is
//           rejected even under a race. When a send is refused this handler
//           works out why and returns a helpful, non-leaking message: not a
//           member, group re-keying, or key out of date (with the current
//           epoch so the client can refresh). Accepted messages are pushed as
//           'group:message' to every current member's private room.
// =============================================================================
import { z } from 'zod';
import { getMembership, listMemberIds } from '../../models/Group.js';
import { createGroupMessage } from '../../models/GroupMessage.js';
import { isUuid, serializeGroupMessage } from '../../utils/serialize.js';
import { emitToUsers } from '../../utils/realtime.js';

const base64 = /^[A-Za-z0-9+/=]+$/;

const groupSendSchema = z
  .object({
    groupId: z.string().refine(isUuid),
    epoch: z.number().int().min(1),
    ciphertext: z.string().min(1).max(20000).regex(base64),
    iv: z.string().min(16).max(32).regex(base64),
    ttlSeconds: z.number().int().min(5).max(604800).optional(),
    burnAfterReadSeconds: z.number().int().min(3).max(3600).optional(),
  })
  .strict();

export default function register({ io, socket, allowed }) {
  const me = socket.data.user.id;

  socket.on('group:send', async (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    try {
      if (!allowed(socket)) return reply({ ok: false, error: 'Slow down' });
      const parsed = groupSendSchema.safeParse(payload);
      if (!parsed.success) return reply({ ok: false, error: 'Invalid message' });
      const { groupId, epoch, ciphertext, iv, ttlSeconds, burnAfterReadSeconds } = parsed.data;

      const msg = await createGroupMessage({
        groupId,
        fromId: me,
        epoch,
        ciphertext,
        iv,
        ttlSeconds,
        burnSeconds: burnAfterReadSeconds,
      });

      if (!msg) {
        const m = await getMembership(groupId, me);
        if (!m) return reply({ ok: false, error: 'Not a member of this group' });
        if (m.needs_rekey) return reply({ ok: false, error: 'The group is getting a new key. Try again shortly.' });
        if (m.epoch !== epoch) {
          return reply({ ok: false, error: 'Group key is out of date. Refresh the group.', epoch: m.epoch });
        }
        return reply({ ok: false, error: 'This room is no longer available' });
      }

      emitToUsers(io, await listMemberIds(groupId), 'group:message', serializeGroupMessage(msg));
      reply({ ok: true });
    } catch (err) {
      console.error('[socket] group:send failed:', err.message);
      reply({ ok: false, error: 'Server error' });
    }
  });
}

// File: server/src/socket/handlers/groups.js
// End of file