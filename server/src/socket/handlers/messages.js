// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/socket/handlers/messages.js
// Purpose : Realtime handler for 1-to-1 messages (auto-loaded by
//           socket/index.js). Event 'message:send' accepts { to, ciphertext,
//           iv, ttlSeconds?, burnAfterReadSeconds? } and answers through the
//           acknowledgement callback with { ok } or { ok:false, error }.
//           The payload is validated with zod (.strict(): unknown fields are
//           rejected; ciphertext and iv must be base64 within size limits).
//           Rules: no messaging yourself or non-existent users; if YOU blocked
//           the recipient you get an error telling you to unblock; if the
//           recipient blocked YOU the server reports success but stores and
//           delivers nothing, so a blocked user cannot tell they are blocked.
//           The stored message is pushed to both users' private rooms (every
//           device of each). The server only ever sees ciphertext.
// =============================================================================
import { z } from 'zod';
import { userExists } from '../../models/User.js';
import { createMessage } from '../../models/Message.js';
import { getBlockState } from '../../models/Block.js';
import { isUuid, serializeMessage } from '../../utils/serialize.js';

const base64 = /^[A-Za-z0-9+/=]+$/;

const sendSchema = z
  .object({
    to: z.string().refine(isUuid),
    ciphertext: z.string().min(1).max(20000).regex(base64),
    iv: z.string().min(16).max(32).regex(base64),
    ttlSeconds: z.number().int().min(5).max(604800).optional(),
    burnAfterReadSeconds: z.number().int().min(3).max(3600).optional(),
  })
  .strict();

export default function register({ io, socket, allowed }) {
  const me = socket.data.user.id;

  socket.on('message:send', async (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    try {
      if (!allowed(socket)) return reply({ ok: false, error: 'Slow down' });
      const parsed = sendSchema.safeParse(payload);
      if (!parsed.success) return reply({ ok: false, error: 'Invalid message' });
      const { to, ciphertext, iv, ttlSeconds, burnAfterReadSeconds } = parsed.data;
      if (to === me) return reply({ ok: false, error: 'Invalid recipient' });
      if (!(await userExists(to))) return reply({ ok: false, error: 'Invalid recipient' });

      const { iBlocked, blockedMe } = await getBlockState(me, to);
      if (iBlocked) return reply({ ok: false, error: 'You blocked this user. Unblock them to send messages.' });
      if (blockedMe) return reply({ ok: true }); // silent drop: a blocked sender cannot tell

      const msg = await createMessage({
        from: me,
        to,
        ciphertext,
        iv,
        ttlSeconds,
        burnSeconds: burnAfterReadSeconds,
      });
      io.to(`user:${me}`).to(`user:${to}`).emit('message:new', serializeMessage(msg));
      reply({ ok: true });
    } catch (err) {
      console.error('[socket] message:send failed:', err.message);
      reply({ ok: false, error: 'Server error' });
    }
  });
}

// File: server/src/socket/handlers/messages.js
// End of file