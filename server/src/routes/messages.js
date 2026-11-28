// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/routes/messages.js
// Purpose : HTTP API under /api/messages for 1-to-1 chats. GET / lists
//           conversations; GET /:userId returns up to 100 messages of one
//           conversation (ciphertext only; expired and burned messages are
//           excluded); DELETE /item/:id lets the SENDER unsend one message
//           for both people; DELETE /:userId clears a whole conversation for
//           BOTH people. Sending is done over the realtime socket
//           (socket/handlers/messages.js), not here. Realtime events keep
//           every device in sync. Session required; ids validated as UUIDs.
// =============================================================================
import { Router } from 'express';
import { listConversations, getHistory, deleteOwnMessage, clearChat } from '../models/Message.js';
import { requireAuth } from '../middleware/auth.js';
import { isUuid, serializeMessage } from '../utils/serialize.js';

const router = Router();
router.use(requireAuth);

router.get('/', async (req, res, next) => {
  try {
    const conversations = await listConversations(req.user.id);
    res.json({ conversations: conversations.map((c) => ({ id: c.id, username: c.username })) });
  } catch (err) {
    next(err);
  }
});

router.get('/:userId', async (req, res, next) => {
  try {
    const peer = req.params.userId;
    if (!isUuid(peer)) return res.status(400).json({ error: 'Invalid input' });
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);
    const rows = await getHistory(req.user.id, peer, limit);
    res.json({ messages: rows.map(serializeMessage) });
  } catch (err) {
    next(err);
  }
});

// Unsend: only the original sender can delete a message.
router.delete('/item/:id', async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid input' });
    const msg = await deleteOwnMessage(req.params.id, req.user.id);
    if (!msg) return res.status(404).json({ error: 'Not found' });
    req.app
      .get('io')
      ?.to(`user:${msg.from_id}`)
      .to(`user:${msg.to_id}`)
      .emit('message:deleted', { id: msg.id, from: msg.from_id, to: msg.to_id });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// Clear chat: removes the whole conversation for BOTH people.
router.delete('/:userId', async (req, res, next) => {
  try {
    const peer = req.params.userId;
    if (!isUuid(peer)) return res.status(400).json({ error: 'Invalid input' });
    await clearChat(req.user.id, peer);
    req.app
      .get('io')
      ?.to(`user:${req.user.id}`)
      .to(`user:${peer}`)
      .emit('chat:cleared', { a: req.user.id, b: peer });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

export default router;

// File: server/src/routes/messages.js
// End of file