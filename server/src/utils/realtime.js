// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/utils/realtime.js
// Purpose : Small helpers for pushing realtime events from HTTP routes and the
//           socket layer. emitToUsers() sends one event to many users at once
//           (each user has a private "user:<id>" room, shared by all of their
//           devices). notifyGroup() looks up the group's CURRENT members and
//           sends them a "group:updated" event with a type such as
//           member_added, member_removed, rekeyed or rekey_needed, so clients
//           know to refresh the group and, if needed, post new key envelopes.
//           Failures are logged and swallowed: a realtime hiccup must never
//           make an already-successful database change look like an error.
// =============================================================================
import { listMemberIds } from '../models/Group.js';

export function emitToUsers(io, userIds, event, payload) {
  if (!io || !userIds || userIds.length === 0) return;
  io.to(userIds.map((id) => `user:${id}`)).emit(event, payload);
}

export async function notifyGroup(io, groupId, type, extra = {}) {
  try {
    const ids = await listMemberIds(groupId);
    emitToUsers(io, ids, 'group:updated', { groupId, type, ...extra });
  } catch (err) {
    console.error('[realtime] notifyGroup failed:', err.message);
  }
}

// File: server/src/utils/realtime.js
// End of file