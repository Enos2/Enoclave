// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/Presence.js
// Purpose : Decides WHO may see a user's presence. visiblePeers(userId)
//           returns the users that userId and the system may show to each
//           other, with each peer's chosen status. A peer qualifies only if ALL
//           of these hold: the two users are MUTUAL contacts (each added the
//           other, so nobody can watch you just by adding you); both have
//           showPresence enabled (reciprocal: hide yours and you stop seeing
//           theirs); and neither has blocked the other. If the user's own
//           presence is switched off the answer is an empty list, so they are
//           invisible and also see nothing. The same list is used both to push
//           updates (people who may see me) and to build a snapshot (people I
//           may see), because the rule is symmetric.
// =============================================================================
import { query } from '../config/db.js';

export async function visiblePeers(userId) {
  const { rows } = await query(
    `SELECT u.id, COALESCE(ps.status, 'available') AS status
     FROM contacts c1
     JOIN contacts c2 ON c2.owner_id = c1.contact_id AND c2.contact_id = c1.owner_id
     JOIN users u ON u.id = c1.contact_id
     LEFT JOIN user_settings ps ON ps.user_id = u.id
     WHERE c1.owner_id = $1::uuid
       AND COALESCE((SELECT show_presence FROM user_settings WHERE user_id = $1::uuid), true)
       AND COALESCE(ps.show_presence, true)
       AND NOT EXISTS (
         SELECT 1 FROM blocks b
         WHERE (b.blocker_id = $1::uuid AND b.blocked_id = u.id)
            OR (b.blocker_id = u.id AND b.blocked_id = $1::uuid))`,
    [userId]
  );
  return rows;
}

// File: server/src/models/Presence.js
// End of file