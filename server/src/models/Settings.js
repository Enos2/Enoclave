// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/Settings.js
// Purpose : Data-access layer for each user's privacy settings: showPresence
//           (let mutual contacts see when you are online), showTyping (send and
//           receive typing indicators), readReceipts (send and see read
//           receipts) and status (available, focus or away). Everything
//           defaults to ON/available, and a user without a row simply has the
//           defaults, so accounts need no setup. updateSettings is an upsert
//           that changes only the fields provided (COALESCE keeps the rest).
//           clearReceipts deletes all of a user's read cursors; it runs when
//           they switch receipts off, so nothing is left behind that could
//           reappear later. The settings are reciprocal by design (turn a
//           signal off and you also stop seeing it), which the signal queries
//           in Presence.js and Signal.js enforce.
// =============================================================================
import { query } from '../config/db.js';

const DEFAULTS = { show_presence: true, show_typing: true, read_receipts: true, status: 'available' };

export async function getSettings(userId) {
  const { rows } = await query(
    'SELECT show_presence, show_typing, read_receipts, status FROM user_settings WHERE user_id = $1',
    [userId]
  );
  return rows[0] ?? { ...DEFAULTS };
}

export async function updateSettings(userId, patch) {
  const { rows } = await query(
    `INSERT INTO user_settings (user_id, show_presence, show_typing, read_receipts, status)
     VALUES ($1, COALESCE($2::boolean, true), COALESCE($3::boolean, true),
                 COALESCE($4::boolean, true), COALESCE($5::text, 'available'))
     ON CONFLICT (user_id) DO UPDATE SET
       show_presence = COALESCE($2::boolean, user_settings.show_presence),
       show_typing   = COALESCE($3::boolean, user_settings.show_typing),
       read_receipts = COALESCE($4::boolean, user_settings.read_receipts),
       status        = COALESCE($5::text,    user_settings.status),
       updated_at    = now()
     RETURNING show_presence, show_typing, read_receipts, status`,
    [userId, patch.showPresence ?? null, patch.showTyping ?? null, patch.readReceipts ?? null, patch.status ?? null]
  );
  return rows[0];
}

export async function clearReceipts(userId) {
  await query('DELETE FROM read_cursors WHERE user_id = $1', [userId]);
  await query('DELETE FROM group_read_cursors WHERE user_id = $1', [userId]);
}

// File: server/src/models/Settings.js
// End of file