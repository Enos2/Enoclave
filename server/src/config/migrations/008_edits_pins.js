// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/config/migrations/008_edits_pins.js
// Purpose : Database changes for Day 8. EDITING: messages and group_messages
//           gain edited_at (when the message was last edited, NULL if never)
//           and edit_count (how many times; a CHECK keeps it between 0 and 10,
//           so the 10-edit limit is enforced by the database itself, not only
//           by application code). PINNING: pinned_direct marks messages pinned
//           in a 1-to-1 conversation (shared by both people) and pinned_group
//           marks messages pinned in a group (admins only, enforced by the
//           model). Each pin row is keyed by its message id (a message can be
//           pinned once) and references the message with ON DELETE CASCADE, so
//           unsending, expiring, burning, clearing a chat or destroying a room
//           removes the pin automatically; pinned_by cascades with the user.
//           Pin counts per conversation are limited by the model under an
//           advisory lock. Safe to run twice (IF NOT EXISTS). Never edit after
//           applying.
// =============================================================================
export const name = '008_edits_pins';

export const sql = `
ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited_at timestamptz;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS edit_count integer NOT NULL DEFAULT 0
  CHECK (edit_count BETWEEN 0 AND 10);
ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS edited_at timestamptz;
ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS edit_count integer NOT NULL DEFAULT 0
  CHECK (edit_count BETWEEN 0 AND 10);

CREATE TABLE IF NOT EXISTS pinned_direct (
  message_id uuid PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
  pinned_by  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  pinned_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS pinned_direct_by_idx ON pinned_direct (pinned_by);

CREATE TABLE IF NOT EXISTS pinned_group (
  message_id uuid PRIMARY KEY REFERENCES group_messages(id) ON DELETE CASCADE,
  group_id   uuid NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
  pinned_by  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  pinned_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS pinned_group_group_idx ON pinned_group (group_id);
CREATE INDEX IF NOT EXISTS pinned_group_by_idx ON pinned_group (pinned_by);
`;

// File: server/src/config/migrations/008_edits_pins.js
// End of file