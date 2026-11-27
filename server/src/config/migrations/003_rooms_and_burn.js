// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/config/migrations/003_rooms_and_burn.js
// Purpose : Database changes for self-destruct rooms and burn-on-read (Day 3B).
//           chat_groups gets expires_at: when set, the room (with all its
//           messages, keys, invites and requests, via ON DELETE CASCADE) is
//           destroyed at that time. messages and group_messages get
//           burn_after_read_seconds (the sender's chosen countdown, 3 seconds
//           to 1 hour, enforced by a CHECK) and burn_started_at (when the
//           countdown began). group_message_reads records which member has read
//           which burn message, so a group burn starts only when everyone has
//           read it. Read state exists ONLY for burn messages; general read
//           receipts (with privacy toggles) arrive on Day 4. Uses IF NOT EXISTS
//           throughout so it is safe to run twice. Never edit after applying.
// =============================================================================
export const name = '003_rooms_and_burn';

export const sql = `
ALTER TABLE chat_groups ADD COLUMN IF NOT EXISTS expires_at timestamptz;
CREATE INDEX IF NOT EXISTS chat_groups_expires_idx ON chat_groups (expires_at) WHERE expires_at IS NOT NULL;

ALTER TABLE messages ADD COLUMN IF NOT EXISTS burn_after_read_seconds integer
  CHECK (burn_after_read_seconds BETWEEN 3 AND 3600);
ALTER TABLE messages ADD COLUMN IF NOT EXISTS burn_started_at timestamptz;

ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS burn_after_read_seconds integer
  CHECK (burn_after_read_seconds BETWEEN 3 AND 3600);
ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS burn_started_at timestamptz;
CREATE INDEX IF NOT EXISTS group_messages_burn_idx ON group_messages (created_at)
  WHERE burn_after_read_seconds IS NOT NULL AND burn_started_at IS NULL;

CREATE TABLE IF NOT EXISTS group_message_reads (
  message_id uuid NOT NULL REFERENCES group_messages(id) ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  read_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id)
);
CREATE INDEX IF NOT EXISTS group_message_reads_user_idx ON group_message_reads (user_id);
`;

// File: server/src/config/migrations/003_rooms_and_burn.js
// End of file