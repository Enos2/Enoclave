// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/config/migrations/004_files_presence_receipts.js
// Purpose : Database changes for Day 4. Adds four tables.
//           files: metadata for encrypted attachments (the bytes live on disk,
//           the server only ever holds ciphertext). Each row targets EITHER a
//           direct recipient OR a group (a CHECK enforces exactly one), has a
//           kind ('file' or 'voice'), a declared size capped at 25 MB, a status
//           (pending -> uploading -> ready) and an expiry. Foreign keys cascade,
//           so deleting a user or destroying a group removes the rows (the file
//           sweeper then removes the orphaned bytes from disk).
//           user_settings: per-user privacy toggles (presence, typing, read
//           receipts) and the self-chosen status (available/focus/away).
//           A missing row means "all defaults", so no row is needed until a user
//           changes something.
//           read_cursors and group_read_cursors: one "read up to this time"
//           pointer per user per conversation - not one row per message - so
//           read state stays small and reveals as little as possible.
//           Safe to run twice (IF NOT EXISTS). Never edit after applying.
// =============================================================================
export const name = '004_files_presence_receipts';

export const sql = `
CREATE TABLE IF NOT EXISTS files (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id uuid REFERENCES users(id) ON DELETE CASCADE,
  group_id     uuid REFERENCES chat_groups(id) ON DELETE CASCADE,
  kind         text NOT NULL CHECK (kind IN ('file', 'voice')),
  size_bytes   bigint NOT NULL CHECK (size_bytes BETWEEN 28 AND 26214400),
  status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'uploading', 'ready')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  CHECK ((recipient_id IS NOT NULL)::int + (group_id IS NOT NULL)::int = 1)
);
CREATE INDEX IF NOT EXISTS files_owner_idx     ON files (owner_id);
CREATE INDEX IF NOT EXISTS files_expires_idx   ON files (expires_at);
CREATE INDEX IF NOT EXISTS files_group_idx     ON files (group_id) WHERE group_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS files_recipient_idx ON files (recipient_id) WHERE recipient_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS user_settings (
  user_id       uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  show_presence boolean NOT NULL DEFAULT true,
  show_typing   boolean NOT NULL DEFAULT true,
  read_receipts boolean NOT NULL DEFAULT true,
  status        text NOT NULL DEFAULT 'available' CHECK (status IN ('available', 'focus', 'away')),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS read_cursors (
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  peer_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  last_read_at timestamptz NOT NULL,
  PRIMARY KEY (user_id, peer_id),
  CHECK (user_id <> peer_id)
);

CREATE TABLE IF NOT EXISTS group_read_cursors (
  group_id     uuid NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  last_read_at timestamptz NOT NULL,
  PRIMARY KEY (group_id, user_id)
);
`;

// File: server/src/config/migrations/004_files_presence_receipts.js
// End of file