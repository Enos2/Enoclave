// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/config/migrations/006_account_scheduling_prefs.js
// Purpose : Database changes for Day 6. (1) users gets password_changed_at,
//           set when a passphrase is changed (existing accounts start at the
//           migration time), which feeds the security checkup. (2)
//           scheduled_messages holds encrypted direct messages waiting for
//           their delivery time: only ciphertext and iv (the server cannot read
//           them), the delivery time, and the optional disappearing / burn
//           settings, which start counting at DELIVERY. CHECK constraints keep
//           sizes and timers within limits and forbid messaging yourself;
//           cascade deletes remove a user's schedules when the account (or the
//           recipient) is deleted. Rows are removed the moment they are
//           delivered or cancelled, so nothing lingers. (3) chat_prefs stores
//           each user's private per-conversation preferences (pinned,
//           archived, muted until a time, default disappearing timer) for
//           EITHER a direct peer OR a group (a CHECK enforces exactly one;
//           UNIQUE constraints allow one row per user and target). Safe to run
//           twice (IF NOT EXISTS). Never edit after applying.
// =============================================================================
export const name = '006_account_scheduling_prefs';

export const sql = `
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS scheduled_messages (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  from_id                 uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_id                   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ciphertext              text NOT NULL CHECK (length(ciphertext) <= 20000),
  iv                      text NOT NULL CHECK (length(iv) <= 32),
  deliver_at              timestamptz NOT NULL,
  ttl_seconds             integer CHECK (ttl_seconds BETWEEN 5 AND 604800),
  burn_after_read_seconds integer CHECK (burn_after_read_seconds BETWEEN 3 AND 3600),
  created_at              timestamptz NOT NULL DEFAULT now(),
  CHECK (from_id <> to_id)
);
CREATE INDEX IF NOT EXISTS scheduled_messages_due_idx  ON scheduled_messages (deliver_at);
CREATE INDEX IF NOT EXISTS scheduled_messages_from_idx ON scheduled_messages (from_id, deliver_at);

CREATE TABLE IF NOT EXISTS chat_prefs (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  peer_id             uuid REFERENCES users(id) ON DELETE CASCADE,
  group_id            uuid REFERENCES chat_groups(id) ON DELETE CASCADE,
  pinned              boolean NOT NULL DEFAULT false,
  archived            boolean NOT NULL DEFAULT false,
  muted_until         timestamptz,
  default_ttl_seconds integer CHECK (default_ttl_seconds BETWEEN 5 AND 604800),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  CHECK ((peer_id IS NOT NULL)::int + (group_id IS NOT NULL)::int = 1),
  CHECK (peer_id IS NULL OR peer_id <> user_id),
  UNIQUE (user_id, peer_id),
  UNIQUE (user_id, group_id)
);
CREATE INDEX IF NOT EXISTS chat_prefs_user_idx ON chat_prefs (user_id);
`;

// File: server/src/config/migrations/006_account_scheduling_prefs.js
// End of file