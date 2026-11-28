// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/config/migrations/007_two_factor_reactions.js
// Purpose : Database changes for Day 7. TWO-FACTOR: two_factor holds, per user,
//           the TOTP secret ENCRYPTED (AES-256-GCM; the plaintext secret is
//           never stored), whether 2FA is switched on, and last_step - the last
//           30-second time step that was accepted, which makes every code
//           single-use (replay protection). recovery_codes holds the single-use
//           backup codes as keyed HMAC hashes only (the codes themselves are
//           shown once and never stored), with used_at set when spent; UNIQUE
//           (user_id, code_hash) prevents duplicates. REACTIONS: direct_reactions
//           and group_reactions store one reaction per user per message, from a
//           fixed list enforced by a CHECK constraint (no arbitrary text can be
//           stored). Both tables reference their message with ON DELETE
//           CASCADE, so unsending, expiring, burning, clearing a chat or
//           destroying a room removes the reactions automatically, and
//           deleting a user removes their reactions. Safe to run twice (IF NOT
//           EXISTS). Never edit after applying.
// =============================================================================
export const name = '007_two_factor_reactions';

export const sql = `
CREATE TABLE IF NOT EXISTS two_factor (
  user_id    uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret_enc text NOT NULL CHECK (length(secret_enc) <= 300),
  enabled    boolean NOT NULL DEFAULT false,
  last_step  bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  enabled_at timestamptz
);

CREATE TABLE IF NOT EXISTS recovery_codes (
  id         bigserial PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  text NOT NULL CHECK (length(code_hash) = 64),
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, code_hash)
);
CREATE INDEX IF NOT EXISTS recovery_codes_unused_idx ON recovery_codes (user_id) WHERE used_at IS NULL;

CREATE TABLE IF NOT EXISTS direct_reactions (
  message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reaction   text NOT NULL CHECK (reaction IN ('thumbs_up','heart','laugh','wow','sad','pray','fire','thumbs_down')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id)
);
CREATE INDEX IF NOT EXISTS direct_reactions_user_idx ON direct_reactions (user_id);

CREATE TABLE IF NOT EXISTS group_reactions (
  message_id uuid NOT NULL REFERENCES group_messages(id) ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reaction   text NOT NULL CHECK (reaction IN ('thumbs_up','heart','laugh','wow','sad','pray','fire','thumbs_down')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id)
);
CREATE INDEX IF NOT EXISTS group_reactions_user_idx ON group_reactions (user_id);
`;

// File: server/src/config/migrations/007_two_factor_reactions.js
// End of file