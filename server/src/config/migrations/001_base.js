// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/config/migrations/001_base.js
// Purpose : The original schema from Days 1 and 2, now registered as migration
//           001: users, 1-to-1 messages, login sessions (devices), the security
//           audit log, contacts, blocks, and group chats (groups, members with
//           roles, per-epoch wrapped key envelopes, encrypted group messages).
//           Every statement uses IF NOT EXISTS, so applying it to a database
//           that already has these tables is harmless. Constraints (CHECKs and
//           foreign keys with cascades) are enforced by the database itself, so
//           bad data cannot get in even if application code has a bug.
//           Never edit this file after it has been applied; add a new migration.
// =============================================================================
export const name = '001_base';

export const sql = `
CREATE TABLE IF NOT EXISTS users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username      text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9_]{3,24}$'),
  password_hash text NOT NULL,
  public_key    jsonb NOT NULL,
  token_version integer NOT NULL DEFAULT 0,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS messages (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  from_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ciphertext text NOT NULL CHECK (length(ciphertext) <= 20000),
  iv         text NOT NULL CHECK (length(iv) <= 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz
);
CREATE INDEX IF NOT EXISTS messages_pair_idx    ON messages (from_id, to_id, created_at DESC);
CREATE INDEX IF NOT EXISTS messages_to_idx      ON messages (to_id, created_at DESC);
CREATE INDEX IF NOT EXISTS messages_expires_idx ON messages (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS users_username_idx   ON users (username text_pattern_ops);

CREATE TABLE IF NOT EXISTS sessions (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_label text NOT NULL DEFAULT 'Unknown device',
  ip_hash      text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id, created_at DESC) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS auth_events (
  id           bigserial PRIMARY KEY,
  user_id      uuid REFERENCES users(id) ON DELETE CASCADE,
  username     text,
  event        text NOT NULL,
  ip_hash      text NOT NULL,
  device_label text NOT NULL DEFAULT 'Unknown device',
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS auth_events_user_idx ON auth_events (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS auth_events_fail_idx ON auth_events (username, created_at DESC) WHERE event = 'login_failed';

CREATE TABLE IF NOT EXISTS contacts (
  owner_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  contact_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (owner_id, contact_id),
  CHECK (owner_id <> contact_id)
);

CREATE TABLE IF NOT EXISTS blocks (
  blocker_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (blocker_id, blocked_id),
  CHECK (blocker_id <> blocked_id)
);
CREATE INDEX IF NOT EXISTS blocks_blocked_idx ON blocks (blocked_id);

CREATE TABLE IF NOT EXISTS chat_groups (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
  created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  epoch       integer NOT NULL DEFAULT 1,
  needs_rekey boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS group_members (
  group_id  uuid NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
  user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role      text NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
  joined_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS group_members_user_idx ON group_members (user_id);

CREATE TABLE IF NOT EXISTS group_key_envelopes (
  group_id           uuid NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
  epoch              integer NOT NULL,
  user_id            uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  wrapped_by         uuid REFERENCES users(id) ON DELETE SET NULL,
  wrapper_public_key jsonb NOT NULL,
  wrapped_key        text NOT NULL CHECK (length(wrapped_key) <= 200),
  iv                 text NOT NULL CHECK (length(iv) <= 32),
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, epoch, user_id)
);

CREATE TABLE IF NOT EXISTS group_messages (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id   uuid NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
  from_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  epoch      integer NOT NULL,
  ciphertext text NOT NULL CHECK (length(ciphertext) <= 20000),
  iv         text NOT NULL CHECK (length(iv) <= 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz
);
CREATE INDEX IF NOT EXISTS group_messages_group_idx   ON group_messages (group_id, created_at DESC);
CREATE INDEX IF NOT EXISTS group_messages_expires_idx ON group_messages (expires_at) WHERE expires_at IS NOT NULL;
`;

// File: server/src/config/migrations/001_base.js
// End of file