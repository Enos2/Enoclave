// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/config/migrations/002_group_invites.js
// Purpose : Adds invite links and join requests for groups (Day 3A).
//           group_invites stores only the SHA-256 HASH of each invite token,
//           never the token itself, so a database leak cannot reveal working
//           links. Each invite has an expiry, a maximum number of uses and an
//           optional revocation time; CHECK constraints keep uses within
//           max_uses. group_join_requests holds people who redeemed an invite
//           and are waiting for an admin to approve them (the admin's client
//           wraps the group key for them). Both tables cascade-delete with
//           their group, so a destroyed group leaves nothing behind.
// =============================================================================
export const name = '002_group_invites';

export const sql = `
CREATE TABLE IF NOT EXISTS group_invites (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id   uuid NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  token_hash text NOT NULL UNIQUE CHECK (length(token_hash) = 64),
  max_uses   integer NOT NULL CHECK (max_uses BETWEEN 1 AND 50),
  uses       integer NOT NULL DEFAULT 0 CHECK (uses >= 0),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (uses <= max_uses)
);
CREATE INDEX IF NOT EXISTS group_invites_group_idx ON group_invites (group_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS group_join_requests (
  group_id   uuid NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invite_id  uuid REFERENCES group_invites(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS group_join_requests_user_idx ON group_join_requests (user_id);
`;

// File: server/src/config/migrations/002_group_invites.js
// End of file