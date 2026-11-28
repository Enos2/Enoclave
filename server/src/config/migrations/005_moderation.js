// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/config/migrations/005_moderation.js
// Purpose : Database changes for reporting and moderation (Day 5).
//           users gains is_admin (default false; set only through the
//           make-admin script), suspended_until (NULL = not suspended,
//           'infinity' = permanent) and suspension_reason.
//           reports stores each report: who reported (reporter_id), who is
//           reported (reported_user_id plus a username snapshot so the record
//           survives account deletion), what was reported (user, a direct
//           message or a group message), a fixed reason list, an optional note,
//           and evidence. Evidence is a snapshot taken by the SERVER from the
//           message at report time (ciphertext, iv, epoch and send time, so
//           unsending cannot erase it) plus optional reporter-supplied
//           plaintext, which is unverified. status is open, actioned or
//           dismissed; flagged marks reports caught by the anti-brigading
//           rule. A partial UNIQUE index allows only one OPEN report per
//           reporter + target. moderation_actions is the audit trail of every
//           admin decision. Deleting an account sets the ids to NULL instead of
//           deleting the record. Safe to run twice. Never edit after applying.
// =============================================================================
export const name = '005_moderation';

export const sql = `
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended_until timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS suspension_reason text;

CREATE TABLE IF NOT EXISTS reports (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reporter_id         uuid REFERENCES users(id) ON DELETE SET NULL,
  reported_user_id    uuid REFERENCES users(id) ON DELETE SET NULL,
  reported_username   text NOT NULL,
  target_type         text NOT NULL CHECK (target_type IN ('user', 'message', 'group_message')),
  message_id          uuid,
  group_id            uuid REFERENCES chat_groups(id) ON DELETE SET NULL,
  reason              text NOT NULL CHECK (reason IN ('spam', 'harassment', 'scam', 'illegal', 'impersonation', 'other')),
  note                text CHECK (char_length(note) <= 1000),
  evidence_text       text CHECK (char_length(evidence_text) <= 4000),
  evidence_ciphertext text CHECK (length(evidence_ciphertext) <= 20000),
  evidence_iv         text CHECK (length(evidence_iv) <= 32),
  evidence_epoch      integer,
  evidence_sent_at    timestamptz,
  status              text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'actioned', 'dismissed')),
  flagged             boolean NOT NULL DEFAULT false,
  resolved_by         uuid REFERENCES users(id) ON DELETE SET NULL,
  resolution_note     text CHECK (char_length(resolution_note) <= 1000),
  created_at          timestamptz NOT NULL DEFAULT now(),
  resolved_at         timestamptz
);
CREATE INDEX IF NOT EXISTS reports_status_idx   ON reports (status, created_at DESC);
CREATE INDEX IF NOT EXISTS reports_reported_idx ON reports (reported_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS reports_reporter_idx ON reports (reporter_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS reports_one_open_idx ON reports (
  reporter_id, reported_user_id, target_type,
  COALESCE(message_id, '00000000-0000-0000-0000-000000000000'::uuid)
) WHERE status = 'open';

CREATE TABLE IF NOT EXISTS moderation_actions (
  id              bigserial PRIMARY KEY,
  admin_id        uuid REFERENCES users(id) ON DELETE SET NULL,
  target_user_id  uuid REFERENCES users(id) ON DELETE SET NULL,
  target_username text,
  action          text NOT NULL CHECK (action IN ('suspend', 'unsuspend', 'resolve', 'dismiss')),
  reason          text CHECK (char_length(reason) <= 1000),
  until           timestamptz,
  report_id       uuid,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS moderation_actions_created_idx ON moderation_actions (created_at DESC);
`;

// File: server/src/config/migrations/005_moderation.js
// End of file