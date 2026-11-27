// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/utils/serialize.js
// Purpose : Converts database rows into the exact JSON the API and realtime
//           events return, so internal column names (snake_case) and secrets
//           such as password hashes can never leak into a response. Covers the
//           public user shape, direct messages and group messages, including
//           the burn-on-read setting (burnAfterReadSeconds) and expiry time
//           (expiresAt, which is null until a timer starts). Also provides the
//           UUID check used on every route parameter and socket payload: an
//           id that fails it never reaches a SQL query. This file is final;
//           later features add their own serializers next to their models.
// =============================================================================
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const isUuid = (v) => typeof v === 'string' && UUID_RE.test(v);

export function publicUser(u) {
  return { id: u.id, username: u.username, publicKey: u.public_key };
}

export function serializeMessage(m) {
  return {
    id: m.id,
    from: m.from_id,
    to: m.to_id,
    ciphertext: m.ciphertext,
    iv: m.iv,
    createdAt: m.created_at,
    expiresAt: m.expires_at,
    burnAfterReadSeconds: m.burn_after_read_seconds ?? null,
  };
}

export function serializeGroupMessage(m) {
  return {
    id: m.id,
    groupId: m.group_id,
    from: m.from_id,
    epoch: m.epoch,
    ciphertext: m.ciphertext,
    iv: m.iv,
    createdAt: m.created_at,
    expiresAt: m.expires_at,
    burnAfterReadSeconds: m.burn_after_read_seconds ?? null,
  };
}

// File: server/src/utils/serialize.js
// End of file