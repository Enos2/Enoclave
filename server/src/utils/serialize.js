// File: server/src/utils/serialize.js
// Purpose: Safe response shapes and UUID validation helpers.
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
  };
}

// File: server/src/utils/serialize.js
// End of file