// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/utils/schemas.js
// Purpose : Shared zod schemas for the data every account route accepts.
//           usernameSchema: 3-24 characters, lowercase letters, digits and
//           underscore, trimmed and lowercased. passwordSchema: 10-72
//           characters (72 is the most bcrypt can use). publicKeySchema: a
//           strict EC P-256 public JWK - kty, crv and two 43-character
//           base64url coordinates, nothing else. Keeping them in one place
//           guarantees registration, login and key rotation apply identical
//           rules.
// =============================================================================
import { z } from 'zod';

export const usernameSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(3)
  .max(24)
  .regex(/^[a-z0-9_]+$/);

export const passwordSchema = z.string().min(10).max(72);

const coord = z.string().regex(/^[A-Za-z0-9_-]{43}$/);

export const publicKeySchema = z
  .object({
    kty: z.literal('EC'),
    crv: z.literal('P-256'),
    x: coord,
    y: coord,
  })
  .strict();

// File: server/src/utils/schemas.js
// End of file