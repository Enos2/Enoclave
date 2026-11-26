// File: server/src/utils/schemas.js
// Purpose: Shared zod validation schemas for usernames, passwords and public keys.
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