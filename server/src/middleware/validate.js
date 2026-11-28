// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/middleware/validate.js
// Purpose : Express middleware factory that validates req.body against a zod
//           schema BEFORE any route logic runs. validate(schema) returns a
//           middleware: if the body does not match (wrong types, missing
//           fields, unknown fields when the schema is .strict(), values out
//           of range) it answers 400 "Invalid input" without revealing which
//           rule failed; otherwise it replaces req.body with the parsed,
//           trimmed and type-coerced result, so handlers only ever see clean
//           data. Used on every route that accepts a JSON body.
// =============================================================================
export const validate = (schema) => (req, res, next) => {
  const result = schema.safeParse(req.body);
  if (!result.success) return res.status(400).json({ error: 'Invalid input' });
  req.body = result.data;
  next();
};

// File: server/src/middleware/validate.js
// End of file