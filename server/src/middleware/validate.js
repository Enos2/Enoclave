// File: server/src/middleware/validate.js
// Purpose: Validate and sanitise request bodies with a zod schema; reject anything unexpected.
export const validate = (schema) => (req, res, next) => {
  const result = schema.safeParse(req.body);
  if (!result.success) return res.status(400).json({ error: 'Invalid input' });
  req.body = result.data;
  next();
};

// File: server/src/middleware/validate.js
// End of file