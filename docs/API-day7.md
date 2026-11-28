<!-- =========================================================================
Project : Enoclave - private, end-to-end encrypted web chat
File    : docs/API-day7.md
Purpose : API reference for the Day 7 features: two-factor authentication
          (TOTP with recovery codes) and message reactions. Complements
          docs/API.md and docs/API-day6.md; their conventions (cookie auth,
          Origin header, strict bodies, status codes) apply unchanged.
========================================================================== -->
# Day 7 API additions

## Login with two-factor `POST /api/auth/login`
Body: `{username, password, code?, recoveryCode?}` (send at most one of `code` / `recoveryCode`).
- 2FA off: works as before.
- 2FA on, no code sent: **401 `{error, twoFactorRequired: true}`**. Show a code field and retry the same request with `code`.
- Wrong, malformed-but-accepted or already-used code: 401 `Invalid credentials` (counts toward the login lockout, 429 after 5 failures).
- Recovery codes work once; case and the dash do not matter.

## Two-factor `/api/two-factor`
| GET `/status` | | `{enabled, recoveryCodesRemaining}` |
|---|---|---|
| POST `/setup` | `{password}` | `{secret, otpauthUrl, digits, period}`; render `otpauthUrl` as a QR code; 2FA stays off until `/enable`; 409 if already on |
| POST `/enable` | `{code}` | `{ok, recoveryCodes[10]}`: **shown once**, tell the user to save them |
| POST `/disable` | `{password, code \| recoveryCode}` | `{ok}` |
| POST `/recovery-codes` | `{password, code}` | `{ok, recoveryCodes[10]}`: replaces all old codes, shown once |
Failures (wrong passphrase or code) are limited to 5 per 15 minutes per user (429 + `Retry-After`). Responses carrying secrets are `no-store`.
Operational note: the secrets are encrypted with a key derived from `JWT_SECRET`; do not rotate `JWT_SECRET` without a plan.

## Reactions `/api/reactions`
Allowed values: `thumbs_up`, `heart`, `laugh`, `wow`, `sad`, `pray`, `fire`, `thumbs_down` (one per person per message; a new one replaces the old).
| PUT `/direct/:messageId` | `{reaction}` | react to a direct message you can see |
|---|---|---|
| DELETE `/direct/:messageId` | | remove your reaction |
| PUT / DELETE `/group/:messageId` | same | group messages you could see |
| GET `/conversation/:peerId` | | `{reactions:{"<messageId>":[{userId,reaction}]}}` for the latest 100 messages |
| GET `/groups/:groupId` | | same for a group (404 if not a member) |
Errors: 400 invalid, 404 not visible to you, 409 you blocked that user. If THEY blocked you the call returns 200 but nothing is stored.
Reactions are plaintext metadata (the server can see them); message content stays encrypted. They are deleted with their message.

## New realtime event (server -> client)
`reaction:update {kind: direct|group, groupId?, messageId, userId, reaction | null}`; `null` means removed.

<!-- File: docs/API-day7.md -->
<!-- End of file -->