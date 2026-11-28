<!-- =========================================================================
Project : Enoclave - private, end-to-end encrypted web chat
File    : docs/API-day8.md
Purpose : API reference for the Day 8 features: editing sent messages, pinned
          messages, and the additions to the account export and security
          checkup. Complements docs/API.md, API-day6.md and API-day7.md; their
          conventions (cookie auth, Origin header, strict bodies, status codes)
          apply unchanged.
========================================================================== -->
# Day 8 API additions

## Edits `/api/edits`
The client encrypts the NEW text like a normal message and sends only ciphertext.
| PUT `/direct/:id` | `{ciphertext, iv}` | `{ok, editedAt}` |
|---|---|---|
| PUT `/group/:id` | `{epoch, ciphertext, iv}` (epoch = the message's original key epoch) | `{ok, editedAt}` |
Rules: only the sender; within 15 minutes of sending (server clock); at most 10 edits; not after a burn timer started or the message expired.
Errors: 404 not yours/unknown/expired, 409 too late / burning / edited too often / you blocked the recipient / wrong epoch. If the recipient blocked you the call returns 200 but nothing changes and nothing is sent.
Messages now carry `editedAt` (null if never edited) in every list and event.

## Pins `/api/pins`
| PUT / DELETE `/direct/:messageId` | | pin / unpin a message of a conversation you are in (either person; max 3 per conversation, shared) |
|---|---|---|
| PUT / DELETE `/group/:messageId` | | group admins only (403 for members, 404 for non-members; max 5 per group) |
| GET `/conversation/:peerId` | | `{pins:[{messageId,pinnedBy,pinnedAt,message}]}` (message includes ciphertext) |
| GET `/groups/:groupId` | | same for a group (404 if not a member) |
Limit reached: 409 with `{max}`. Pinning an already pinned message is harmless. Pins are removed automatically with their message. Pins are plaintext metadata. If the other person blocked you, pinning returns 200 but stores nothing.

## Account changes
- `GET /api/account/security` has a new check `two_factor` (warn, -15 points, when off).
- `POST /api/account/export` additionally contains `reactionsGiven`, `twoFactor {enabled, enabledAt, recoveryCodesRemaining}`, `pinsCreated`, and `edited_at` on messages. Secrets and recovery codes are never included.

## New realtime events (server -> client)
`message:edited` (full updated message incl. `editedAt`) | `group:message:edited` (same, group message) | `pin:update {kind: direct|group, groupId?, messageId, pinned, by}`

<!-- File: docs/API-day8.md -->
<!-- End of file -->