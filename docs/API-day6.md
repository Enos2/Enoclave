<!-- =========================================================================
Project : Enoclave - private, end-to-end encrypted web chat
File    : docs/API-day6.md
Purpose : API reference for the Day 6 features: account self-service (change
          passphrase, data export, security checkup), scheduled (time-locked)
          direct messages and per-chat preferences. Complements docs/API.md,
          which covers everything built earlier. The conventions in API.md
          (cookie auth, Origin header, strict bodies, status codes) apply here
          unchanged.
========================================================================== -->
# Day 6 API additions

## Account `/api/account`
| Method + path | Body | Result |
|---|---|---|
| PUT `/password` | `{currentPassword, newPassword}` (10-72 chars) | `{ok, otherSessionsRevoked}`; signs out all OTHER devices; 429 after 5 wrong attempts in 15 min |
| POST `/export` | `{password}` | JSON file download (`Content-Disposition: attachment`, `no-store`); 3 per hour; ciphertext only, never the password hash |
| GET `/security` | | `{score 0-100, rating, checks:[{id,status: ok\|warn\|info,title,detail}]}` |

Changing the passphrase does not affect encryption keys (they are device keys).

## Scheduled messages `/api/scheduled`
| POST `/` | `{to, ciphertext, iv, deliverAt (ISO 8601 with timezone, 10 s to 30 days ahead), ttlSeconds?, burnAfterReadSeconds?}` | 201 `{scheduled:{id,to,deliverAt}}`; max 50 pending |
|---|---|---|
| GET `/` | | `{scheduled:[{id,to,toUsername,deliverAt,ttlSeconds,burnAfterReadSeconds,createdAt}]}` (no ciphertext) |
| DELETE `/:id` | | cancel (sender only) |
Errors: 400 invalid/time out of range, 404 unknown recipient, 409 you blocked them or too many pending.
Disappearing and burn timers start at **delivery**. If the recipient rotates their key before delivery the message cannot be decrypted.

## Chat preferences `/api/chats`
| GET `/prefs` | | `{prefs:[{kind: direct\|group, targetId, name, pinned, archived, mutedUntil, defaultTtlSeconds}]}` (non-default only) |
|---|---|---|
| PUT `/prefs/direct/:peerId` | `{pinned?, archived?, mutedUntil? (future ISO or null), defaultTtlSeconds? (5..604800 or null)}` | `{prefs}`; max 5 pinned (409) |
| PUT `/prefs/group/:groupId` | same | 404 if you are not a member |
Preferences are private and only stored for the user's own clients.

## New realtime events (server -> client)
`scheduled:delivered {id, messageId}` | `scheduled:failed {id, reason}` | `prefs:updated {kind, targetId, prefs}` (to all of the user's devices)

<!-- File: docs/API-day6.md -->
<!-- End of file -->