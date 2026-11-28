<!-- =========================================================================
Project : Enoclave - private, end-to-end encrypted web chat
File    : docs/API.md
Purpose : The complete reference for the Enoclave backend, written for the
          person building the frontend: conventions, every HTTP endpoint with
          its body and result, and every realtime (Socket.IO) event in both
          directions. If code and this document ever disagree, the code wins;
          fix the document.
========================================================================== -->
# Enoclave API reference

## Conventions
- Base URL `http://localhost:5000`; all HTTP paths start with `/api`. JSON in, JSON out. Errors are `{ "error": "message" }`.
- Authentication is the **httpOnly cookie** set by register/login. Send `credentials: 'include'` on every `fetch`; use `withCredentials: true` for Socket.IO.
- Every `POST`, `PUT` and `DELETE` must carry an `Origin` header equal to the server's `CLIENT_ORIGIN` (browsers do this automatically from the allowed origin).
- Ids are UUIDs. Unknown fields in a body are rejected with 400. Base64 values are standard base64; key coordinates are base64url.
- Status codes: 400 invalid input, 401 not logged in, 403 forbidden/blocked/suspended, 404 not found **or not yours**, 409 conflict/state, 413 too large, 429 rate limited (see `Retry-After`).
- Every response has `X-Request-Id`; quote it in bug reports.

## Auth `/api/auth`
| Method + path | Body | Result |
|---|---|---|
| POST `/register` | `{username, password, publicKey}` | 201 `{user}`; sets cookie |
| POST `/login` | `{username, password}` | `{user}`; 403 if suspended `{permanent, until}`; 429 lockout |
| GET `/me` | | `{user:{id,username,publicKey,isAdmin}}` |
| POST `/logout` | | revokes this session |
| POST `/logout-all` | | revokes every session |

## Users `/api/users`
| GET `/search?q=` | 2-24 chars `[a-z0-9_]` | `{users:[{id,username}]}` |
|---|---|---|
| GET `/:id/key` | | `{user:{id,username,publicKey}}` |
| PUT `/me/key` | `{publicKey, password}` | rotates key; flags your groups for rekey |
| DELETE `/me` | `{password}` | deletes the account and its data |

## Messages (1-to-1) `/api/messages` (sending is over the socket)
| GET `/` | | `{conversations:[{id,username}]}` |
|---|---|---|
| GET `/:userId?limit=` | | `{messages:[{id,from,to,ciphertext,iv,createdAt,expiresAt,burnAfterReadSeconds}]}` |
| DELETE `/item/:id` | | sender unsends for both |
| DELETE `/:userId` | | clears the chat for both |

## Sessions `/api/sessions`
| GET `/` | | `{sessions:[{id,device,createdAt,lastSeenAt,expiresAt,current}]}` |
|---|---|---|
| GET `/events` | | last 50 security events |
| DELETE `/:id` | | revoke one (cuts its sockets) |
| DELETE `/` | | revoke all others |

## Contacts `/api/contacts` and Blocks `/api/blocks`
| GET `/` | | list |
|---|---|---|
| POST `/` | `{userId}` | add / block (blocking also removes the contact) |
| DELETE `/:id` | | remove / unblock |

## Groups `/api/groups`
| GET `/` | | my groups `{id,name,role,epoch,needsRekey,memberCount}` |
|---|---|---|
| POST `/` | `{name, members[], envelopes[{userId,wrappedKey,iv}]}` | create; envelopes must cover exactly you + members |
| GET `/:id` | | group + members with public keys |
| PUT `/:id` | `{name}` | rename (admin) |
| POST `/:id/members` | `{userId, wrappedKey, iv}` | add (admin) |
| DELETE `/:id/members/:userId` | | remove (admin) -> group needs rekey |
| POST `/:id/leave` | | leave |
| PUT `/:id/members/:userId/role` | `{role: admin\|member}` | change role (admin) |
| POST `/:id/rekey` | `{fromEpoch, envelopes[]}` | new key epoch (admin); envelopes cover exactly the members |
| GET `/:id/keys` | | my wrapped keys, one per epoch |
| GET `/:id/messages?limit=&before=` | | history (only after you joined) |
| DELETE `/:id/messages/:messageId` | | sender or admin |

## Invites and join requests (`/api`)
| POST `/groups/:id/invites` | `{ttlSeconds 60-604800, maxUses 1-50}` | `{invite, token}`; token shown **once** (put it in the URL fragment `#`) |
|---|---|---|
| GET `/groups/:id/invites` / DELETE `.../:inviteId` | | list / revoke (admin) |
| POST `/invites/preview` | `{token}` | `{group:{name,memberCount}, alreadyMember}` |
| POST `/invites/redeem` | `{token}` | `{status: pending\|member, groupId}`; invalid links are all 404 |
| GET `/groups/:id/join-requests` | | requesters with public keys (admin) |
| POST `/groups/:id/join-requests/:userId/approve` | `{wrappedKey, iv}` | admin wraps the group key for them |
| DELETE `/groups/:id/join-requests/:userId` | | deny |

## Self-destruct rooms `/api/rooms`
| GET `/:id` | | `{room:{expiresAt, serverTime}}` |
|---|---|---|
| PUT `/:id/lifespan` | `{lifespanSeconds: 10..2592000 \| null}` | admin sets/clears |

## Files `/api/files` (ciphertext only; the file key travels inside an encrypted message)
| POST `/init` | `{kind: file\|voice, sizeBytes, recipientId \| groupId, ttlSeconds?}` | `{file:{id,expiresAt,uploadPath}}` |
|---|---|---|
| PUT `/:id/content` | raw bytes, `Content-Type: application/octet-stream`, exact size | `{ok}` |
| GET `/:id/link` | | `{url, expiresAt}` valid 60 s, bound to you |
| GET `/:id/download?e=&s=` | | the ciphertext |
| DELETE `/:id` | | owner (or group admin) |
Limits: file 25 MB, voice 10 MB, 500 MB per user.

## Settings `/api/settings`, Receipts `/api/receipts`
| GET/PUT `/api/settings` | `{showPresence?, showTyping?, readReceipts?, status?: available\|focus\|away}` | reciprocal privacy toggles |
|---|---|---|
| GET `/api/receipts/direct/:peerId` | | `{mine, theirs}` read-up-to times |
| GET `/api/receipts/group/:id` | | `{members:[{userId,lastReadAt}]}` |

## Reports `/api/reports`, Admin `/api/admin`
| POST `/api/reports` | `{type: user\|message\|group_message, targetUserId \| messageId, reason, note?, evidence?}` | 201; 409 duplicate |
|---|---|---|
| GET `/api/reports/mine` | | my reports and their status |
| GET `/api/admin/reports?status=&flagged=&before=&limit=` | | admin only (404 otherwise) |
| GET `/api/admin/reports/:id` | | evidence: server snapshot + reporter text (unverified) |
| POST `/api/admin/reports/:id/resolve` | `{status: actioned\|dismissed, note?}` | final |
| GET `/api/admin/users?q=` | | search with open-report counts |
| POST `/api/admin/users/:id/suspend` | `{durationSeconds: 60..31536000 \| null, reason, reportId?}` | `null` = permanent |
| DELETE `/api/admin/users/:id/suspension` | | lift |
| GET `/api/admin/actions` | | audit trail |

## Health
`GET /api/health` liveness. `GET /api/ready` readiness (503 if the database is down or shutting down).

## Realtime (Socket.IO)
Connect with `withCredentials: true`, **register listeners before connecting**.

**Client -> server** (all answer through the ack callback with `{ok}` or `{ok:false,error}`):
`message:send {to, ciphertext, iv, ttlSeconds?, burnAfterReadSeconds?}` | `group:send {groupId, epoch, ciphertext, iv, ttlSeconds?, burnAfterReadSeconds?}` | `message:read {id}` | `group:read {groupId, id}` | `typing:set {to|groupId, typing}` | `receipt:read {peerId, upTo}` | `receipt:group_read {groupId, upTo}` | `presence:sync`

**Server -> client:**
`message:new` | `message:deleted {id,from,to}` | `chat:cleared {a,b}` | `message:burning {id,from,to,expiresAt}` | `group:message` | `group:message:deleted {groupId,id}` | `group:burning {groupId,id,expiresAt}` | `group:updated {groupId,type,...}` | `group:removed {groupId}` | `group:joined {groupId}` | `group:join_request {groupId}` | `group:join_denied {groupId}` | `group:destroyed {groupId}` | `presence:snapshot {peers[]}` | `presence:update {userId,online,status}` | `typing:update {from,groupId?,typing}` | `receipt:read {by,upTo,readAt}` | `receipt:group_read {groupId,by,upTo,readAt}` | `account:suspended`

<!-- File: docs/API.md -->
<!-- End of file -->