<!-- =========================================================================
Project : Enoclave - private, end-to-end encrypted web chat
File    : README.md
Purpose : The front page of the repository. Explains what Enoclave is, how the
          code is organised, how to run it locally, how to run the automated
          tests, where the API reference and deployment guide live, what the
          security design is, and - just as important - what it does NOT
          protect against, so nobody markets it as "unbreakable".
========================================================================== -->
# Enoclave

A private, end-to-end encrypted web chat. No phone number, no email: just a username and a passphrase.

## Features
- 1-to-1 and group chat, encrypted in the browser (ECDH P-256 + HKDF + AES-256-GCM); the server stores ciphertext only
- Disappearing messages, burn-on-read, self-destruct rooms
- Encrypted files and voice notes (ciphertext only on disk, 60-second signed download links)
- Contacts, blocking, invite links with admin approval, device/session management
- Presence, typing and read receipts with reciprocal privacy toggles
- Reporting and moderation with an audit trail and anti-brigading

## Structure
- `server/` Node 20+ / Express / Socket.IO / PostgreSQL (Neon). Routes, socket handlers, jobs and migrations are auto-loaded from their folders.
- `client/` React + Vite (built after the API is stable)
- `docs/API.md` full HTTP and realtime reference, `docs/DEPLOY.md` production guide

## Run locally
1. Create `server/.env` (see `server/.env.example`).
2. `cd server` then `npm run dev` (API on http://localhost:5000)
3. `cd client` then `npm run dev` (app on http://localhost:5173)

## Tests
Start the server with `$env:TEST_MODE='1'; npm run dev`, then in `server/` run `npm test`.

## Security design
- Passphrases hashed with bcrypt (cost 12); generic login errors; brute-force lockout; session-bound JWT in an httpOnly, SameSite=Strict cookie
- Strict input validation (zod, unknown fields rejected), Helmet + CSP, CORS locked to one origin, Origin check on writes, layered rate limits
- Private keys are non-extractable and stay on the device; the server never sees keys or plaintext
- Audit logs store only a keyed hash of the network address; request logs contain no IPs or query strings
- Moderation: admins are set only via a database-access script; every action is audited

## Known limitations (do not market as "unbreakable")
- No forward secrecy yet (static keys); a Double Ratchet is the next cryptographic milestone
- The server could swap public keys: users should compare the Safety Number out of band
- The server still sees metadata: who talks to whom, group membership, and when
- Keys are per browser: a new device gets new keys and cannot read old messages
- Reports of message content rely on what the reporter chooses to show; the server can only verify sender, time and ciphertext
- Unsend and clear-chat cannot remove screenshots or copies the other person already made
- Presence assumes a single server process; file storage is local disk (or a mounted volume)

<!-- File: README.md -->
<!-- End of file -->