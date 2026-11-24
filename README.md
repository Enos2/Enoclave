<!-- File: README.md -->
<!-- Purpose: Project overview, setup steps and honest security notes for Enoclave. -->
# Enoclave

A private, end-to-end encrypted web chat. No phone number or email required.

## Run locally
1. Start MongoDB.
2. `cd server && npm run dev` (API on http://localhost:5000)
3. `cd client && npm run dev` (app on http://localhost:5173)

## Security design
- Passwords hashed with bcrypt (cost 12). Login errors are generic and timing-equalised.
- Session is a JWT in an httpOnly, SameSite=Strict cookie (Secure in production).
- Strict input validation (zod), Helmet headers, CORS locked to one origin, Origin checks on writes and sockets, rate limits.
- Messages are encrypted in the browser (ECDH P-256 + HKDF + AES-256-GCM). The server stores only ciphertext.
- Private keys are non-extractable and live in IndexedDB on the device.
- Optional self-destruct: the server deletes expired messages via a MongoDB TTL index.

## Known limitations (do not market as "unbreakable")
- No forward secrecy yet (static keys). Next step: Double Ratchet / Signal protocol.
- The server could swap public keys; compare the Safety Number with your contact to detect this.
- The server still sees metadata: who talks to whom, and when.
- Keys are per browser. A new device creates new keys, so old messages are unreadable there.
- Set a strict Content-Security-Policy header on your production host.
<!-- File: README.md -->
<!-- End of file -->
