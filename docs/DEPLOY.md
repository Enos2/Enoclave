<!-- =========================================================================
Project : Enoclave - private, end-to-end encrypted web chat
File    : docs/DEPLOY.md
Purpose : Step-by-step production deployment guide for the API: what you need,
          how to configure it, how to start it with Docker, how to put HTTPS
          and WebSockets in front of it with Caddy, how to create the first
          admin, how to back it up, what the current scaling limits are, and a
          pre-launch checklist.
========================================================================== -->
# Deploying Enoclave

## You need
- A Linux server with Docker and Docker Compose
- A Neon PostgreSQL database (copy its connection string; use `sslmode=verify-full`)
- Two hostnames on the **same site**, e.g. `app.example.com` (web app) and `api.example.com` (API). The login cookie is `SameSite=Strict`, so a different registrable domain will not work.

## 1. Configure
```bash
cp server/.env.production.example server/.env.production
# edit it: DATABASE_URL, a fresh JWT_SECRET, CLIENT_ORIGIN=https://app.example.com
```

## 2. Start
```bash
docker compose up -d --build
docker compose logs -f api        # look for "server listening"
```
Migrations run automatically on start. Health: `curl http://127.0.0.1:5000/api/ready`.

## 3. HTTPS with Caddy (automatic certificates, WebSockets work out of the box)

api.example.com {
reverse_proxy 127.0.0.1:5000
}

Keep `TRUST_PROXY=1` (one proxy in front).

## 4. First admin
Register in the app, then:
```bash
docker compose exec api node scripts/make-admin.mjs yourusername
```

## Backups
- Database: use Neon's point-in-time restore / branches.
- Uploaded files: back up the `enoclave_storage` volume (they are encrypted; the keys are not on the server).

## Current limits (by design, for a single server)
- Presence tracking and per-socket limits live in memory: run **one** API instance. Several instances need Redis plus the Socket.IO Redis adapter.
- Uploads use local disk. For multiple servers, swap `src/utils/storage.js` for object storage (S3).

## Pre-launch checklist
- [ ] `JWT_SECRET` is random and not reused anywhere else
- [ ] `NODE_ENV=production`, `TEST_MODE` unset
- [ ] `CLIENT_ORIGIN` is the exact https origin
- [ ] Neon connection uses `sslmode=verify-full`
- [ ] Port 5000 is NOT exposed publicly (only 127.0.0.1)
- [ ] Caddy/nginx serves HTTPS only
- [ ] First admin created; `npm test` passed against a staging copy
- [ ] Backups verified by restoring once

<!-- File: docs/DEPLOY.md -->
<!-- End of file -->