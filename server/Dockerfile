# =============================================================================
# Project : Enoclave - private, end-to-end encrypted web chat
# File    : server/Dockerfile
# Purpose : Builds the production image of the API server. Two stages: the
#           first installs only production dependencies from the lockfile
#           (npm ci, reproducible); the second copies them with the source into
#           a small Alpine image, runs as the unprivileged "node" user (never
#           root), starts through tini so signals and zombie processes are
#           handled properly (graceful shutdown works), exposes port 5000, keeps
#           encrypted uploads in the /app/storage volume, and reports health via
#           /api/ready. Secrets are NEVER baked in: they arrive as environment
#           variables at run time (see docker-compose.yml and
#           .env.production.example). Build from the server folder:
#             docker build -t enoclave-api .
# =============================================================================
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
RUN apk add --no-cache tini && mkdir -p /app/storage && chown node:node /app/storage
COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src
COPY --chown=node:node scripts ./scripts
USER node
EXPOSE 5000
VOLUME ["/app/storage"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:5000/api/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "src/server.js"]

# File: server/Dockerfile
# End of file