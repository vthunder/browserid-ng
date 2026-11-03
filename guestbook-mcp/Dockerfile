# browserid-ng guestbook MCP — build from the REPO ROOT for consistency with
# the other services:  docker build -f guestbook-mcp/Dockerfile -t guestbook-mcp .
# Base image pinned by digest (audit 2026-11 W7-7): the tag names the
# version a human chose, the digest makes the build reproducible. Bump by
# re-resolving the tag (multi-arch manifest list, 2026-11-03).
FROM node:24-bookworm-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c

WORKDIR /app/guestbook-mcp

COPY guestbook-mcp/package.json guestbook-mcp/package-lock.json ./
RUN npm ci --omit=dev

COPY guestbook-mcp/src src

ENV NODE_ENV=production PORT=3200
EXPOSE 3200

CMD ["node", "src/server.mjs"]
