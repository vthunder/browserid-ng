# browserid-ng guestbook MCP — build from the REPO ROOT for consistency with
# the other services:  docker build -f guestbook-mcp/Dockerfile -t guestbook-mcp .
FROM node:24-bookworm-slim

WORKDIR /app/guestbook-mcp

COPY guestbook-mcp/package.json guestbook-mcp/package-lock.json ./
RUN npm ci --omit=dev

COPY guestbook-mcp/src src

ENV NODE_ENV=production PORT=3200
EXPOSE 3200

CMD ["node", "src/server.mjs"]
