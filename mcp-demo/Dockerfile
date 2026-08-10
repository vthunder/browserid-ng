# browserid-ng MCP-auth demo — build from the REPO ROOT (like guestbook-mcp):
#   docker build -f mcp-demo/Dockerfile -t mcp-demo .
# It bundles the local @browserid-ng/mcp-auth package (a file: dependency), so
# the build context must include sdk/mcp-auth.
FROM node:24-bookworm-slim

WORKDIR /app

# The local file: dependency must be present before `npm ci` resolves it.
COPY sdk/mcp-auth ./sdk/mcp-auth

WORKDIR /app/mcp-demo
COPY mcp-demo/package.json mcp-demo/package-lock.json ./
RUN npm ci --omit=dev

COPY mcp-demo/src src

ENV NODE_ENV=production PORT=3300
EXPOSE 3300

CMD ["node", "src/server.mjs"]
