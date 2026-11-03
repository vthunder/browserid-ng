# browserid-ng hosted wallet — build from the REPO ROOT so the file: SDK deps
# resolve:  docker build -f wallet-service/Dockerfile -t wallet-service .
# Base image pinned by digest (audit 2026-11 W7-7): the tag names the
# version a human chose, the digest makes the build reproducible. Bump by
# re-resolving the tag (multi-arch manifest list, 2026-11-03).
FROM node:24-bookworm-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c

WORKDIR /app

# The two monorepo SDKs the service depends on via file: links.
COPY sdk/agent sdk/agent
COPY sdk/js sdk/js

COPY wallet-service/package.json wallet-service/package-lock.json wallet-service/
WORKDIR /app/wallet-service
RUN npm ci --omit=dev

COPY wallet-service/src src

ENV NODE_ENV=production WALLET_ENV=production PORT=3100 \
    WALLET_DATABASE_PATH=/data/wallet.db
# Persist /data (dokku: storage:mount browserid-wallet /var/lib/dokku/data/storage/browserid-wallet:/data)
VOLUME /data
EXPOSE 3100

CMD ["node", "src/server.mjs"]
