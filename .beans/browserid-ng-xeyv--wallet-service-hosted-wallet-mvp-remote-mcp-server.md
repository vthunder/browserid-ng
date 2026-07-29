---
# browserid-ng-xeyv
title: 'wallet-service: hosted wallet MVP (remote MCP server)'
status: completed
type: feature
priority: normal
created_at: 2026-07-29T08:51:50Z
updated_at: 2026-07-29T09:32:05Z
---

Implement the MVP cut from docs/plans/2026-07-29-hosted-wallet-remote-mcp-design.md (design bean browserid-ng-83ab).

- [x] Scaffold wallet-service/ (Node, reuses sdk/agent, SQLite)
- [x] Tenant store + custody: per-tenant Ed25519 seed, AES-256-GCM envelope with env KEK, KeyWrapper seam
- [x] OAuth AS+RS: RFC 9728/8414 discovery, /authorize (browserid sign-in), /token (PKCE S256, RFC 8707 resource binding, RFC 9207 iss), DCR + pre-registered clients, rotating refresh tokens
- [x] MCP streamable-HTTP server with local-wallet tool surface (provision, identity, authorize, get_assertion, warrants, drop_grant, forget, guestbook demo)
- [x] Audit log write path (mint/assert/warrant-request/admin per tenant)
- [x] Unit tests (node --test) green
- [x] Deploy notes (dokku app wallet.browserid.me)

## Summary of Changes

New top-level `wallet-service/` (Node >=22.5, zero native deps: node:http + node:sqlite):
- `src/config.mjs` — env config; production refuses dev-fallback secrets; dev generates KEK/session secrets as 0600 files.
- `src/custody.mjs` — EnvKeyWrapper (AES-256-GCM envelope, KeyWrapper seam for KMS).
- `src/db.mjs` — schema: accounts, agents (encrypted credential), grants, oauth_clients/codes/tokens (hashed), audit_log.
- `src/store.mjs` — tenant store; only module touching plaintext credentials; DeviceAgent cache so access certs survive across calls.
- `src/oauth.mjs` — OAuth 2.1 AS+RS: RFC 9728/8414 discovery, DCR (7591), PKCE S256 only, resource binding (8707), iss (9207), rotating refresh tokens with reuse->burn-family, code replay->burn tokens. CIMD deliberately deferred (SSRF surface).
- `src/mcp.mjs` — per-tenant port of sdk/wallet tool surface (9 tools, same prompts), module-level pending-approval state keyed by tenant, 20s bounded waits, audit on every op.
- `src/pages.mjs` — authorize page (browserid sign-in via include.js + connect approval) and landing page.
- `src/server.mjs` — router, rate limits, bearer RS auth with WWW-Authenticate resource_metadata, stateless StreamableHTTPServerTransport (JSON response mode).
- Tests: 20 passing (custody, full OAuth flow over HTTP, MCP surface + tenant isolation + audit rows).
- `Dockerfile` (build from repo root for file: SDK deps) + README with dokku deploy notes.

Deferred (offer follow-up beans): Playwright e2e against a local broker, actual dokku deploy + CI workflow, account/audit UI, named multi-agent tenancy, KMS KeyWrapper.

## Deployed 2026-07-29

Live at https://wallet.browserid.me (dokku app browserid-wallet on sandmill.org — the name 'wallet' was taken by an unrelated app at wallet.sandmill.org). CI deploy-wallet.yml builds wallet-service/Dockerfile from repo root -> GHCR ghcr.io/vthunder/browserid-ng/wallet -> git:from-image. First deploy succeeded first try (GHCR package defaulted public). Let's Encrypt enabled; HTTPS smoke test green: /healthz, RFC 9728 + 8414 discovery, /mcp 401 + resource_metadata handshake. Secrets (WALLET_KEK, WALLET_SESSION_SECRET) generated and set via config:set without echoing values.
