---
# browserid-ng-kp0a
title: 'Guestbook MCP: Level 1 reference service + AUTH_REQUIRED error contract'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-29T17:15:33Z
updated_at: 2026-07-29T17:19:15Z
---

Standalone authless remote MCP server (guestbook-mcp/) implementing the Level 1 'typed veneer' pattern from docs/design/browserid-enabled-apis.md over the existing browserid.me/guestbook API. v1 uses per-call presentation. Centerpiece: the AUTH_REQUIRED error payload optimized so an agent WITHOUT the wallet connector guides the user to install it (wallet MCP URL: https://wallet.browserid.me/mcp). Demo test: uninstall wallet connector, call guestbook MCP, verify the agent relays install instructions.

- [x] Spec the AUTH_REQUIRED error contract in the design doc
- [x] guestbook-mcp service (server, tools, config)
- [x] Tests (missing presentation -> AUTH_REQUIRED; forward to mocked guestbook API; feed) — 8 passing
- [x] Dockerfile + deploy-guestbook.yml workflow (dokku one-time setup documented)
- [ ] Live test on claude.ai: error -> install flow; iterate on error copy

## Status

Built, tests green, boots locally. Remaining before the live test: commit+push, one-time dokku setup on the host (runbook in .github/workflows/deploy-guestbook.yml header: apps:create guestbook-mcp, builder/domains/ports/config, DNS for guestbook-mcp.browserid.me, letsencrypt, make ghcr package public), then add https://guestbook-mcp.browserid.me/mcp as a custom connector with the wallet uninstalled and iterate on authRequired() copy in guestbook-mcp/src/mcp.mjs.
