---
# browserid-ng-kp0a
title: 'Guestbook MCP: Level 1 reference service + AUTH_REQUIRED error contract'
status: completed
type: feature
priority: normal
created_at: 2026-07-29T17:15:33Z
updated_at: 2026-07-29T18:04:46Z
---

Standalone authless remote MCP server (guestbook-mcp/) implementing the Level 1 'typed veneer' pattern from docs/design/browserid-enabled-apis.md over the existing browserid.me/guestbook API. v1 uses per-call presentation. Centerpiece: the AUTH_REQUIRED error payload optimized so an agent WITHOUT the wallet connector guides the user to install it (wallet MCP URL: https://wallet.browserid.me/mcp). Demo test: uninstall wallet connector, call guestbook MCP, verify the agent relays install instructions.

- [x] Spec the AUTH_REQUIRED error contract in the design doc
- [x] guestbook-mcp service (server, tools, config)
- [x] Tests (missing presentation -> AUTH_REQUIRED; forward to mocked guestbook API; feed) — 8 passing
- [x] Dockerfile + deploy-guestbook.yml workflow (dokku one-time setup documented)
- [x] Live test on claude.ai: error -> install flow — worked first try, no copy changes needed

## Status

Built, tests green, boots locally. Remaining before the live test: commit+push, one-time dokku setup on the host (runbook in .github/workflows/deploy-guestbook.yml header: apps:create guestbook-mcp, builder/domains/ports/config, DNS for guestbook-mcp.browserid.me, letsencrypt, make ghcr package public), then add https://guestbook-mcp.browserid.me/mcp as a custom connector with the wallet uninstalled and iterate on authRequired() copy in guestbook-mcp/src/mcp.mjs.

## Deployed 2026-07-29

Live at https://guestbook-mcp.browserid.me/mcp — dokku app created, CI deploy green (b943e0d), DNS added by Dan, letsencrypt enabled, AUTH_REQUIRED verified over HTTPS in production. ghcr package was already publicly pullable, no visibility step needed. Remaining: the claude.ai live test (wallet uninstalled) and error-copy iteration.

## Summary of Changes

Built, deployed (https://guestbook-mcp.browserid.me/mcp), and live-tested. The AUTH_REQUIRED flow worked end-to-end on claude.ai with the wallet disconnected: the agent relayed the verbatim install instruction, the human reconnected the wallet, the agent retried and signed successfully. No refusal, no dead end — error copy kept as-is.

Live test surfaced two follow-ups:
1. read_guestbook rendered 'undefined, for undefined' — the public feed shape is {at, domain, message, name, scopes}, not {agent, parent}. Fixed in guestbook-mcp AND wallet-service (same bug, copied from the same source). Tests updated to the real shape.
2. Public display name surprise: the guestbook published the pairing-time device label ('Claude.ai (web)') as the public byline — the human thought of that name as internal. Design issue tracked in a separate bean.
