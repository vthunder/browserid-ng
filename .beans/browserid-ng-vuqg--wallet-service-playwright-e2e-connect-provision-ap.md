---
# browserid-ng-vuqg
title: 'wallet-service: Playwright e2e (connect → provision → approve → guestbook)'
status: todo
type: task
created_at: 2026-07-29T09:17:46Z
updated_at: 2026-07-29T09:17:46Z
---

Design doc MVP item 6 (docs/plans/2026-07-29-hosted-wallet-remote-mcp-design.md §12), deferred from the MVP build (browserid-ng-xeyv). Drive the full flow against a local broker + wallet-service: OAuth connect (DCR + PKCE), MCP provision tool, approve at the broker consent page, sign the guestbook. Add to e2e-tests/ alongside the existing Playwright suite.
