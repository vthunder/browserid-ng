---
# browserid-ng-8iz0
title: 'Guestbook demo v2: identity-first CLI wallet, no MCP install, no restart'
status: completed
type: feature
priority: normal
created_at: 2026-07-26T22:51:28Z
updated_at: 2026-07-26T22:54:12Z
---

From Dan's live demo log (~/browserid-guestbook-2026-07-26.md): the agent burned attempts on MCP install syntax, then hit the tools-only-after-restart wall. Changes:
- [x] wallet CLI mode (npx -y @browserid-ng/wallet provision|identity|sign-guestbook|read-guestbook): same store as MCP, short-lived commands, pending-approval state persisted so re-running resumes — no MCP, no restart, timeout-proof
- [x] identity-first flow: provision (name+address) before drafting, so the agent signs with its own name; sign-guestbook does the permission separately (Flow P card shows the name + message)
- [x] guestbook page: agent steps rewritten around the CLI; exact claude mcp add -s user command + pitfalls in an optional MCP section; draft-and-show-human before posting
- [x] consent.html: /device/issue fallback (fresh browser could not sign warrants — only account.html had it)
- [x] guestbook sign: accepts legacy assertion field (published wallets have been silently 422ing — likely why the feed is empty); entry/response now carry BOTH names (actor grantee + attributed grantor)
- [x] e2e validated locally: CLI + playwright through both real approval pages

## Summary of Changes

Shipped: broker CI green (consent /device/issue fallback, sign 'assertion' alias, two-name entries, CSP), www 1766826 live. E2E proof against a local broker: fresh account → CLI provision (APPROVE_URL relayed, command exits) → browser I1 → I2 (name prefilled 'Quill') → I3 Meet → re-run picks up the identity → sign-guestbook → consent P card renders 'Quill wants permission.' + quoted message + on-behalf dropdown → approve → re-run signs → feed entry shows '+quill for base', both names.

BLOCKING for the live demo: @browserid-ng/wallet 0.4.0 must be npm-published — the page's npx commands need the CLI; the published 0.3.x has no argv handling and would start the MCP server and hang.
