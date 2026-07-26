---
# browserid-ng-8iz0
title: 'Guestbook demo v2: identity-first CLI wallet, no MCP install, no restart'
status: in-progress
type: feature
created_at: 2026-07-26T22:51:28Z
updated_at: 2026-07-26T22:51:28Z
---

From Dan's live demo log (~/browserid-guestbook-2026-07-26.md): the agent burned attempts on MCP install syntax, then hit the tools-only-after-restart wall. Changes:
- [ ] wallet CLI mode (npx -y @browserid-ng/wallet provision|identity|sign-guestbook|read-guestbook): same store as MCP, short-lived commands, pending-approval state persisted so re-running resumes — no MCP, no restart, timeout-proof
- [ ] identity-first flow: provision (name+address) before drafting, so the agent signs with its own name; sign-guestbook does the permission separately (Flow P card shows the name + message)
- [ ] guestbook page: agent steps rewritten around the CLI; exact claude mcp add -s user command + pitfalls in an optional MCP section; draft-and-show-human before posting
- [ ] consent.html: /device/issue fallback (fresh browser could not sign warrants — only account.html had it)
- [ ] guestbook sign: accepts legacy assertion field (published wallets have been silently 422ing — likely why the feed is empty); entry/response now carry BOTH names (actor grantee + attributed grantor)
- [ ] e2e validated locally: CLI + playwright through both real approval pages
