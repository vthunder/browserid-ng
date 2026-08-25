---
# browserid-ng-vwju
title: 'Connection-lane leftovers: service-class identities + per-mint status-snapshot retention'
status: todo
type: task
priority: normal
created_at: 2026-08-25T19:16:55Z
updated_at: 2026-08-25T19:17:11Z
---

The two deferred items from the connection-warrants work (bean rjmm, closed 2026-08-25), split out so rjmm could close:

- [ ] Per-mint status-snapshot retention — spec §6.4 SHOULD: the embedded AS retains the status-list snapshot backing each bearer mint, so a disputed admission audits as record + config cert + signed snapshot. Needs /validate-record to return the snapshot tokens, then mcp-auth stores them per mint. Small.
- [ ] Service-class identities — infra credentials in the agent lane still read as personal subaddresses (danmills+mcp-demo2). NOTE: the motivating UX ('danmills+mcp-demo2 wants permission' on the consent card) was eliminated by connection records themselves, so this is now cosmetic hygiene for Lane A only — consider SCRAPPING rather than building; decide before investing.
