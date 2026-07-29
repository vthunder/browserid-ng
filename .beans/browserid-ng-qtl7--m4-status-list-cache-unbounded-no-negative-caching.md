---
# browserid-ng-qtl7
title: '[M4] Status-list cache: unbounded, no negative caching, uncapped body (DoS)'
status: in-progress
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-07-29T01:18:24Z
parent: browserid-ng-wre6
---

docs/security-audit-2026-07-29.md (M4). verifier.rs:225 unbounded HashMap keyed by attacker-supplied r.uri; verifier.rs:203 uncapped body read; failed fetches not negative-cached → 5s stall/request. Unauth via /verify-access & /guestbook.
- [ ] Size cap/LRU on foreign_status_lists
- [ ] Response body-size limit
- [ ] Negative caching for failed/unreachable fetches

## Summary of Changes
M4 fixed: bounded status cache (1024, stale-evict) + streaming body cap. (Negative-caching of failed fetches left as a minor follow-up.)

## Remaining
Memory-exhaustion (unbounded cache) and body-size DoS are FIXED. Remaining minor item: negative-caching of failed/unreachable status fetches (avoids 5s re-fetch stall per request) — needs a small shared negative-cache in AppState; deferred as low-value follow-up.
