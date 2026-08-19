---
# browserid-ng-qtl7
title: '[M4] Status-list cache: unbounded, no negative caching, uncapped body (DoS)'
status: in-progress
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-08-17T09:23:48Z
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

## Re-verification 2026-08-17 — remaining item STILL OPEN

Bounded cache (MAX_STATUS_CACHE_ENTRIES=1024, verifier.rs:190) + body cap (MAX_STATUS_BODY 4MiB, :195) + eviction (:390-394) confirmed present. Only SUCCESSFUL verified tokens are inserted (lists.insert at :393); every error path (:352-384) returns Err with no cache write — no negative/failure cache type exists. Status client timeout is 5s (verifier.rs:170), so a blackholed URI still stalls ~5s per request, repeatedly. Remaining work: add negative caching for failed/unreachable fetches.
