---
# browserid-ng-nlj8
title: '[M3] No verifier-side ceiling on foreign status-list ttl'
status: completed
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-07-29T01:18:04Z
parent: browserid-ng-wre6
---

docs/security-audit-2026-07-29.md (M3). core/status.rs:190 is_fresh trusts issuer-declared ttl with no clamp; a malicious issuer signs ttl=years → cached all-clear list authoritative for the process lifetime, defeating revocation.
- [ ] Clamp foreign ttl to a max (e.g. reference 5-min window)

## Summary of Changes
M3 fixed: is_fresh_capped(5min) ceiling on foreign status ttl.
