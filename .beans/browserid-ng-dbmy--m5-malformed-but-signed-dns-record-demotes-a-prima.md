---
# browserid-ng-dbmy
title: '[M5] Malformed-but-signed DNS record demotes a primary IdP to fallback'
status: completed
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-07-29T01:18:04Z
parent: browserid-ng-wre6
---

docs/security-audit-2026-07-29.md (M5). dns_fetcher.rs:273 downgrades a corrupt-but-signed _browserid record (or extra TXT RR; :245 first-match-break) to secure_nxdomain → broker fallback → is_primary:false; primary's own presentations rejected as 'not an accepted fallback'.
- [ ] Treat malformed-but-signed record as Bogus (hard reject), not NXDOMAIN
- [ ] Reject/deterministically handle multiple _browserid TXT records

## Summary of Changes
M5 fixed: malformed-but-signed / multi-record _browserid hard-reject (Bogus); scan filters to v=browserid record. Regression tests added.
