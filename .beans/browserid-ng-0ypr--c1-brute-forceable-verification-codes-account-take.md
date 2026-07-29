---
# browserid-ng-0ypr
title: '[C1] Brute-forceable verification codes → account takeover'
status: completed
type: bug
priority: critical
created_at: 2026-07-28T23:53:20Z
updated_at: 2026-07-29T01:18:04Z
parent: browserid-ng-wre6
---

Full detail in docs/security-audit-2026-07-29.md (C1). complete_reset (broker/routes/reset.rs:114) resolves pending records by 6-digit code alone (sqlite.rs:986 WHERE secret=?1) and NEVER burns the code on a wrong guess (deletes only on expiry/success). 900k code space, 15-min window, NO per-IP/per-account/per-attempt throttle anywhere (only EmailRateLimited on the send side). Unauthenticated attacker + known email (enumeration is free) can spray reset completion and take over the account. Same unthrottled pattern in complete_user_creation (account.rs:115) and complete_email_addition (email.rs:266). fallback_idp.rs:60 already burns after 5 attempts — bring the wsapi path to parity.

- [ ] Burn pending record (or attempt counter ≤5) on each failed guess, all three completion endpoints
- [ ] Add per-IP throttle on completion endpoints
- [ ] Consider longer reset codes

## Summary of Changes
C1 fixed: code_guard binds completion to email + burns pending record after 5 wrong tries (all 3 complete_* endpoints). Unit + integration tests green.
