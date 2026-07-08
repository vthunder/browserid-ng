---
# browserid-ng-51qa
title: Docs & ergonomics gaps from review
status: todo
type: task
priority: normal
created_at: 2026-07-08T06:14:02Z
updated_at: 2026-07-08T06:14:02Z
parent: browserid-ng-8u60
---

Documentation/ergonomics items from the 2026-07-08 review.

- [ ] RP audience is exact string match (verifier.rs:238) with a bare 'Audience mismatch' error. Document the exact expected origin format (scheme+host+port, no path/trailing slash) or normalize server-side.
- [ ] No worked example for a third-party IdP integrating (DNS record format, key format, what authority delegation buys them). DNS TXT format only lives in a dns.rs code comment.
- [ ] SBO design doc describes 'Custody hardening' and 'revoke by signing out' that the code doesn't implement — reconcile doc with code (see e2fi, 3mek).
- [ ] README stale: says '60 tests', describes only the fallback-IdP model; no mention of DNSSEC primaries or SBO typed signing.
