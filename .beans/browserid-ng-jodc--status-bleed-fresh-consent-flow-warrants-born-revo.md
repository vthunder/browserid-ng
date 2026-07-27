---
# browserid-ng-jodc
title: 'Status bleed: fresh consent-flow warrants born revoked + forged status-ref hardening'
status: completed
type: bug
priority: high
created_at: 2026-07-27T08:55:06Z
updated_at: 2026-07-27T08:55:06Z
---

Dan revoked all devices/warrants, provisioned a fresh agent, approved a new guestbook warrant — and the server reported the NEW warrant revoked. Root cause: warrant status indices are stable per (user, agent, audience, scopes); a re-approval reactivates the bit in the PROVISIONING flow (since 8v6c) but the CONSENT flow (/warrant/request → respond) never did, so a fresh warrant for a previously revoked subject was born revoked.

Fixes:
- [x] respond() reactivates each grant's allocated status index on approval
- [x] register_warrant reactivates a VERIFIED own-index ref
- [x] hardening found adjacent: nothing checked a signed warrant's embedded status ref against the server-allocated one — a forged index could arm the account's revoke lever (and verifiers) at a grant the signer doesn't own, cross-user. validate_grant_warrants now requires the ref to be exactly (our list URI, the grant's allocated index) whenever one was allocated; register_warrant only records/reactivates an index it can re-derive from the subject registry, else records none (row stays reviewable, lever disarmed)
- [x] regression test: approve → revoke → fresh approval of the same subject → NOT revoked; forged-index respond refused. Full broker+agent suites green (35 binaries).

Note: existing born-revoked warrants don't self-heal — one fresh approval of the same subject clears the bit.
