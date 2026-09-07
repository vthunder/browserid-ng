---
# browserid-ng-xmqm
title: 'registry-api-v1: registry-local ''retired'' mark for certs the registry cannot bit-revoke (review A2)'
status: completed
type: task
priority: high
created_at: 2026-09-06T11:08:57Z
updated_at: 2026-09-06T19:56:47Z
parent: browserid-ng-0c49
---

From the 2026-09-06 adversarial review (security H2, coherence 11). Dan agrees with the issue, unsure of the fix; discuss separately.

ISSUE: core makes the `status` ref OPTIONAL on device certs, and devices/revoke on a foreign issuer's cert only "hides" it. So a ref-less or foreign cert passes the §7.1 validity bar after revoke, leave, or holder move, and a stolen laptop cert for a transferred identity can keep write on it.

r5 already introduces a registry-local `suspended` mark (identity leaves an account, §4.4) that fails the session member check regardless of issuer. This bean generalizes it:
- [ ] Decide: one local mark (`retired`) set by devices/revoke, holders/move, holders/forget, leave/suspend — fails the member check, reason `cert_retired`
- [ ] Session identities and tiers recomputed on every call from certs that are recorded, not retired/suspended, and whose identity is currently on the account (spec §4.2)
- [ ] Multi-identity certs: recorded once per listed identity (already in §5.6.1 r5); confirm revoke semantics per identity
- [ ] Update §7.1 and invariant 3

## Summary of Changes

Settled with Dan 2026-09-06 and applied to registry-api-v1 r5: a recorded cert is RETIRED when the account revokes it (own or foreign issuer), its holder is moved/forgotten, or it is dropped from the device list; retired keys can never open a session (401 invalid_cert/cert_retired) or act in one (dropped as a member). §4.2, §5.4, invariant 3. The single exception, deliberately: a retired or revoked recorded key still proves 'I am the account that recorded me' for the attach RESTORE row (§5.6.1 `recorded` proofs), which is what lets a previous holder whose IdP correctly revoked their certs challenge a takeover.
