---
# browserid-ng-0c49
title: Build registry-api-v1 §5.6 account membership (attach/detach/transfer cascade)
status: todo
type: feature
priority: normal
created_at: 2026-08-30T18:01:42Z
updated_at: 2026-08-30T18:01:50Z
parent: browserid-ng-9yyk
blocked_by:
    - browserid-ng-a93p
---

THE RESUME POINTER for the account-membership thread (Dan asked 2026-08-30). Spec is SETTLED — registry-api-v1 §5.6 (synchronous attach/detach with inline browserid-membership-v1 records, transfer-on-proof with loser notification, revoke-and-drop of derived agent children) + §7.1 reasons + §10.8 decision log; design history and parity table live on bean 1sb3; reset-channel mitigations are bean dksx (explore separately).

Implementation checklist:
- [ ] Registrar: POST /api/v1/account/attach + /api/v1/account/detach; membership-record validation (config-cert bar, grantor ownership, subject match, ≤300s window, jti replay cache)
- [ ] Transfer cascade (shared core): hg2j-scoped cert revocation at the loser + grantor-warrant revocation + derived-agent revoke-and-drop (this also FIXES a93p for the shipped cookie transfer arms — wire them through the same core) + kind:'notice' inbox item + out-of-band notify SHOULD + emptied-account deletion
- [ ] Host/store capabilities: identity ownership moves, agent-children enumeration, notice items in the inbox shape (§5.1)
- [ ] Wallet: bootstrap flow gains 'add to existing account' — when the wallet already holds an anchor, second-identity bootstrap calls attach instead of letting the token exchange mint a parallel account; sign the membership record with the anchor config key
- [ ] Dialog/account page: per Dan's Q6 ruling the account-page email UI invokes the WALLET which talks to the registry — sequence with 71vt (blocked on 71vt's account/consent routing decision landing as implementation)
- [ ] Deployment note dksx-lite: ensure registry-attached rows don't silently join the reset-eligible set (full mitigation design in dksx)
- [ ] Tests: registry_api_test coverage for attach/detach/transfer incl. record replay, last_identity, agent-children cascade, no-existence-leak; SqliteStore test for the membership moves (memory-store rule)

Blocked-by: nothing hard; touches a93p (fixes it). Related: 71vt (surface retirement), dksx (reset hardening), 1sb3 (design record).
