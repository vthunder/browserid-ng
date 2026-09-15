---
# browserid-ng-0vdu
title: 'Account authentication policy: add-a-device bar (password | 2 proofs | approval), login key as device credential for registry + fallback IdP, policy as data'
status: draft
type: epic
priority: high
created_at: 2026-09-14T20:25:25Z
updated_at: 2026-09-15T00:12:21Z
parent: browserid-ng-9yyk
---

Design in docs/plans/2026-09-14-account-authentication-policy-draft.md (review draft for Dan). Rulings so far (2026-09-12..14): password stays special (only proof that mints broker-vouched identities); add a device = password | two identity proofs | approval from enrolled device, and that one step also logs in the registry; enrolled login key suffices for the fallback IdP to re-issue SMTP/agent certs (co-location); bridged identities always re-prove live at the bridge; requirements configurable per account and later dynamic (signals), evaluated at registry enrol + authorize_mint. Reset is a separate later pass.

- [ ] Dan reviews the draft
- [ ] Spec changes (registry-api §4.2/§5.2.3, fallback-idp §3 co-location)
- [x] Reset folded into the draft (2026-09-14): k = min(2,n) proofs, approval never; sets password only on completion; unverify unproven mailboxes, suspend agents, revoke all login keys

Review decisions 2026-09-14: password is the account's own credential, not an identity proof; approval-enrolled keys may approve once the device has proven one identity (no timer); masked addresses as hints after one proof. Draft has mermaid diagrams (roles, device state machine, two add-device sequences, reset sequence).

## Build order (2026-09-15)
1. noqd policy engine + enrolled_by + spec edits (blocks everything)
2. browserid-ng-puo8 device approval (the phone flow) and browserid-ng-73ok co-location (one ceremony on a new device) — independent, both high
3. browserid-ng-d26p identity proofs as a login method (needs e98a: mediator in the embedded window)
4. browserid-ng-yz4y reset as a multi-proof ceremony (needs browserid-ng-d26p's proof collection)
5. svs7 account page policy editor + devices list
