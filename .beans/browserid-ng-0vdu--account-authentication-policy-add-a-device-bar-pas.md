---
# browserid-ng-0vdu
title: 'Account authentication policy: add-a-device bar (password | 2 proofs | approval), login key as device credential for registry + fallback IdP, policy as data'
status: draft
type: epic
priority: high
created_at: 2026-09-14T20:25:25Z
updated_at: 2026-09-15T07:40:38Z
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

## Status 2026-09-15

All six build beans completed and deployed to browserid.me (commits eabbc6f, a9ae7fc, 924b106, cd7df48, 2e515db; schema 43→46). Left open for a follow-up: native approvals of inbox requests (e98a's first item); Playwright coverage of the dialog's two-identity proofs chooser (needs a non-password second identity); the dialog's mid-flow sign-in for a missing identity is opportunistic (finishes on a later sign-in with it). Dan to try in prod: phone-joins-by-approval, a bridged sign-in enrolling this browser without the login page, the policy editor.

2026-09-15 live test (Dan): a primary sign-in in a fresh browser blocked on the dialog's proofs screen with the issuer popup held open. Ruling: the add-a-device bar is PART of the sign-in — the dialog's enrol screen (code for a signed-in device, or the password; missing addresses named); cancel or an unreachable registry fails the sign-in and drops the fresh certs. Shipped in caad2be. Follow-up: Playwright cannot reach the enrol screen (every e2e sign-in has a broker password; the mock primary signs no real certs) — needs a mock primary that issues verifiable device certs.
