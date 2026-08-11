---
# browserid-ng-4vu7
title: 'Managed identities: implementation (spec §4.7)'
status: completed
type: epic
priority: normal
created_at: 2026-08-11T12:29:56Z
updated_at: 2026-08-11T14:15:09Z
---

Implement cert constraints + managed marker per spec §4.7/§6.1/§7.2 (beans dbmw = spec work). Sequencing: verifiers first (constraints bind only at enforcing verifiers), then issuance/tenant policy, then client UX, then positioning.

## Build progress (2026-08-11)

Phase 1 (x0wx) DONE: core Constraints/AudConstraint types (+ unknown-key
capture), managed marker, AccessRequest.audience (+create_for_audience),
enforcement in AccessPresentation::verify (step 7, both presented certs).
9 new core tests, golden vectors unchanged (consumer wire identical).

Phase 2 (790g) DONE: ManagementPolicy model + tenants.management JSON column
(migration v25) + set_tenant_management/tenant_status_revoke_all (sqlite,
memory, forwarding); hosted idp_device_cert stamps managed:true; mint applies
current policy (broad allowlist / per-audience scoping, early "not permitted"
+ "audience required" refusals); admin endpoints GET/POST
/wsapi/tenant/management with revoke-on-enable; domains.js policy panel.
2 new hosted_primary integration tests pass.

Phase 3 (vy1a) DONE: dialog.js — audience in access request only when device
cert marked, managed-identity disclosure (confirm, once per identity) before
storeDevicePair, mismatch-rule warning; sdk/agent — per-audience access-cert
cache + audience in request when managed (2 new tests); browserid-agent (Rust)
— same per-audience cache, mint(audience) signature.

Phase 4 (fgop) DONE (page edits): marketing/domains.html lede re-centered on
govern/offboard + new "Managed identities" section with offboard-cascade story.

Pending: full broker suite (running), commit, deploy broker+www, mingo pin
bump + deploy, verify prod.

## Deploy status (2026-08-11)

- broker (id), www, wallet released to browserid.me host at a04ddf7; verified:
  /wsapi/tenant/management live (401 auth-gated), /dialog/dialog.js +
  /common/js/domains.js carry the new code, /domains page has the managed
  section, verify-access healthy.
- mingo: pin bumped to a04ddf7 (commit e12eb60), tests green (70), deploy
  re-running after a stale deploy lock (first push hit a 10m timeout;
  apps:unlock cleared it).
- Still open under this epic: SBO on-chain verifier conformance audit for
  §6.1 step 7 (constraints) — separate repo.

## Summary of Changes

All four phases built, tested, and deployed:
- browserid-ng a04ddf7: verifier enforcement (core), tenant policy + mint
  stamping + admin console (broker/UI), client disclosure + per-audience
  minting (dialog, JS+Rust agent SDKs), /domains www re-center. Released to
  the id-host (id, www, browserid-wallet apps) via mini-ops; verified live.
- mingo e12eb60/6adc908: pin bump to a04ddf7, deployed to sandmill.org
  (confirmed via container GIT_REV; the host's `git:report` sha field is
  stale/unreliable — and the app repo's HEAD points at master while deploys
  use main, so `ps:rebuild` builds the WRONG branch; use ref-changing pushes).
- Follow-ups filed: SBO on-chain verifier audit (separate bean); nicer
  managed-disclosure UI + account badges (noted in vy1a).
