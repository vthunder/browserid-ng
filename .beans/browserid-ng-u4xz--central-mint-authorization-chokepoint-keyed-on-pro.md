---
# browserid-ng-u4xz
title: Central mint-authorization chokepoint keyed on provenance x session level
status: todo
type: task
priority: high
created_at: 2026-08-19T13:33:57Z
updated_at: 2026-08-19T13:33:57Z
parent: browserid-ng-shyj
blocked_by:
    - browserid-ng-ca29
---

Route every credential-issuing path through one authorize_mint decision with an exhaustive match, so provenance can never be silently skipped again.

## Design
authorize_mint(email: &EmailRecord, level: SessionLevel) -> MintDecision
  match (email.email_type, email.proof) {
    (Primary, _)              => Delegate(Primary)      // E1: never off broker session
    (Secondary, Oidc|Atproto) => Delegate(email.proof)  // E2: live bridge proof required
    (Secondary, Smtp)         => match level { Full => Allow, _ => NeedPassword }  // E3
    // exhaustive: new EmailType/ProofMethod forces a decision here
  }

## Wire into issuance paths
- /device/issue (device.rs:139) — replace the verified-only gate (owned_verified_email, device.rs:60-76) with authorize_mint; NeedPassword => 401 step-up, Delegate => refuse (client must use bridge/primary path).
- /auth/device_cert (fallback_idp.rs:282) — see 7ww7 slice.
- /access/mint, /fedcm/assertion — audit against the same decision (fedcm already restricts to Secondary; make proof-awareness consistent).

## Regression guards
- Table-driven test matrix (email_type x proof x session_level) -> expected MintDecision.
- Test asserting every issuance route calls authorize_mint (no direct DeviceCert::create bypassing it).
- Cover on BOTH SqliteStore and InMemoryUserStore (memory-store tests miss sqlite-only constraints).
