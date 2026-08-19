---
# browserid-ng-u4xz
title: Central mint-authorization chokepoint keyed on provenance x session level
status: completed
type: task
priority: high
created_at: 2026-08-19T13:33:57Z
updated_at: 2026-08-19T15:39:17Z
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

## Summary of Changes (2026-08-19)

- New `src/mint.rs`: `authorize_mint(&Email, SessionLevel) -> MintDecision {Allow, NeedPassword, Delegate(Voucher)}` with an EXHAUSTIVE match on (EmailType × ProofMethod) — a new enum variant fails compilation until its policy is decided. Agent identities (not in the epic's E1–E3 classes) are broker-vouched via the delegation chain, so they follow the E3 password rule.
- `/device/issue`: `owned_verified_email` → `owned_mintable_email` — ownership + chokepoint. NeedPassword → 401 with stable reason "password required" (new `BrokerError::PasswordRequired`); Delegate → 403 PolicyRefused.
- `/fedcm/assertion` refuses anything but Allow; `/fedcm/accounts` filters the chooser by the same decision (no dead entries). FedCM has no step-up surface, so lightweight sessions and E2 addresses simply don't appear.
- Dialog: `completeSignIn` catches the 401 step-up and shows the password screen (re-auth → Full → retry). E2 Delegate routing lands with pr3a.
- Outside the chokepoint by design (documented in mint.rs): `/access/mint` (device-cert-authed — the cert was already authorized at issuance; revocation is the recourse) and `/idp/*` (the hosted tenant primary IS the E1 voucher).
- Test-harness consequence: `create_user` now returns a FULL (password-authed) session — completion sessions are Lightweight since ca29 and would fail every mint test, which is precisely the new model working.

## Tests
- src/mint.rs: full table-driven (EmailType × ProofMethod × SessionLevel) decision matrix.
- tests/mint_chokepoint_test.rs: E3 full-mints/lightweight-401s; E2 refused even under Full (Oidc + Atproto); Primary refused; Agent follows the password rule; FedCM accounts-filter + assertion gate under both levels; sqlite provenance round-trip feeding the chokepoint; and the no-silent-bypass guard — a source scan asserting every DeviceCert/AccessCert create/from_claims call site is a registered issuance surface and the session-authed ones call authorize_mint.
- Full broker suite green.
