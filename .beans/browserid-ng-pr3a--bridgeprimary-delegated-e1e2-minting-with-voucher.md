---
# browserid-ng-pr3a
title: Bridge/primary-delegated E1/E2 minting with voucher-decided TTL
status: completed
type: task
priority: normal
created_at: 2026-08-19T13:34:10Z
updated_at: 2026-08-19T15:47:50Z
parent: browserid-ng-shyj
blocked_by:
    - browserid-ng-u4xz
---

Make E1/E2 cert issuance a live voucher decision, not a broker-session decision.

## Behavior
- When authorize_mint returns Delegate(Primary|Oidc|Atproto), the broker must NOT sign off its own session. The mint requires a fresh voucher proof:
  - E1 (Primary): client obtains the cert from the primary IdP's own device-cert endpoint (already the model); broker only records (primary.rs record_device_cert). Ensure /device/issue refuses Primary emails so the broker never signs iss=browserid.me for a primary identity.
  - E2 (Oidc/Atproto): re-run the bridge before minting. HOW is the bridge's choice — it may reuse a live OAuth/session silently or force a visible re-login. Define a bridge-mint entrypoint the dialog calls for a known/linked E2 email (today the chooser goes straight to /device/issue with no bridge — dialog.js:650-652).
- Cert TTL becomes the voucher's decision, not the DEVICE_CERT_VALIDITY_DAYS constant (core/device.rs:49). E2 defaults short (~1 week); may vary per-address; may use OAuth hints (token lifetime, auth_time, ACR/AMR). E1 already the primary's call. Thread a TTL through the bridge mint path.

## Dialog
- Known/linked E2 email selected from the chooser must go through the bridge, not the session-authed /device/issue.

## Tests
- E2 mint with no live bridge proof is refused even with a valid full session.
- TTL returned by the bridge is honored end-to-end.

## Summary of Changes (2026-08-19)

Mechanism: a completed bridge proof records a single-use **bridge mint grant** — `AppState.bridge_mint_grants`, keyed (user_id, email), 10-min redemption window (BRIDGE_GRANT_WINDOW_SECS), in-memory like the app's other anti-replay state. `/device/issue`, on a Delegate(Oidc|Atproto) decision, redeems the grant and mints with the grant's TTL; no live grant → 403 'a live bridge proof is required'. Delegate(Primary) is always refused (broker never signs E1; /device/issue refusal landed with u4xz; primary recording via record_device_cert unchanged).

- Grants recorded in oidc.rs attach_verified and handle_claim.rs complete_handle_claim (both session-attach and cold-claim arms), right after set_email_proof.
- TTL is the voucher's: BRIDGE_DEFAULT_TTL_DAYS = 7 for E2 (OAuth-hint refinement left open); broker-vouched E3/Agent stay 90d (BROKER_VOUCHED_CERT_TTL_DAYS in device.rs — the hard-coded Duration::days(90) is gone). owned_mintable_email now returns (email, ttl).
- Session level is irrelevant on the Delegate path by design: a cold bsky/Google claim (lightweight) mints immediately off its own fresh proof — invariants 1+3.
- Dialog: (a) proactive — a 'known' E2 with no cached device pair runs the bridge before /device/issue; (b) reactive — completeSignIn catches the delegated-mint 403, runs the bridge once (guarded by an _afterBridge flag on all four bridge re-entry call sites so a failed grant can't loop popups).

## Tests (tests/bridge_mint_test.rs, real handle-claim bridge with forged attestor key)
- Bridge proof → one mint whose cert TTL is exactly 7d (not 90d) → second mint refused (single-use) → re-running the bridge re-arms exactly one more.
- Grants are per-(account, email): a fresh proof for one address does not unlock a different E2 address.
- 'E2 refused with full session but no live proof' covered in mint_chokepoint_test. Full broker suite green.
