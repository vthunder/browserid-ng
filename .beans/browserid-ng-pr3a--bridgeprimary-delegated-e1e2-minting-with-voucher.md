---
# browserid-ng-pr3a
title: Bridge/primary-delegated E1/E2 minting with voucher-decided TTL
status: todo
type: task
priority: normal
created_at: 2026-08-19T13:34:10Z
updated_at: 2026-08-19T13:34:10Z
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
