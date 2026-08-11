---
# browserid-ng-pbzn
title: Account registry must match credential reality (status-uri revocation, login re-record, revoke-now)
status: completed
type: bug
priority: high
created_at: 2026-08-11T18:28:21Z
updated_at: 2026-08-11T18:42:46Z
---

User-reported: /account showed browsers inactive (then nothing) while the browser kept signing in. Defects: (1) forget_holder revokes status_idx on the BROKER list even for tenant-issued certs whose authority is the tenant list — wrong authority, cert stays live; registry rows lack the status URI. (2) Registry only re-records on session-join, so it can't converge to reality on ordinary logins. (3) No explicit revoke-everyone-now lever (enable-transition only). Fixes: status_uri on DeviceCertRecord (v26), authority-routed revocation in forget_holder (+unrevocable surfaced in UI), /wsapi/record_device_cert (cryptographically verified, fail-closed status) called fire-and-forget by the dialog on every login, revoke_now flag + console button.

## Summary of Changes
- DeviceCertRecord.status_uri (migration v26) — which authority status_idx
  indexes into; recorded from the cert's own status ref (primary path) or the
  broker's list (issuance paths); mapped through registrar glue.
- forget_holder routes revocation to the RIGHT authority: own list, hosted
  tenant list (new tenant_status_revoke_idx), or reports `unrevocable` issuers
  — account.html shows the honesty note (in-content, no window.confirm/alert;
  those were ALSO lurking here and got replaced).
- Self-healing: POST /wsapi/record_device_cert — sessionless, gated by
  issuer-conformant DNSSEC signature + validity + FAIL-CLOSED status at the
  cert's own authority (own/tenant/foreign via check_foreign_status_fresh);
  can only assert facts that verify NOW, so it cannot resurrect revoked certs.
  dialog.js fire-and-forgets it on every successful login → the registry
  converges to observed reality.
- Explicit revoke lever: revoke_now flag on /wsapi/tenant/management + "Sign
  everyone out now" console button (two-step in-content confirm). Saving an
  already-enabled policy still deliberately does not re-revoke.
- Tests: forget_holder tenant-authority + unrevocable reporting; existing
  suites green; CSP hash updated for account.html. record_device_cert has no
  unit test (needs live DNS) — exercised in production by every dialog login.
