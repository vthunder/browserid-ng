---
# browserid-ng-2lgy
title: '[Audit 2026-11] D3: hosted IdP must assign the device-cert holder, never copy a caller-chosen one'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:15:00Z
parent: browserid-ng-ag1l
---

Findings: D3 (WS1/WS4/WS8). Severity: Medium. Decision: none needed.

Where: browserid-broker/src/routes/hosted_idp.rs:396-403 (req.holder copied verbatim; format check only). Contrast routes/device.rs:300-313, which enforces the account's browsers namespace. Page side: browserid-broker/static/common/js/idp-device-authorize.js:23 (holder fragment parameter). WS8 reproduced: /idp/device_cert returns a cert whose holder equals the caller-supplied zzzzzzzzzz.attacker.

What: a tenant user (or whoever holds the roster password) stamps any well-formed holder on tenant-issued device certs, including the holder of a device the grantor already approved, and satisfies holder-pinned warrant matchers (B3 broken for tenant identities). Spec fb §3.2 / §7.4: the holder is issuer-assigned, never choosable.

Change: self-assign the holder on the hosted lane always (drop the holder fragment parameter from idp-device-authorize.js), or keep a per-tenant-user holder namespace and apply the same prefix rule as /device/issue. The dialog's reissue hop relies on the passthrough to reconcile the browser's holder across issuers; give it another way (accept the reassigned holder from the response). Run the hosted-IdP e2e before deploying.

Acceptance (un-ignore): browserid-broker/tests/audit_2026_11_ws4.rs: d3_tenant_device_cert_does_not_take_a_caller_chosen_holder (the pin d3_pin_tenant_device_cert_self_assigns_a_fresh_holder_when_absent must keep passing).

Reports: ws4 §1.1, ws8 §1.3. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.



## Summary of Changes

- routes/hosted_idp.rs `/idp/device_cert`: the holder is issuer-assigned, never copied from the body. New `assigned_holder(keypair, tenant_id, local, device_pub)` keeps a per-tenant-user namespace (`<8 chars>` derived from the tenant's secret signing key + tenant id + local part) and a suffix (`<10 chars>` derived from the secret + device pubkey), so: the same device re-issued (the dialog's reissue hop) gets the same holder; two devices get two; a caller cannot stamp another device's holder. `req.holder` stays in the request shape for older pages but is ignored.
- static/common/js/idp-device-authorize.js: the `holder` fragment parameter is dropped and the hold-mode reissue hop no longer forwards the dialog's holder (the re-issued certs carry the same issuer-assigned holder). dialog.js is unchanged: its `reconcileBrowserHolder` is best-effort and keeps the pair when the reissue does not land in the canonical namespace.
- Tests: un-ignored `d3_tenant_device_cert_does_not_take_a_caller_chosen_holder`; the pin `d3_pin_tenant_device_cert_self_assigns_a_fresh_holder_when_absent` still passes (audit_2026_11_ws4: 14 passed; hosted_primary_test: 20 passed).
- Deploy note: a static page script changed (idp-device-authorize.js); run the hosted-IdP / device-authorize Playwright specs before deploying.
