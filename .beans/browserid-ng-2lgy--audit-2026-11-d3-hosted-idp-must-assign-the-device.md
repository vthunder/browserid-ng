---
# browserid-ng-2lgy
title: '[Audit 2026-11] D3: hosted IdP must assign the device-cert holder, never copy a caller-chosen one'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-02T22:43:19Z
parent: browserid-ng-ag1l
---

Findings: D3 (WS1/WS4/WS8). Severity: Medium. Decision: none needed.

Where: browserid-broker/src/routes/hosted_idp.rs:396-403 (req.holder copied verbatim; format check only). Contrast routes/device.rs:300-313, which enforces the account's browsers namespace. Page side: browserid-broker/static/common/js/idp-device-authorize.js:23 (holder fragment parameter). WS8 reproduced: /idp/device_cert returns a cert whose holder equals the caller-supplied zzzzzzzzzz.attacker.

What: a tenant user (or whoever holds the roster password) stamps any well-formed holder on tenant-issued device certs, including the holder of a device the grantor already approved, and satisfies holder-pinned warrant matchers (B3 broken for tenant identities). Spec fb §3.2 / §7.4: the holder is issuer-assigned, never choosable.

Change: self-assign the holder on the hosted lane always (drop the holder fragment parameter from idp-device-authorize.js), or keep a per-tenant-user holder namespace and apply the same prefix rule as /device/issue. The dialog's reissue hop relies on the passthrough to reconcile the browser's holder across issuers; give it another way (accept the reassigned holder from the response). Run the hosted-IdP e2e before deploying.

Acceptance (un-ignore): browserid-broker/tests/audit_2026_11_ws4.rs: d3_tenant_device_cert_does_not_take_a_caller_chosen_holder (the pin d3_pin_tenant_device_cert_self_assigns_a_fresh_holder_when_absent must keep passing).

Reports: ws4 §1.1, ws8 §1.3. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
