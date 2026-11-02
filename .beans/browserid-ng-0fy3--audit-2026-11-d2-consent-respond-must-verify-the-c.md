---
# browserid-ng-0fy3
title: '[Audit 2026-11] D2: consent respond must verify the config cert (issuer signature, recorded on account, status)'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:36:28Z
updated_at: 2026-11-02T22:36:28Z
parent: browserid-ng-ag1l
---

Findings: D2 (WS1/WS5/WS8). Severity: High. Decision: none needed (settled).

Where: browserid-registrar/src/consent.rs:678-760 (validate_grant_warrants), :551-581 (respond_record). Contrast browserid-registrar/src/api.rs:611-623 (register_warrant, config_cert_not_recorded).

What: /api/v1/requests/respond accepts a "config cert" that the IdP never signed, that is not recorded on the responding account, or whose status bit is set. It checks only purpose, expiry, authorizes_identity(grantor) and that the warrant verifies under the cert's own key. WS8 reproduced it end to end: a config cert signed by a fresh attacker key is accepted (200 {}) and the forged-config grant is delivered to the filer via /warrant/poll.

Change: one shared helper recorded_config_cert(state, user_id, jws) used by respond_core, respond_record and register_warrant: parse -> verify under the issuer key (broker key for the broker's own domain; the presentation verifier for a primary-issued cert) -> get_device_cert_by_pubkey must belong to this account and is_active(). Reason code config_cert_not_recorded. Keep the validation order per registry-api-v1 §7.1.

Acceptance (un-ignore):
- browserid-broker/tests/authz_matrix_test.rs: respond_refuses_a_config_cert_the_issuer_never_signed, respond_refuses_a_config_cert_not_recorded_on_the_account
- browserid-broker/tests/audit_2026_11_ws8_d2.rs (PoC; flips from "passes today" to asserting the refusal, then becomes a regression test)

Report: docs/security-audit-2026-11-ws5-http-surface.md §1, docs/security-audit-2026-11-ws8-pocs.md §1.2. Ledger: docs/security-audit-2026-11.md.
