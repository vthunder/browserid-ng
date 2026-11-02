---
# browserid-ng-imn6
title: '[Audit 2026-11] W5-3/W5-12/S11: residual existence oracles answer identically (record_device_cert, approvals cap, foreign login key)'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W5-3 (July M7 class residual oracle), W5-12 and S11 (code side; decided 2026-11-01: answer identically whether or not the account or key exists). Severity: Low. Decision: settled.

Where: browserid-broker/src/routes/primary.rs:265-320 (/wsapi/record_device_cert: identity lookup precedes the cert signature check, "no account holds this identity" vs a later issuer/signature error -> unauthenticated existence oracle); browserid-registrar/src/approvals.rs:74-85 (sixth open -> 403 login_rejected "too many open approvals" only for an existing account; reg §5.2.8 amended: same 200 as an unknown account); browserid-registrar/src/account.rs:266-274 ("this key is a login key on another account" vs success for a fresh key).

Change: record_device_cert: verify the signature first and answer one generic refusal. approvals: at the cap return the unknown-account shape. account attach: generic login_rejected for the foreign-key case. Keep timing uniform (dummy work on the miss path where a lookup precedes the answer).

Acceptance (un-ignore) in browserid-broker/tests/authz_matrix_test.rs: record_device_cert_does_not_reveal_account_existence (currently network-ignored; after the reorder it must pass offline), approvals_at_the_cap_answer_like_an_unknown_account. Add a test for the foreign-login-key refusal shape. Bean browserid-ng-oawf carries W5-3 and S11 too.

Reports: ws5 §1 (S11) and §2 / §2a. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
