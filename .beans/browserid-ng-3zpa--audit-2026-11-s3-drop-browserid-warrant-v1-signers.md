---
# browserid-ng-3zpa
title: '[Audit 2026-11] S3: drop browserid-warrant-v1 (signers to v2 first, then delete the core accept arm)'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:25:41Z
parent: browserid-ng-ag1l
---

Findings: S3 (spec, decided 2026-11-01: drop browserid-warrant-v1 outright, no sunset), confirmed open in code by WS6 and WS2. Severity: Medium (a refless v1 record is unrevocable at the registry, I10). Decision: settled.

Where: the one accept gate is Warrant::validate_claims, arm TYP_WARRANT at browserid-core/src/device.rs:1304; Warrant::create still emits v1 (device.rs:1231). Callers that therefore accept v1 today: AccessPresentation::parse/verify, RecordBundle::parse/validate, hosted /verify and /validate-record, browserid-rp verify and verify_dnssec.

Change, in order:
1. Move every signer still emitting v1 login warrants to v2 with a holder binding entry and a status ref from allocate_status: browserid-broker/static/dialog.js:796, wallet/src/login.js:29, wallet/src/mediator.js:53, scripts/e2e/smoke-prod-dc.mjs:58, prototypes/menubar-wallet. Deploy and let in-flight v1 warrants expire.
2. Core: delete the v1 arm in validate_claims, Warrant::create, WarrantClaims::holder, and the v1 fixtures in device/tests.rs and admission.rs tests; regenerate test-vectors/device-cert-v1.json.

Acceptance:
- un-ignore browserid-core/tests/audit_2026_11_ws6.rs: s3_v1_warrant_rejects_in_presentation, s3_v1_record_rejects_in_admission
- delete the S3 rows from EXPECTED_FAIL in browserid-core/tests/audit_2026_11_ws2_runner.rs, browserid-verifier/tests/audit_2026_11_ws2_runner.rs, sdk/js/conformance.test.mjs, sdk/python-mcp-auth/tests/test_conformance_vectors.py, sdk/mcp-auth/test/conformance-vectors.test.mjs, sdk/gate/test/conformance-vectors.test.mjs (vectors P-TYP-01, P-TYP-02, A-REJ-13)

Run the wallet and dialog e2e before deploying step 1 (CI does not run e2e).

Reports: ws1 §5 (S3), ws6 §1.3, ws2 §2, ws4 §3 (login warrants note). Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Precondition check (2026-11-03) — NOT done, blocked on signers

The remediation brief assumed WS1's note that no signer in the repo emits `browserid-warrant-v1`. That is false; deleting the accept arm now would break production login. Signers that still emit v1 (`typ: 'browserid-warrant-v1'`):

- browserid-broker/static/dialog.js:796 — the login-warrant mint for every web sign-in (allocates a status ref when a registry session exists, else refless).
- wallet/src/login.js:29 — the native wallet's login warrant (90-day cached in the store; refless when allocation fails).
- wallet/src/mediator.js:53 — `presentationFor`: a **deliberately refless, unregistered** 600 s warrant used for the registry login itself (no registry call may run while the registry login is in flight). v2 REQUIRES `status` (`Warrant::validate_claims`), so this signer cannot move to v2 without a design change (a refless v2 shape, or a pre-login allocation lane).
- browserid-broker/src/routes/fedcm.rs:310 — production Rust: FedCM login warrants via `Warrant::create` (v1, `status: None`).
- browserid-core `Warrant::create` itself (device.rs:1231) — emits v1; 13 Rust files call it (broker/agent/rp tests, fedcm.rs).
- scripts/e2e/smoke-prod-dc.mjs:58, prototypes/menubar-wallet/app/ceremony.js:238, sdk/agent/device.test.mjs, sdk/mcp-auth/test/authcode*.test.mjs (fixtures).

Only the SBO signing-grant paths (dialog.js:2813, wallet-signer.js, wallet/src/request.js) and `Warrant::create_v2` emit v2.

What has to happen before step 2 (delete the arm) can land, in order: (1) decide how a refless registry-login presentation (mediator.js) and FedCM login warrants get a status ref under v2 — this is a design question (S4/§6.4 say status is REQUIRED on v2), not a code chore; (2) move dialog.js, wallet login.js, fedcm.rs and `Warrant::create` to v2 (`binding: {holder: matcher}`, status from allocate_status) and make the wallet's 90-day warrant cache skip cached v1 entries; (3) deploy and wait out in-flight v1 warrants (dialog/wallet warrants live 90 days unless the cache is invalidated); (4) then delete the v1 arm, `TYP_WARRANT`, `WarrantClaims::holder`, the v1 fixtures and `validate_record_accepts_v1_as_holder_binding`, regenerate test-vectors/device-cert-v1.json, and un-list P-TYP-01/02 and A-REJ-13 from every runner.

Nothing in core was changed for this bean. The ignored acceptance tests stay ignored; the S3 rows stay in both Rust runners' EXPECTED_FAIL.
