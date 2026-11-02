---
# browserid-ng-3zpa
title: '[Audit 2026-11] S3: drop browserid-warrant-v1 (signers to v2 first, then delete the core accept arm)'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-02T22:43:19Z
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
