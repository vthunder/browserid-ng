---
# browserid-ng-lnf7
title: '[Audit 2026-11] W6-4: a cert''s status.uri host must equal its iss (or its DNSSEC host= delegate)'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-02T22:43:19Z
parent: browserid-ng-ag1l
---

Findings: W6-4 (WS6, = I9 cert-side clause), confirmed everywhere by WS2 (P-STAT-06). Severity: Medium. Decision: none needed; §6.3 (amended 2026-11-01) states the rule: a cert's status.uri host must be the cert's iss or the host= its _browserid record delegates to. Warrants stay signer-chosen (S4 decision).

Where: browserid-verifier/src/verify.rs:754-771, :575-594: a cert's status.uri host is never compared to its iss; a primary's certs pointing at the broker's own list verify via the own-list shortcut.

Change: in verify_access_core and validate_record_with_dns, before the status loop, require uri_matches_issuer(cert.status.uri, cert.iss, serving_host) for the access and config certs, mirroring the list-signer handling already used for the list itself.

Acceptance:
- un-ignore browserid-verifier/tests/audit_2026_11_ws6.rs: w6_4_cert_status_uri_host_must_equal_cert_iss
- delete the W6-4 rows from EXPECTED_FAIL in browserid-core/tests/audit_2026_11_ws2_runner.rs (documented as a verifier rule), browserid-verifier/tests/audit_2026_11_ws2_runner.rs, sdk/js/conformance.test.mjs, sdk/python-mcp-auth/tests/test_conformance_vectors.py, sdk/mcp-auth/test/conformance-vectors.test.mjs, sdk/gate/test/conformance-vectors.test.mjs (vector P-STAT-06)

Reports: ws6 §2, ws2 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
