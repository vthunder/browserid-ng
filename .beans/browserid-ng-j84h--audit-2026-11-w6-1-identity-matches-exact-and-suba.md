---
# browserid-ng-j84h
title: '[Audit 2026-11] W6-1: identity_matches exact and subaddress branches use the §5 domain comparison'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:44:00Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-v8s0
---

Findings: W6-1 (WS6; confirmed everywhere by WS2, P-OK-12). Severity: Low (fail-closed, July L1 parser-differential class; issuers emit lowercase A-labels so unreachable in practice). Decision: none needed; the rule is core §5 (domain lowercased A-label, local part byte-exact).

Where: browserid-core/src/device.rs:73-74 and :107: the exact and subaddress branches of identity_matches compare the domain byte-exact, so a config cert for user@example.com does not cover a grantor written user@EXAMPLE.com.

Change: route the exact branch through identity::identity_eq and the subaddress branch through domain_eq. (The D1 split of identity_matches touches the same function; land after or with it.) The identity fuzz target's reference implementation mirrors the byte-exact comparison on purpose; update it.

Acceptance:
- un-ignore browserid-core/tests/audit_2026_11_ws6.rs: w6_1_grantor_match_uses_spec_domain_comparison
- delete the W6-1 rows from EXPECTED_FAIL in browserid-core/tests/audit_2026_11_ws2_runner.rs, browserid-verifier/tests/audit_2026_11_ws2_runner.rs, sdk/js/conformance.test.mjs, sdk/python-mcp-auth/tests/test_conformance_vectors.py, sdk/mcp-auth/test/conformance-vectors.test.mjs, sdk/gate/test/conformance-vectors.test.mjs (vector P-OK-12)

The JS half of the identity rule (D17 / W2-3 / W2-4) is its own draft bean under Q26.

Reports: ws6 §2, ws2 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
