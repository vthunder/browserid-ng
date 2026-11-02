---
# browserid-ng-oa6s
title: '[Audit 2026-11] D7: hosted /verify and /validate-record return scope entries verbatim (Vec<ScopeEntry>)'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-02T22:43:19Z
parent: browserid-ng-ag1l
---

Findings: D7 (WS1/WS6/WS2), confirmed across the whole SDK tree. Severity: Medium. Decision: settled by S7 (2026-11-01): relays pass scope entries through verbatim; core keeps the generic parameter mechanism; pay parameters are audience-enforced in browserid-pay.

Where: browserid-verifier/src/verify.rs:122 (AccessVerificationResult.scopes: Vec<String>), :487 (RecordValidationResult.scopes), :602, :689; browserid-rp/src/lib.rs VerifiedIdentity.scopes has the same projection. Core preserves the entries (VerifiedAccess.scope_entries); the hosted /verify and /validate-record flatten a pay:usd entry with a cap to the bare string, so every attenuation is void downstream of the hosted verifier.

Change: change scopes on both result structs (and browserid-rp VerifiedIdentity) to Vec<ScopeEntry>; serde already emits a bare string for a parameterless entry so the wire shape is unchanged for today's records. Alternatively add scope_entries and deprecate scopes. sdk/js, python-mcp-auth, mcp-auth and gate then relay the objects (sdk/js and mcp-auth already carry them through; python is W4-14).

Acceptance:
- un-ignore browserid-verifier/tests/audit_2026_11_ws6.rs: d7_verify_response_carries_scope_parameters, d7_validate_record_response_carries_scope_parameters
- delete the D7 rows from EXPECTED_FAIL in browserid-verifier/tests/audit_2026_11_ws2_runner.rs, sdk/js/conformance.test.mjs, sdk/python-mcp-auth/tests/test_conformance_vectors.py, sdk/mcp-auth/test/conformance-vectors.test.mjs, sdk/gate/test/conformance-vectors.test.mjs (vectors P-OK-07, P-OK-08, A-OK-08); re-record the hosted responses (WS2_REGEN=1).

Related: W4-13 (Lane A bearer expiry; /verify should also return expires_at) is its own draft bean under Q23, blocked by this one.

Reports: ws6 §1.2, ws2 §2, ws1 §5 (S7). Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
