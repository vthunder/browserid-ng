---
# browserid-ng-oa6s
title: '[Audit 2026-11] D7: hosted /verify and /validate-record return scope entries verbatim (Vec<ScopeEntry>)'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:14:30Z
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


## Summary of Changes

- browserid-verifier/src/verify.rs: `AccessVerificationResult.scopes` and `RecordValidationResult.scopes` are now `Option<Vec<ScopeEntry>>`, filled from core's `scope_entries` (was the `scopes` string projection). Scope parameters (`cap`, `mode`, `counterparties`, `max_duration`, `min_reputation`) now ride through hosted `/verify` and `/validate-record` verbatim.
- Wire format (hosted `/verify`, `/validate-record`, `scopes[]`): backward-compatible. `ScopeEntry` is `#[serde(untagged)]`: a parameterless entry serializes as the bare string it always was (`"tool:read"`); an entry carrying parameters serializes as the object `{"scope": "pay:usd", "cap": {"amount": "20.00", "currency": "USD", "window": "P1D"}}` (only present parameters are emitted; `mode` for `sign:` entries as `{"scope": …, "mode": "prompt"}`). Every record that exists today yields the same bytes as before; only parameterized entries change from a flattened string to the object. Consumers that treat `scopes` as a string list must read `typeof e === "string" ? e : e.scope` (sdk/js and mcp-auth already do; python is W4-14).
- browserid-rp `VerifiedIdentity`: additive — `scope_entries: Vec<ScopeEntry>` (verbatim) beside the unchanged `scopes: Vec<String>` projection, so downstream Rust RPs keep compiling; `exchange()` still intersects on scope strings.
- Broker consumers updated to project through `ScopeEntry::scope()`: routes/guestbook.rs (guestbook-sign check), routes/primary.rs (registry-scope log); tests/verifier_test.rs assertion typed to `ScopeEntry`.
- Acceptance: `d7_verify_response_carries_scope_parameters`, `d7_validate_record_response_carries_scope_parameters` un-ignored and passing; P-OK-07, P-OK-08, A-OK-08 removed from the hosted runner's EXPECTED_FAIL and test-vectors/conformance-2026-11.hosted.json re-recorded (WS2_REGEN=1). Hosted runner: 148 pass, 11 expected-fail, 0 unexpected.
- Not done here (SDK agent): D7 rows in the sdk/js, python-mcp-auth, mcp-auth and gate runners; W4-13 (`expires_at` on /verify) stays its own bean.
