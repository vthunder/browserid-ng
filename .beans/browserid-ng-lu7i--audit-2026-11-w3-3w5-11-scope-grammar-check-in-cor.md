---
# browserid-ng-lu7i
title: '[Audit 2026-11] W3-3/W5-11: scope grammar check in core, enforced by the registrar at filing and authoring'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:47:41Z
parent: browserid-ng-ag1l
---

Findings: W3-3 (WS3, Medium) = W5-11 (WS5, Low): the registrar does not enforce the one scope grammar. The ledger takes Medium per Q27 (settled: core helper) (the consent card's control/bidi stripping is the only mitigation and it is JS). Decision: Q27 settled 2026-11-02: (a) put the grammar check in core and have the registrar and every other Rust signer call it.

Where: browserid-registrar/src/consent.rs:868-889 (validate_grant_shape: scopes.len() > 32 || s.scope().len() > 128 is the whole check). registry-api-v1 §3 and request-kinds/warrant.json pin ^[a-z0-9_:.\-/*@+]{1,128}$; the wallet enforces it (wallet/src/request.js:22); the registrar, which renders the card and signs, accepts empty, uppercase, whitespace, control/bidi and non-ASCII scope strings.

Change: one scope_grammar(&str) -> bool in browserid-core (identity.rs is the analogous home) used by validate_grant_shape, warrant_to_record and the admission AuthoringGrantItem path; reject with 400 invalid_request. The property scope_grammar_reference_matches_the_spec_regex in browserid-core/tests/audit_2026_11_ws3_proptest.rs is the reference predicate.

Acceptance (un-ignore): browserid-registrar/src/consent/audit_2026_11_ws3_proptest.rs: grant_shape_accepts_exactly_the_scope_grammar; browserid-broker/tests/authz_matrix_test.rs: filed_scopes_must_match_the_one_scope_grammar.

Reports: ws3 §3 (W3-3), ws5 §2a (W5-11). Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.



## Summary of Changes (core half — bean stays open for the registrar/broker half)

- New module `browserid_core::scope` with `pub fn validate_scope_string(s: &str) -> bool` (re-exported at the crate root as `browserid_core::validate_scope_string`), plus `scope::SCOPE_MAX_BYTES` (128) and `scope::SCOPE_GRAMMAR_REGEX`. Byte-level check of `^[a-z0-9_:.\-/*@+]{1,128}$`, no regex engine, total on any input; doc comment names the callers that must use it (registrar validate_grant_shape, warrant_to_record, admission AuthoringGrantItem).
- WS3 property `scope_grammar_reference_matches_the_spec_regex` now also pins core's predicate against the spec regex.
- Still to do (other agent): call `browserid_core::validate_scope_string` from browserid-registrar validate_grant_shape / warrant_to_record and the broker admission authoring path, reject with 400 invalid_request, and un-ignore the two acceptance tests named above.


## Summary of Changes (registrar half)

- `validate_grant_shape` (every filing: JIT warrant requests, agent-provision requests, connection and authoring record requests) now requires each scope string — bare, or the `scope` of a parameterized entry — to pass `browserid_core::validate_scope_string`; refused as 400 `bad scopes`. `register_warrant_core` applies the same check to an externally minted warrant's scopes (`422 invalid_warrant/warrant_invalid`), so nothing outside the grammar is ever recorded or rendered. The consent-side `validate_grant_warrants` compares warrant scopes to the validated grant exactly, so signed warrants inherit the check.
- Un-ignored: `consent/audit_2026_11_ws3_proptest.rs::grant_shape_accepts_exactly_the_scope_grammar` (its sibling `grant_shape_is_total_and_bounds_sizes` now expects the grammar too) and `authz_matrix_test::filed_scopes_must_match_the_one_scope_grammar` (also asserts in-grammar scopes still file).
