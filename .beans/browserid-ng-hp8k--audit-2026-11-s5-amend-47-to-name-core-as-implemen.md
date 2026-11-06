---
# browserid-ng-hp8k
title: '[Audit 2026-11] S5: amend §4.7 to name core as implementing aud/scopes/max-ttl; flip P-CONS-01/06'
status: completed
type: task
priority: normal
created_at: 2026-11-02T22:43:21Z
updated_at: 2026-11-03T08:14:11Z
parent: browserid-ng-ag1l
---

Spec edit, not code. Findings: S5 (refuted as a code gap by WS6: core already fails closed on unknown constraint keys and enforces aud, scopes, max-ttl; WS2 confirms the spec/code divergence on P-CONS-01/06). Decision: Q24 settled 2026-11-02: (a) amend §4.7 to name browserid-core (and everything built on it) as implementing those three keys; the two vectors flip to accept. (b) would strip the core implementation.

Under (a): edit docs/specs/browserid-ng-protocol.md §4.7; in browserid-core/tests/audit_2026_11_ws2_generate.rs flip P-CONS-01 and P-CONS-06 to accept and regenerate (WS2_REGEN=1 for core and hosted); delete the S5 rows from EXPECTED_FAIL in every runner (core, hosted, sdk/js, python, mcp-auth, gate). The S5 corner (a scopes allowlist never restricts a scope-less login; use aud) is already settled by the spec edits and pinned by s5_scope_allowlist_is_vacuous_for_a_scope_less_login_warrant.

Reports: ws6 §1.7, ws2 §2 and §6. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

- docs/specs/browserid-ng-protocol.md §4.7: the "planned extension — not yet implemented" banner is replaced by an implementation-status note naming browserid-core (and every verifier built on it: hosted /verify, /validate-record, browserid-rp, the conformance runners) as implementing `aud`, `scopes`, `max-ttl`; the fail-closed paragraph now states that a presentation whose constraints are all satisfied verifies, an empty `constraints` object verifies, and any other key rejects. Managed-identity marker and UA duties stay planned.
- browserid-core/tests/audit_2026_11_ws2_generate.rs: P-CONS-01 and P-CONS-06 flipped to accept (`as_you(&b)`), `known: S5` dropped; test-vectors/conformance-2026-11.json regenerated (WS2_REGEN=1; only the two vectors changed).
- S5 rows removed from EXPECTED_FAIL in browserid-core/tests/audit_2026_11_ws2_runner.rs and browserid-verifier/tests/audit_2026_11_ws2_runner.rs (the verifier-side removal and the hosted re-recording land in the D7 commit, bean oa6s). Core runner: P-CONS-01/06 now `ok`.
- Not done here (SDK agent): the S5 rows in sdk/js/conformance.test.mjs, sdk/python-mcp-auth/tests/test_conformance_vectors.py, sdk/mcp-auth/test/conformance-vectors.test.mjs, sdk/gate/test/conformance-vectors.test.mjs.
