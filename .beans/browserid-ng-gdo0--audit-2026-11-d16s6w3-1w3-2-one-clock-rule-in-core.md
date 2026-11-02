---
# browserid-ng-gdo0
title: '[Audit 2026-11] D16/S6/W3-1/W3-2: one clock rule in core (iat <= exp, iat <= now + skew, ttl >= 0, checked arithmetic)'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: D16 / S6 (Medium), W3-1 (Low), W3-2 (Low): one clock rule for every object. Decision: Q28 settled 2026-11-02: (a) one normative rule (already implied by the amended §6.1 "Time bounds" paragraph) and one core helper: iat <= exp, iat <= now + skew, ttl >= 0, checked arithmetic; every verifier calls it.

Where: browserid-core/src/device.rs:61 (expired_at only), :314-317 (Constraints::check: exp - iat unsigned/unchecked; W3-1 reproducer panics in debug, wraps in release and passes any max-ttl), admission.rs validate (no iat), status.rs:190/:198 (is_fresh / is_fresh_capped: iat + ttl + grace unchecked; a future iat stays fresh past the July M3 cap; W3-2 wrap reads fresh forever). HandleAttestation::verify already bounds iat (now + 60) and is the pattern to copy.

Change: add a core helper (e.g. time::check_window(iat, exp, now, skew) -> Result) with checked_sub / checked_add; call it in verify_at, RecordBundle::validate, recheck_live and every parse path with iat; in is_fresh* reject ttl < 0 and treat iat > now + skew as stale; compute the max-ttl width with checked_sub treating None as a violation. Skew 60-300 s. Remove the W3-1 / W3-2 guards in fuzz/fuzz_targets/claims_json.rs and jws_parse.rs. Assertions carry no iat today (W4-40, Q19); once added they go through the same helper.

Acceptance:
- un-ignore browserid-core/tests/audit_2026_11_ws6.rs: the three s6_* tests, d16_future_iat_defeats_max_ttl, d16_status_list_with_future_iat_is_not_fresh
- un-ignore browserid-core/tests/audit_2026_11_ws3_proptest.rs: max_ttl_check_never_overflows, warrant_iat_is_bounded_by_exp_and_now, status_list_freshness_never_overflows
- delete the D16/S6 rows from EXPECTED_FAIL in browserid-core/tests/audit_2026_11_ws2_runner.rs, browserid-verifier/tests/audit_2026_11_ws2_runner.rs, sdk/js/conformance.test.mjs, sdk/python-mcp-auth/tests/test_conformance_vectors.py, sdk/mcp-auth/test/conformance-vectors.test.mjs, sdk/gate/test/conformance-vectors.test.mjs (vectors P-TIME-05..09, A-REJ-21)

Reports: ws6 §1.6, ws3 §3 (W3-1, W3-2), ws2 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
