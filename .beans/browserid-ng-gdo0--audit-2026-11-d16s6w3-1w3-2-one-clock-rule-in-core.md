---
# browserid-ng-gdo0
title: '[Audit 2026-11] D16/S6/W3-1/W3-2: one clock rule in core (iat <= exp, iat <= now + skew, ttl >= 0, checked arithmetic)'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:18:00Z
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



## Summary of Changes

- New module `browserid_core::time`: `CLOCK_SKEW_SECONDS` (300), `check_window(what, iat, exp, now, skew)` (iat <= exp, iat <= now + skew, now <= exp; checked arithmetic, overflow rejects) and `validity_width(iat, exp)` (checked `exp - iat`, None on inverted/overflow).
- `AccessPresentation::verify_at` runs `check_window` on the access cert, config cert and warrant (replacing the bare expiry checks); `Constraints::check` computes max-ttl via `validity_width` (W3-1/D16).
- Admission: new `RecordBundle::validate_at(audience, at, resolver)` and `recheck_live_at(at)`; `validate`/`recheck_live` delegate at wall-clock now. Both objects go through `check_window`.
- Status lists: `is_fresh`/`is_fresh_capped` now reject `ttl < 0`, treat `iat > now + skew` as stale, and use checked arithmetic (W3-2/D16); new `is_fresh_at`/`is_fresh_capped_at` deterministic forms.
- `HandleAttestation::verify` goes through `check_window` (its 60 s skew kept).
- Tests: core device/admission unit tests judge the 2027 fixtures at `AT = IAT + 60` via the `_at` forms (wall-clock verify rightly rejects post-dated objects now); un-ignored ws6 s6_* (3), d16_* (2) and ws3 max_ttl_check_never_overflows, warrant_iat_is_bounded_by_exp_and_now, status_list_freshness_never_overflows; W3-1 reproducer inverted.
- WS2 runner: P-TIME-05..09 and A-REJ-21 removed from EXPECTED_FAIL (core now agrees). Vector file unchanged (no REGEN).
- fuzz: W3-1/W3-2 guards removed from jws_parse / claims_json; README note dropped; `cargo +nightly check` clean.
- Not done here (other crates): the D16 rows in browserid-verifier's runner and the SDK conformance tests listed in this bean.
