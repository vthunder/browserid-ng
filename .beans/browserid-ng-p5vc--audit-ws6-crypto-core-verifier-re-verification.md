---
# browserid-ng-p5vc
title: 'Audit WS6: crypto core + verifier re-verification'
status: completed
type: task
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-02T10:43:53Z
parent: browserid-ng-ag1l
---

browserid-core (jws, keys, assertion, attestation, admission, device certs, status), browserid-verifier, browserid-dnssec. Re-verify July 'sound' verdict rather than assume it; new since July: device certs, admission, typed signing, attestation. Check verification ordering, time handling, key/sig length pins, DNSSEC fail-closed.

## From WS1 — candidates to confirm/refute
D1 subaddress widening at mint (core device.rs:96-111 + both mint routes); D7 /verify drops scope parameters; D14 DoT transport failure demotes primaries; D15 browserid-rp status path (no host==iss, redirects, no private-IP guard, ttl grace uncapped) and registrar validity bar; D16 iat unbounded. Agents found core verify_at/admission::validate conformant on the headline §6.1/§6.4 items; re-verify rather than assume. See docs/security-audit-2026-11-ws1-spec-review.md §1.


## WS6 todo (2026-11-02)
- [x] Read core/verifier/dnssec/rp; form findings
- [x] browserid-core/tests/audit_2026_11_ws6.rs: D1, D16/S6, S3, S5, I1, I4, I5, alg/length pins
- [x] browserid-verifier/tests/audit_2026_11_ws6.rs: D7, I3
- [x] browserid-dnssec: D14 transport-failure test
- [x] browserid-rp/tests/audit_2026_11_ws6.rs: D15
- [x] Run suites via ssh localtest; confirm ignore-marked tests fail, others pass
- [x] Report docs/security-audit-2026-11-ws6-core-verifier.md (+ July re-verification)
- [x] Commit tests + report + bean


## Summary of Changes
Report: docs/security-audit-2026-11-ws6-core-verifier.md. Regression tests (ignored = fails today, acceptance test for the fix):
browserid-core/tests/audit_2026_11_ws6.rs (17 pass / 9 ignored), browserid-verifier/tests/audit_2026_11_ws6.rs (6 / 2),
browserid-dnssec/tests/audit_2026_11_ws6.rs (0 / 2), browserid-rp/tests/audit_2026_11_ws6.rs (0 / 2). No production code changed;
browserid-verifier gained chrono + serde_json dev-deps.

Verdicts: D1 CONFIRMED (High, identity_matches purpose-blind subaddress rule gates both mints); D7 CONFIRMED (Medium, hosted
result structs project scopes to strings); D14 CONFIRMED (Medium, DoT transport failure/Refused → Insecure → fallback);
D15 CONFIRMED on the rp pinned-table path only (redirects followed, http+loopback accepted, ttl uncapped); D16/S6 CONFIRMED
(no iat bound anywhere; max-ttl and the M3 ttl cap bypassed by future iat); S3 open as expected (all v1 accept paths funnel
through Warrant::validate_claims; status-less v1 verifies); S5 REFUTED for the Rust path (unknown keys reject, aud/scopes/max-ttl
enforced). New: W6-1 (Low, grantor match skips §5 domain normalization, stricter), W6-2 (info, Assertion::verify has no alg pin),
W6-3 (info, status-list inflate cap applied after full read). July H1/M3 hold on the hosted path, open on rp pinned path.
Needs Dan: D1 ordering vs WS8 PoC; S5 login-allowlist corner; I9 wording vs S4; D14 retry-before-reject; D15 fix-or-deprecate.


Follow-up after spec commit d221cb3: added W6-4 (Medium, confirmed) — hosted verifier never checks a cert's status.uri host == cert iss, now required by §6.3; test w6_4_cert_status_uri_host_must_equal_cert_iss (ignored). Flagged the hosted-primary host= tension for Dan.


WS5 handoffs folded in: W6-3 upgraded to High (= W5-8; bomb test shows 768 MiB inflated before the cap) and W6-5 added (= W5-5; discovery .well-known fetch follows redirects to another host, no address guard, uncapped body). Both ignored tests in place.
