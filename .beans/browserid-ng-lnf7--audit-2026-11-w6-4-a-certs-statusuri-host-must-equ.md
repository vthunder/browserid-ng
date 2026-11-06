---
# browserid-ng-lnf7
title: '[Audit 2026-11] W6-4: a cert''s status.uri host must equal its iss (or its DNSSEC host= delegate)'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:21:23Z
parent: browserid-ng-ag1l
---

Findings: W6-4 (WS6, = I9 cert-side clause), confirmed everywhere by WS2 (P-STAT-06). Severity: Medium. Decision: none needed; §6.3 (amended 2026-11-01) states the rule: a cert's status.uri host must be the cert's iss or the host= its _browserid record delegates to. Warrants stay signer-chosen (S4 decision).

Where: browserid-verifier/src/verify.rs:754-771, :575-594: a cert's status.uri host is never compared to its iss; a primary's certs pointing at the broker's own list verify via the own-list shortcut.

Change: in verify_access_core and validate_record_with_dns, before the status loop, require uri_matches_issuer(cert.status.uri, cert.iss, serving_host) for the access and config certs, mirroring the list-signer handling already used for the list itself.

Acceptance:
- un-ignore browserid-verifier/tests/audit_2026_11_ws6.rs: w6_4_cert_status_uri_host_must_equal_cert_iss
- delete the W6-4 rows from EXPECTED_FAIL in browserid-core/tests/audit_2026_11_ws2_runner.rs (documented as a verifier rule), browserid-verifier/tests/audit_2026_11_ws2_runner.rs, sdk/js/conformance.test.mjs, sdk/python-mcp-auth/tests/test_conformance_vectors.py, sdk/mcp-auth/test/conformance-vectors.test.mjs, sdk/gate/test/conformance-vectors.test.mjs (vector P-STAT-06)

Reports: ws6 §2, ws2 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

- browserid-verifier/src/verify.rs: new `resolve_conformant` (returns the issuer's key AND its DNSSEC `host=` serving host; `resolve_conformant_key` is now a thin wrapper, signature unchanged) and `check_cert_status_host`, which requires `uri_matches_issuer(cert.status.uri, cert.iss, serving_host)` — the same rule the list-signer check uses. Applied to the access cert and config cert in `verify_access_core` (so hosted `/verify` and browserid-rp `verify_dnssec`) and to the config cert in `validate_record_with_dns`, before any status lookup, so the own-list shortcut can no longer answer for a primary's cert. Warrants stay signer-chosen (S4). Reject reason: `<label> status.uri host is not its issuer '<iss>' (or the host= its _browserid record delegates to): <uri>`.
- Acceptance: `w6_4_cert_status_uri_host_must_equal_cert_iss` un-ignored and extended (access cert, config cert, record form, third-party host with a verified list in cache); new `w6_4_hosted_primary_may_point_at_its_dnssec_delegate` (host= delegate accepted, another provider refused); new `i9_status_url_guard_refuses_private_and_plain_http` pins the SSRF guard directly since the host rule now trips first. Test helpers: `Mock.delegates`, `bundle_with`, `Status::seed`; certs in the suite now point at their issuer's list. `i9_uncheckable_own_status_rejects` uses a fallback-issued identity (the only kind whose certs legitimately sit on the broker's list).
- browserid-broker/tests/verifier_test.rs: `MockDiscoverer::with_serving_host`; `sandmill.org` fixtures are declared hosted on the broker (host= delegate) or on the local status authority, which is the realistic shape; new `verify_access_rejects_primary_cert_pointing_at_the_brokers_list`.
- browserid-core/tests/audit_2026_11_ws2_runner.rs: harness gains `cert_status_host` (host == iss; the env declares no delegates) so P-STAT-06 is judged as the hosted verifier judges it; W6-4 row removed from EXPECTED_FAIL there and in the hosted runner; hosted responses re-recorded (hosted: 149 pass, 10 expected-fail, 0 unexpected). P-STAT-07/08 now reject on the host rule instead of the fetch.
- Production check: broker-issued certs (iss = broker domain, list = `status_list_uri(domain)`) and hosted-tenant certs (iss = tenant, DNS `host=` = idp_host, list = `tenant_status_uri(idp_host, …)`) both satisfy the rule.
- Not done here (SDK agent): W6-4 rows in sdk/js, python-mcp-auth, mcp-auth and gate runners.
