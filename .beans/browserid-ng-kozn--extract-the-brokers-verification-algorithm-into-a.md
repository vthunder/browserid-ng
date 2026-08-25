---
# browserid-ng-kozn
title: Extract the broker's verification algorithm into a shared crate; browserid-rp consumes it
status: completed
type: task
priority: high
created_at: 2026-07-24T13:29:12Z
updated_at: 2026-08-25T20:57:21Z
---

Direction from Dan (2026-07-24): there must be ONE verification implementation. Today three exist at different fidelity: browserid-core AccessPresentation::verify (crypto join — shared, good), browserid-broker verifier.rs (DNSSEC discovery + primary/fallback conformance + fail-closed status, post-4lxl), and browserid-rp Verifier (pinned/well-known trust table + conformance added in xux4). Either an RP outsources to the hosted /verify-access, or it should run the SAME algorithm the broker runs.

Plan: extract verify_access_with_dns + the Discoverer/DNSSEC machinery (fallback_fetcher, dns_fetcher) from browserid-broker into a crate (e.g. browserid-verifier) consumed by both the broker and browserid-rp; the rp pinned-table mode remains only as an offline/test convenience. Related: audit B1 (broker/core cross-issuer contradiction — fix it in the extracted crate once, i9rr), xux4 (conformance patch this supersedes), 4lxl (fail-closed status lives in the same algorithm). First consumer: the bsky bridge (browserid-bsky), which outsources to hosted /verify-access until this lands.

## Decisions (2026-08-25)

- Crate: NEW workspace member `browserid-verifier` (not folded into browserid-dnssec — keeps the trust-root crate dep-light). Dockerfile workspace-member edit required.
- rp behavior: fail-closed status checks become the default when verify_dnssec is rebacked by the shared crate; `without_status_checks` survives as a documented non-conformant offline/test escape hatch.
- Note: drift is worse than described above — browserid-rp has since grown its own `verify_dnssec` (direct browserid-dnssec key resolution, no fallback-broker/host= logic, no foreign-status fail-closed machinery). Extraction unifies these.

## Summary of Changes

Done 2026-08-25. New workspace crate `browserid-verifier` holds the ONE implementation: discovery (Discoverer/FallbackFetcher, DNSSEC-rooted, hosted-primary host=), verify_access_with_dns + new verify_access_core (rich VerifiedAccess return), validate_record_with_dns, resolve_conformant_key, and the full fail-closed foreign-status machinery (SSRF guard, TTL caps, negative cache). Broker keeps verifier.rs/fallback_fetcher.rs as re-export shims (dns_fetcher precedent), so routes/tests were untouched except the Discoverer error type (VerifierError → BrokerError via From). browserid-rp::Verifier::verify_dnssec is now a thin adapter over verify_access_core — it gains the fallback-broker lane, host= handling, and unconditional fail-closed revocation (no opt-out on this path; without_status_checks stays only on the pinned-table offline/test mode, and a new allow_private_status_hosts() builder relaxes the SSRF guard for local dev). DnsFetcher gained Clone. Dockerfile updated for the new member. All 63 workspace test suites green.

Deferred: browserid-rp has no direct test of the verify_dnssec adapter (the shared core is covered by the broker-side verifier_test.rs); first real consumer remains the bsky bridge (bean bhfi tracks moving it off the hosted endpoint alias).
