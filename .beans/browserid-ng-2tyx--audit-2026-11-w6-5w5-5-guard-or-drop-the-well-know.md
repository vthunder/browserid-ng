---
# browserid-ng-2tyx
title: '[Audit 2026-11] W6-5/W5-5: guard or drop the .well-known discovery fetch; harden /status/proxy (rate limit, generic error)'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:26:12Z
parent: browserid-ng-ag1l
---

Findings: W6-5 (= W5-5): July H1 class on the second fetcher, plus the /status/proxy half of W5-5. Severity: Medium. Decision: none needed.

Where: browserid-verifier/src/discovery.rs:15-27, :193-202 and verify.rs:25-47: the .well-known discovery fetch uses a default reqwest::blocking client (redirects followed, no post-resolution address check, uncapped response.json()); the target is the attacker-choosable DNS host= value and it runs on every verification of a primary-issued bundle before any signature check. Reachable unauthenticated via /verify, /wsapi/address_info, /wsapi/record_device_cert, handle_claim. browserid-broker/src/routes/status.rs:46-76: GET /status/proxy is unauthenticated, outside the rate-limited router, fires a GET at any public https://host:port before any issuer check, and returns the guard's error text verbatim (internal-DNS oracle: "resolves to non-global address 10.x").

Change:
- Verifier: stop fetching .well-known in FallbackFetcher::discover for verification (the key comes from the DNSSEC record; resolve_idp_key already skips the fetch) and leave endpoint discovery to issuance. Short of that, route HttpFetcher through validate_status_url's address check, redirect::Policy::none() and read_capped.
- Broker: put /status/proxy behind rate_limit::verification_api, return a generic error instead of the guard's text, and constrain uri to the issuer's status-list path.

Acceptance (un-ignore): browserid-verifier/tests/audit_2026_11_ws6.rs: w6_5_discovery_fetch_refuses_redirects_and_private_hosts. Add a broker test for /status/proxy (generic error, 429 under load).

Reports: ws6 §2, ws5 §2 (W5-5) and §7. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.



## Summary of Changes

Verifier half (browserid-verifier, outside my area; fix-verifiers confirmed they do not touch `HttpFetcher` and asked me to make this change — flagged):
- src/verify.rs `HttpFetcher`: `redirect::Policy::none()`, 5 s connect / 10 s total timeouts, body capped at `SUPPORT_DOCUMENT_MAX_BYTES` (64 KiB, `read_capped_blocking`), and the production client (`new()`) resolves the host first and refuses any non-global address (`is_global_ip`, the same rule as `validate_status_url`). `allow_http()` (localhost dev/tests) keeps the redirect and size rules. Lines ~17-160 only.
- Cargo.toml: `serde_json` moved from dev-dependencies to dependencies (the capped body is parsed with it).
- tests/audit_2026_11_ws6.rs: un-ignored `w6_5_discovery_fetch_refuses_redirects_and_private_hosts` (that one fn only; the file is being reworked by fix-verifiers).

Broker half:
- routes/status.rs `/status/proxy`: only status-list-shaped URIs are proxied (`status_list_uri_shape_ok`: https — http on localhost dev — no userinfo/query/fragment, path `/.well-known/browserid-status` or `/status/<tenant>`), and every fetch/guard failure answers the one generic reason `status list unavailable`; the detail (e.g. "resolves to non-global address 10.x") goes to the debug log. Unit tests for the shape rule.
- routes/mod.rs: `/status/proxy` sits under `rate_limit::verification_api` (300/min per IP, RateLimit headers, 429 + Retry-After); `routes::RATE_LIMIT` exported for tests.
- tests/status_endpoints_test.rs: the unreachable-URI test asserts the generic reason leaks no address/resolver/connection detail; new `status_proxy_refuses_non_status_uris_and_rate_limits`.
- Not done: dropping the .well-known fetch from `FallbackFetcher::discover` for verification (the bean's preferred option) — fix-verifiers is reworking discovery.rs/verify.rs resolution paths concurrently; the guarded fetcher closes the SSRF class either way.
