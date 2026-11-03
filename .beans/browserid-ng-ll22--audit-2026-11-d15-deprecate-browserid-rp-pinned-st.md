---
# browserid-ng-ll22
title: '[Audit 2026-11] D15: deprecate browserid-rp pinned status refresh; route through verify_dnssec (SSRF guard, ttl cap)'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:25:05Z
parent: browserid-ng-ag1l
---

Findings: D15 (WS1/WS6): July H1/M3 class still open on the browserid-rp pinned-table status path. Severity: Medium (operator-steered URIs, so not High). Decision: Q3 settled 2026-11-02: (b) deprecate refresh / refresh_status and route everything through verify_dnssec.

Where: browserid-rp/src/lib.rs:272-290 (refresh_status: reqwest::get, follows redirects, no private-address guard, no URI host == iss check), :723 (StatusCache::refresh), :779 (verdict: is_fresh(600) with no ttl ceiling; a ten-year ttl stays Valid a year after iat). The DNSSEC path in the same crate reuses the hosted verifier's guard and is clean (pinned by i9_foreign_status_on_a_private_or_plain_http_host_is_never_fetched).

Change: deprecate Verifier::refresh, refresh_status and StatusCache (doc-deprecate now, remove at the next major); point RPs at verify_dnssec, whose status fetches go through fetch_foreign_status_list. Until removal, make the pinned path safe by construction: redirect::Policy::none(), https only, browserid_verifier::verify::validate_status_url, URI host == iss (or the discovered host=), verdict via is_fresh_capped(grace, 300). Update the rp README / examples.

Acceptance (un-ignore) in browserid-rp/tests/audit_2026_11_ws6.rs: d15_pinned_status_refresh_refuses_redirects_and_private_hosts, d15_pinned_status_cache_caps_the_issuer_declared_ttl (or delete them with the code path, if removal lands in one step).

Reports: ws6 §1.5 and §4. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

- browserid-rp/src/lib.rs: `Verifier::refresh_status` and `StatusCache::refresh` carry `#[deprecated]` (note points at `verify_dnssec`); `StatusCache`, `with_status_cache` and `verify` are doc-deprecated as the offline/test pinned-key path, removal at the next major; crate doc steers RPs to `verify_dnssec`.
- Until removal the pinned path is safe by construction: both refreshers go through a new private `fetch_status_list` — `browserid_verifier::verify::validate_status_url(uri, false)` (https only, no private/loopback/link-local address), a client with `redirect::Policy::none()`, 5 s timeout and `no_proxy()`, body read via `read_capped` (4 MiB), and the list's `iss` must equal the URI host (§6.3) before the signature check.
- `StatusCache::verdict` uses `is_fresh_capped(grace, MAX_STATUS_TTL)` with a new `pub const MAX_STATUS_TTL: i64 = 300` — a ten-year issuer `ttl` no longer pins a cached all-clear list.
- Acceptance: `d15_pinned_status_cache_caps_the_issuer_declared_ttl`, `d15_pinned_status_refresh_refuses_redirects_and_private_hosts` un-ignored and passing; rp: 16 unit + 2 integration + 2 doc tests pass, no deprecation warnings in the crate itself.
- No README or examples exist in browserid-rp; the only docs are the crate rustdoc, updated. Downstream (mingo/sbo) callers of `refresh_status`/`StatusCache::refresh` will see a deprecation warning on their next build.
