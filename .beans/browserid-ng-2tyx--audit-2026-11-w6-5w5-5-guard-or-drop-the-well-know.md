---
# browserid-ng-2tyx
title: '[Audit 2026-11] W6-5/W5-5: guard or drop the .well-known discovery fetch; harden /status/proxy (rate limit, generic error)'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-02T22:43:19Z
parent: browserid-ng-ag1l
---

Findings: W6-5 (= W5-5): July H1 class on the second fetcher, plus the /status/proxy half of W5-5. Severity: Medium. Decision: none needed.

Where: browserid-verifier/src/discovery.rs:15-27, :193-202 and verify.rs:25-47: the .well-known discovery fetch uses a default reqwest::blocking client (redirects followed, no post-resolution address check, uncapped response.json()); the target is the attacker-choosable DNS host= value and it runs on every verification of a primary-issued bundle before any signature check. Reachable unauthenticated via /verify, /wsapi/address_info, /wsapi/record_device_cert, handle_claim. browserid-broker/src/routes/status.rs:46-76: GET /status/proxy is unauthenticated, outside the rate-limited router, fires a GET at any public https://host:port before any issuer check, and returns the guard's error text verbatim (internal-DNS oracle: "resolves to non-global address 10.x").

Change:
- Verifier: stop fetching .well-known in FallbackFetcher::discover for verification (the key comes from the DNSSEC record; resolve_idp_key already skips the fetch) and leave endpoint discovery to issuance. Short of that, route HttpFetcher through validate_status_url's address check, redirect::Policy::none() and read_capped.
- Broker: put /status/proxy behind rate_limit::verification_api, return a generic error instead of the guard's text, and constrain uri to the issuer's status-list path.

Acceptance (un-ignore): browserid-verifier/tests/audit_2026_11_ws6.rs: w6_5_discovery_fetch_refuses_redirects_and_private_hosts. Add a broker test for /status/proxy (generic error, 429 under load).

Reports: ws6 §2, ws5 §2 (W5-5) and §7. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
