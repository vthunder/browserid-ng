---
# browserid-ng-t25u
title: 'Audit WS5: broker HTTP surface review + authz matrix test'
status: completed
type: task
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-02T10:44:40Z
parent: browserid-ng-ag1l
---

All ~20 route modules: authz on every handler, CSRF, open redirect (return_origin), SSRF (verifier status fetch, dns_fetcher, proof_fetch), rate limiting, enumeration, cookie attrs, CSP hashes. Build durable authz matrix test: every route x principal (anon, user, other user, agent, tenant admin) asserting expected status. Re-verify July C1/H1/H2/M1-M9 and oawf deferred items.

## From WS1 — candidates to confirm/refute
D2 respond never checks config cert recorded/signed (consent.rs:457-465,551-561); D4 JIT request unsigned; D8 no rate limit on /api/v1 (approvals 30-bit code); D9 fetches before proof verification on accounts/lookup; D10 possession proofs not replay-cached; D11 cross-account attach row corruption (needs SqliteStore test); D18 JIT details. Also resolve the ytjn/dw35/7ww7 completed-vs-open discrepancy. Authz matrix from I22-I28. See docs/security-audit-2026-11-ws1-spec-review.md §1.


## Plan (2026-11-02)
- [x] Read oracle (threat model I15-I28), WS1 §1 + appendix, July audit, oawf/ytjn/dw35/7ww7 beans
- [x] Code read: registrar consent/account/approvals/session/api, broker device/registry_login/auth/rate_limit, sqlite attach
- [x] Authz matrix test browserid-broker/tests/authz_matrix_test.rs (anon/user/other/tenant admin) + AUDIT-2026-11 ignored encodings
- [x] Run via ssh localtest, read tally (10 pass, 11 ignored; 11 ignored verified failing with --include-ignored, 2 network ones by code read)
- [x] Report docs/security-audit-2026-11-ws5-http-surface.md (D-verdicts, W5-new, July table, oawf resolution)
- [x] Commit tests+report+beans; update oawf; mark completed

## Summary of Changes

- `browserid-broker/tests/authz_matrix_test.rs`: route x principal matrix (anon, user, other user, tenant admin) over the cookie surface and all of /api/v1; CSRF, return_origin (I15), proof replay (I22), policy floor (I25) guards. 10 passing. 11 `#[ignore]` tests tagged `AUDIT-2026-11` encode confirmed findings and fail today.
- `docs/security-audit-2026-11-ws5-http-surface.md`: verdicts — D2 CONFIRMED High (respond never checks issuer signature/recording of the config cert), D4 CONFIRMED Medium (unsigned JIT filing), D8 PARTIAL (no 429 on /api/v1; approval-code brute force refuted as takeover vector), D9 PARTIAL Low, D10 REFUTED, D11 CONFIRMED Low (SqliteStore test), D18 CONFIRMED Low, appendix return_origin REFUTED (holds), S1/S11 confirmed as decided. New W5-1..9 incl. W5-2 hosted IdP no throttle, W5-4 password change leaves login keys live (decision), W5-7 agent-provision/complete bypasses authorize_mint, W5-8 zlib decode-before-cap (to WS6). July table: C1/H2/M1/M3/M4/M5/M6/M7/M8/M9 fixed or fixed-with-residual; H1 open for discovery fetch and /status/proxy.
- oawf resolved: ytjn/dw35/7ww7 are fixed in code; bean re-pointed at the residual items.


## Addendum (spec d221cb3 re-check)
Four more ignored encodings added: W5-10 registry_login mints tokens with no return-origin check (S1, High); W5-11 scope grammar not enforced; W5-12 approvals cap answers 403 not the unknown-account 200; W5-13 claim refuses agent codes. W5-14 (restore over a holding account needs config + confirm_takeover; code requires only fresh) and W5-15 (holder_mismatch vs holders_differ) confirmed by code read. Report §2a.
