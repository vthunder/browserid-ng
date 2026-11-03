---
# browserid-ng-4r2j
title: '[Audit 2026-11] D8/W5-9: blanket per-source and per-account rate limiter on /api/v1 (429 before any fetch)'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:22:22Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-gajq
---

Findings: D8 (WS1/WS5/WS8) and W5-9 (Info). Severity: Medium. The approval-code takeover was refuted (approvals.rs:179-234 requires an enrolled session on the same account); what stands is the missing limiter: WS8 measured ~20,000 req/s over 8 keep-alive connections with zero 429s (600 sequential accounts/lookup: 600 x 401). Decision: Q5 settled 2026-11-02: (a) blanket per-source and per-account limiter on all of /api/v1, before any network fetch, generous defaults (registry-api-v1 §3).

Where: browserid-registrar/src/lib.rs:205-237 (the v1 router has only body-size and buffer_body); browserid-registrar/src/approvals.rs:30-39, :57-104 (anyone opens approvals for any account id up to MAX_PENDING=5, so a victim's queue can be filled -> login_rejected for the real device; W5-9).

Change: reuse browserid-broker/src/routes/rate_limit.rs as a layer on the v1 router (per IP, with a lower bucket on /api/v1/login and /api/v1/approvals, and a per-account bucket on approvals opens), applied before any DNSSEC/status fetch. client_ip must take the proxy's own hop (blocked by the W5-6 XFF bean). Generous defaults; return 429 with Retry-After.

Acceptance (un-ignore): browserid-broker/tests/authz_matrix_test.rs: api_v1_login_guessing_is_throttled. The W5-9 pin anon_is_refused_on_every_api_v1_session_route keeps passing. Bean browserid-ng-oawf carries this item too; close both together.

Reports: ws5 §1 (D8) and §2 (W5-9), ws8 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.



## Summary of Changes

- routes/rate_limit.rs: a reusable fixed-window `Limiter` (the verification API's bucket now uses it) and a new `api_v1` middleware applied to the registrar router in routes/mod.rs (the registrar crate itself is untouched). It answers `429 {"error":"slow_down"}` + `Retry-After` (registry-api-v1 §3) before the handler runs, so before any DNSSEC/status fetch:
  - blanket per-source bucket on everything under `/api/v1`: 3000/min (50 r/s; the audit measured ~20k r/s unlimited);
  - `POST /api/v1/login`: failures-only buckets, 20 per source per 5 min and 60 per account per 5 min (the account id is read from the body, hashed before it keys the map); successes never count, so wallets are unaffected;
  - `POST /api/v1/approvals` (opens, W5-9): 30 per source per minute. No per-account cap on opens: `MAX_PENDING=5` already bounds the queue and a per-account bucket would be a cheaper lockout than the one it prevents.
  - The source address is the trusted proxy hop (bean gajq).
- Tests: un-ignored `api_v1_login_guessing_is_throttled` (authz_matrix 13 passed, registry_api_test 12 passed, status_endpoints 7 passed). The W5-9 pin `anon_is_refused_on_every_api_v1_session_route` still passes.
- No new env var: the limits are constants in rate_limit.rs. Bean browserid-ng-oawf carries this item too and can close with it.
