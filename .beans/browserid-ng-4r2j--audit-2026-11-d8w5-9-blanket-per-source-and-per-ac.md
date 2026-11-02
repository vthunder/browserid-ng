---
# browserid-ng-4r2j
title: '[Audit 2026-11] D8/W5-9: blanket per-source and per-account rate limiter on /api/v1 (429 before any fetch)'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-02T22:43:59Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-gajq
---

Findings: D8 (WS1/WS5/WS8) and W5-9 (Info). Severity: Medium. The approval-code takeover was refuted (approvals.rs:179-234 requires an enrolled session on the same account); what stands is the missing limiter: WS8 measured ~20,000 req/s over 8 keep-alive connections with zero 429s (600 sequential accounts/lookup: 600 x 401). Decision: Q5 settled 2026-11-02: (a) blanket per-source and per-account limiter on all of /api/v1, before any network fetch, generous defaults (registry-api-v1 §3).

Where: browserid-registrar/src/lib.rs:205-237 (the v1 router has only body-size and buffer_body); browserid-registrar/src/approvals.rs:30-39, :57-104 (anyone opens approvals for any account id up to MAX_PENDING=5, so a victim's queue can be filled -> login_rejected for the real device; W5-9).

Change: reuse browserid-broker/src/routes/rate_limit.rs as a layer on the v1 router (per IP, with a lower bucket on /api/v1/login and /api/v1/approvals, and a per-account bucket on approvals opens), applied before any DNSSEC/status fetch. client_ip must take the proxy's own hop (blocked by the W5-6 XFF bean). Generous defaults; return 429 with Retry-After.

Acceptance (un-ignore): browserid-broker/tests/authz_matrix_test.rs: api_v1_login_guessing_is_throttled. The W5-9 pin anon_is_refused_on_every_api_v1_session_route keeps passing. Bean browserid-ng-oawf carries this item too; close both together.

Reports: ws5 §1 (D8) and §2 (W5-9), ws8 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
