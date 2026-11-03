---
# browserid-ng-i4kj
title: '[Audit 2026-11] W5-2: throttle /idp/login and /idp/password; dummy bcrypt on the miss path'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:19:44Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-gajq
---

Findings: W5-2 (July M6 class on the hosted primary). Severity: Medium. Decision: none needed.

Where: browserid-broker/src/routes/hosted_idp.rs:186-216 (/idp/login), :263-303 (/idp/password): bcrypt runs only when the tenant and roster entry exist (no dummy hash -> timing oracle) and nothing ever answers 429. July M6 covered only the broker login.

Change: reuse the login_attempts window keyed idp|ip (as routes/auth.rs:84-107 does for the broker login) and verify against a dummy hash on the miss path so existing and non-existing roster entries take the same time. Depends on the client-IP hop fix (W5-6 bean) for the limiter to be meaningful behind a proxy.

Acceptance (un-ignore): browserid-broker/tests/authz_matrix_test.rs: idp_login_is_throttled. Bean browserid-ng-oawf carries this item too.

Reports: ws5 §2 and §4 (M6 row). Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.



## Summary of Changes

- routes/hosted_idp.rs: `/idp/login` and `/idp/password` go through one `check_roster_password` that (1) refuses 429 when the client IP's failed-attempt window is at the cap (`login_attempts` key `idp|<ip>`, same 10-failures-per-5-minutes shape as the broker login), (2) runs exactly one bcrypt verification on every path, against `auth::dummy_password_hash()` when the tenant, roster entry or active hash is missing, so timing no longer reveals whether a tenant or roster entry exists, and (3) counts every refusal against the IP. The client IP is the trusted proxy hop (bean gajq).
- routes/auth.rs: the login throttle helpers (`login_throttled`, `record_login_failure`, the constants, `dummy_password_hash`) are `pub(crate)` for reuse.
- Tests: un-ignored `idp_login_is_throttled` (authz_matrix_test 12 passed; hosted_primary_test 20 passed; audit_2026_11_ws4 14 passed).
