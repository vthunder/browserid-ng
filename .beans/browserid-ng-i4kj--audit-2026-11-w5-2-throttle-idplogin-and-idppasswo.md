---
# browserid-ng-i4kj
title: '[Audit 2026-11] W5-2: throttle /idp/login and /idp/password; dummy bcrypt on the miss path'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-02T22:44:00Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-gajq
---

Findings: W5-2 (July M6 class on the hosted primary). Severity: Medium. Decision: none needed.

Where: browserid-broker/src/routes/hosted_idp.rs:186-216 (/idp/login), :263-303 (/idp/password): bcrypt runs only when the tenant and roster entry exist (no dummy hash -> timing oracle) and nothing ever answers 429. July M6 covered only the broker login.

Change: reuse the login_attempts window keyed idp|ip (as routes/auth.rs:84-107 does for the broker login) and verify against a dummy hash on the miss path so existing and non-existing roster entries take the same time. Depends on the client-IP hop fix (W5-6 bean) for the limiter to be meaningful behind a proxy.

Acceptance (un-ignore): browserid-broker/tests/authz_matrix_test.rs: idp_login_is_throttled. Bean browserid-ng-oawf carries this item too.

Reports: ws5 §2 and §4 (M6 row). Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
