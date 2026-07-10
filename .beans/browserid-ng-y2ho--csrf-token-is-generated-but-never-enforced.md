---
# browserid-ng-y2ho
title: CSRF token is generated but never enforced
status: completed
type: bug
priority: high
created_at: 2026-07-08T06:13:39Z
updated_at: 2026-07-10T23:50:47Z
parent: browserid-ng-8u60
---

session_context returns csrf_token but NO state-changing handler reads/compares it. Practical CSRF only incidentally blocked (application/json requirement + CORS Any without allow_credentials).
- [ ] Enforce csrf_token on all POST /wsapi mutations, OR remove it so it doesn't imply protection
- [ ] Tests

## Summary of Changes (2026-07-11)

CSRF is now enforced (403 'Invalid CSRF token') on every session-authenticated state-changing endpoint: logout, update_password, set_parent, stage_email, remove_email, cert_key, account_cancel, set_password — via a shared require_csrf helper in routes/session.rs; the already-enforcing agent/warrant endpoints were unified onto the same helper. Pre-auth and emailed-token flows (stage_user, authenticate_user, complete_*, stage/complete_reset, auth_with_assertion) are deliberately not gated. Clients updated: network.js already sent csrf (now also drops its cached context on login, which rotates the token); dialog.js apiCall injects a fresh token per POST; account.html post() auto-injects; consent.html cert_key call included. All broker integration tests updated + new test_cert_key_missing_csrf; workspace green.

Note: exploitability was already limited (JSON-only extractors reject form posts; CORS never allows credentials), so this is defense-in-depth — now consistent with the SameSite=Lax cookie (0eud).
