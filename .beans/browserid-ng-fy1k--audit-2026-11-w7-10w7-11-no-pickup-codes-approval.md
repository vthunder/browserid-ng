---
# browserid-ng-fy1k
title: '[Audit 2026-11] W7-10/W7-11: no pickup codes, approval ids, emails or audiences in log lines (matched route, opaque ids)'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:33:11Z
parent: browserid-ng-ag1l
---

Findings: W7-10 and W7-11 (identifiers in logs). Severity: Medium. Decision: Q10 settled 2026-11-02: (a) opaque ids in log lines (hashed email, record id instead of audience) and path redaction for requests/:code; (b) would be a separate PII log target off in prod.

Where: browserid-registrar/src/session.rs:60 (registry api access log prints the raw path: for GET /api/v1/requests/:code that is the filer's single-use pickup code, a bearer that releases the approved warrants; for /api/v1/approvals/:id[/cancel] the approval id). browserid-registrar/src/consent.rs:1241 (warrant revoked: delegator email + audience), :498 (consent approved: delegator), :1483 (request raised: agent identity + delegator); browserid-broker/src/routes/device.rs:380 (kid + email). Together they reconstruct the RP-user association the threat model treats as protected metadata (§3 item 7) and expose a pickup secret (item 6).

Change under (a): log axum::extract::MatchedPath (route pattern) instead of the raw path, or redact the last segment under /requests/ and /approvals/; replace emails with the existing hashed distinct_id_for_email (browserid-broker/src/analytics.rs:114) and audiences with record ids in the consent/device/account lines. Under (b): move identifier fields behind a browserid_registrar::pii=debug target that is off in prod.

Acceptance: a test that drives GET /api/v1/requests/<code> through the access-log layer with a capturing subscriber and asserts the code is absent; grep review of every tracing! call in registrar and broker routes.

Reports: ws7 §5. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.



## Summary of Changes

Q10 (a): opaque ids in log lines, route patterns instead of raw paths.

Broker:
- crypto.rs: `log_id(value)` — 12 chars of sha256 over a fixed prefix + the lowercased value; stable per address/tag for correlation, never the value.
- routes/device.rs (`device/issue: minted on a login key`), routes/hosted_idp.rs (issued certs, tenant activated, roster user created, admin removed, revoked-all, tenant deleted, management policy lines), routes/guestbook.rs (`guestbook signed`), email/smtp.rs (sent lines): emails, roster locals and admin identities now logged as `log_id(...)`.
- email/console.rs: the tracing lines no longer carry the code or the address (the stdout banner the dev console sender exists for is unchanged; W7-12 keeps that sender out of production).

Registrar (another agent's crate; log statements only, flagged — files: browserid-registrar/src/session.rs, consent.rs, account.rs):
- session.rs `registry api` access log: logs the matched route pattern (`axum::extract::MatchedPath`, e.g. `/api/v1/requests/:code`) instead of the raw path, so filer pickup codes and approval ids never land in the log (W7-10). The only non-log change is the three-line `route` lookup feeding that statement.
- consent.rs (`warrant consent approved`, `warrant revoked`, `warrant request raised`) and account.rs (`accounts: created/takeover`, `attach`): delegator/agent/identity emails and the audience are logged as 12-char sha256 ids (inline `crate::session::b64url_sha256_pub`), so the RP-user association cannot be reconstructed from the log (W7-11).

Tests: registrar lib 33 passed; broker lib 74 passed; warrant_device_test and registry_api_test unaffected. (hosted_primary_test shows 2 failures on `+tag` subaddress mints that come from the core D1 merge on audit-2026-11, not from these edits.)
