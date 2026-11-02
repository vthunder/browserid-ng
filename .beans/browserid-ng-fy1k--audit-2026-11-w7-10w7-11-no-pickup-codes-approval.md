---
# browserid-ng-fy1k
title: '[Audit 2026-11] W7-10/W7-11: no pickup codes, approval ids, emails or audiences in log lines (matched route, opaque ids)'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W7-10 and W7-11 (identifiers in logs). Severity: Medium. Decision: Q10 settled 2026-11-02: (a) opaque ids in log lines (hashed email, record id instead of audience) and path redaction for requests/:code; (b) would be a separate PII log target off in prod.

Where: browserid-registrar/src/session.rs:60 (registry api access log prints the raw path: for GET /api/v1/requests/:code that is the filer's single-use pickup code, a bearer that releases the approved warrants; for /api/v1/approvals/:id[/cancel] the approval id). browserid-registrar/src/consent.rs:1241 (warrant revoked: delegator email + audience), :498 (consent approved: delegator), :1483 (request raised: agent identity + delegator); browserid-broker/src/routes/device.rs:380 (kid + email). Together they reconstruct the RP-user association the threat model treats as protected metadata (§3 item 7) and expose a pickup secret (item 6).

Change under (a): log axum::extract::MatchedPath (route pattern) instead of the raw path, or redact the last segment under /requests/ and /approvals/; replace emails with the existing hashed distinct_id_for_email (browserid-broker/src/analytics.rs:114) and audiences with record ids in the consent/device/account lines. Under (b): move identifier fields behind a browserid_registrar::pii=debug target that is off in prod.

Acceptance: a test that drives GET /api/v1/requests/<code> through the access-log layer with a capturing subscriber and asserts the code is absent; grep review of every tracing! call in registrar and broker routes.

Reports: ws7 §5. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
