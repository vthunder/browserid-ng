---
# browserid-ng-3k53
title: '[Audit 2026-11] D13: hosted wallet keeps status refs, re-checks on refresh, adds revoke/disconnect'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: D13. Severity: Low (RP-session semantics; the asset behind the session is a custodied agent key). Decision: Q21 settled 2026-11-02: (a) keep status refs, re-check status on refresh (fail closed), add disconnect; after the Mediums.

Where: wallet-service/src/server.mjs:116-120 (statusRefs dropped at login), src/oauth.mjs:213-227 (30-day refresh re-mints 1 h tokens with no verifier contact); no RFC 7009 revoke, no logout, no per-tenant disconnect; the accounts table stores only email, created_at.

Change under (a): persist statusRefs per account; call checkStatus on refresh and fail closed; add /oauth/revoke and a "disconnect all clients" page or MCP tool.

Acceptance: un-skip wallet-service/test/audit_2026_11_ws4.test.mjs "D13: a tenant can revoke a connection (RFC 7009 /oauth/revoke)"; the two D13 pins keep passing.

Reports: ws4 §1.5. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
