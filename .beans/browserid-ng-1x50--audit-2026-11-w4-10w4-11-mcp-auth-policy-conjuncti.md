---
# browserid-ng-1x50
title: '[Audit 2026-11] W4-10/W4-11: mcp-auth policy conjunction in Lane A; refresh requires client_id'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W4-10 and W4-11 (mcp-auth OAuth lane hardening). Severity: Low. Decision: none needed.

Where: sdk/mcp-auth/index.mjs createAuthCodeLane vs createMcpAuth.handleToken: policy conjunction runs only in connection mode, so with createAuthCodeLane({policy}) a jwt-bearer (Lane A) presentation from a non-owner with no covering policy row still mints a bearer and authenticate returns permittedBy: null (the gate compensates at /mcp; mcp-demo configures no policy, so no live exposure; a footgun for other consumers). index.mjs:1323: the refresh grant accepts a request with no client_id (p.client_id != null && ...) while the authorization-code branch requires it; OAuth 2.1 §4.3.1 makes it REQUIRED for public clients (rotation and family burn bound the impact).

Change: make policy live on createMcpAuth so Lane A mints conjoin too; require p.client_id === rt.clientId on refresh.

Acceptance: un-skip sdk/mcp-auth/test/audit_2026_11_ws4.test.mjs: "W4-10: with policy configured, a jwt-bearer presentation from a non-owner with no covering row must not mint", "W4-11: a refresh without client_id must be refused for a public client".

Reports: ws4 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
