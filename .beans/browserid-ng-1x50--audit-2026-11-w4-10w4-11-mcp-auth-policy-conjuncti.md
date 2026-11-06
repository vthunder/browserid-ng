---
# browserid-ng-1x50
title: '[Audit 2026-11] W4-10/W4-11: mcp-auth policy conjunction in Lane A; refresh requires client_id'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:37:13Z
parent: browserid-ng-ag1l
---

Findings: W4-10 and W4-11 (mcp-auth OAuth lane hardening). Severity: Low. Decision: none needed.

Where: sdk/mcp-auth/index.mjs createAuthCodeLane vs createMcpAuth.handleToken: policy conjunction runs only in connection mode, so with createAuthCodeLane({policy}) a jwt-bearer (Lane A) presentation from a non-owner with no covering policy row still mints a bearer and authenticate returns permittedBy: null (the gate compensates at /mcp; mcp-demo configures no policy, so no live exposure; a footgun for other consumers). index.mjs:1323: the refresh grant accepts a request with no client_id (p.client_id != null && ...) while the authorization-code branch requires it; OAuth 2.1 §4.3.1 makes it REQUIRED for public clients (rotation and family burn bound the impact).

Change: make policy live on createMcpAuth so Lane A mints conjoin too; require p.client_id === rt.clientId on refresh.

Acceptance: un-skip sdk/mcp-auth/test/audit_2026_11_ws4.test.mjs: "W4-10: with policy configured, a jwt-bearer presentation from a non-owner with no covering row must not mint", "W4-11: a refresh without client_id must be refused for a public client".

Reports: ws4 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

- W4-10, sdk/mcp-auth/index.mjs: `createAuthCodeLane.handleToken` routes jwt-bearer through a new `handleJwtBearer`: the presentation mints via `mcpAuth.handleToken` as before, then — when the lane has `policy` — the §6.5 `conjoinPolicy` runs on the bearer's grantor; the stored grant is narrowed to S ∩ S′, both records' status refs, the earlier expiry and `permittedBy`; no covering row (or a 503 from the validator) withdraws the bearer and refuses the exchange. Lane A at a policy-mode server is thus no longer open. README documents it.
- W4-11: `handleRefresh` requires a string `client_id` (`invalid_request` when missing, OAuth 2.1 §4.3.1) and it must match the token's client.

Tests: un-skipped "W4-10: with policy configured, a jwt-bearer presentation from a non-owner with no covering row must not mint" and "W4-11: a refresh without client_id must be refused"; the "today the Lane A mint ignores the policy layer" pin became "a covered non-owner mints S ∩ S′ under the permitter's grant". Existing refresh calls in sdk/mcp-auth/test/connection-lane.test.mjs and sdk/gate/test/policy.test.mjs now send `client_id`. Gate consequence: a member the records do not cover is refused at `/token` (400) instead of first minting and failing at `/mcp` (403), and policy-minted bearers now carry the policy row's status refs (re-checked per call); sdk/gate/test/audit_2026_11_ws4.test.mjs (`attempt`/`refused`) and roles.test.mjs (`expectRefused`, a `/status/check` route on its mock broker) accept either refusal point. mcp-auth 68 pass; gate 81 pass.
