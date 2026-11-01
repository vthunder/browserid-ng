---
# browserid-ng-n6nn
title: 'Audit WS4: code review of never-audited layers: agent/MCP, wallet, hosted IdP'
status: todo
type: task
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-01T15:43:06Z
parent: browserid-ng-ag1l
---

sdk/mcp-auth + sdk/gate (OAuth 2.1 AS, 7521 assertions, per-call status, audience confusion, warrant scope enforcement, what an MCP server can induce an agent to sign); wallet extension + wallet-service (key storage, origin checks on messaging, WinChan/popup trust, request-lanes consent clarity); browserid-agent SDK + mingo CLI key custody; hosted primary IdP tenancy (custodial keys, tenant isolation, DNS delegation checks); OIDC bridge; signing grants; cookie session admission. Reviewer-then-skeptic method as in July.

## From WS1 — candidates to confirm/refute
D3 hosted_idp holder passthrough; D5 mcp-auth/gate ignore bindings; D6 gate fails open on 503 and single-server mode never re-checks; D12 wallet signs under unverified stored grants; D13 wallet-service drops status refs; D17 local-part case folding; D19 FedCM server-side warrant with no refs; D20 binding.id not 1:1 in mcp-auth. See docs/security-audit-2026-11-ws1-spec-review.md §1.
