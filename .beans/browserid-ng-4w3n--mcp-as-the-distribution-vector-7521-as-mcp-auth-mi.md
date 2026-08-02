---
# browserid-ng-4w3n
title: 'MCP as the distribution vector: 7521 AS + mcp-auth middleware + flagship warrant-gated server'
status: draft
type: epic
created_at: 2026-08-02T21:54:40Z
updated_at: 2026-08-02T21:54:40Z
---

Design: docs/plans/2026-08-02-mcp-distribution-design.md (companion to the 2026-08-02 roadmap doc, Theme 2).

Ride MCP's OAuth 2.1 model via the RFC 7521 assertion grant (ported from the bsky bridge's /browserid/token): each MCP server embeds a tiny AS that redeems warrant presentations for short-lived scoped bearers; hosts run unmodified. Authority stays minted at the issuer (approval hop + status ref), so revocation remains visible and one-click at the issuer's UI (browserid.me/account) no matter how many ASes exist — every AS fail-closes on the issuer's status list, checked per tool call.

First epic = one artifact in three parts:
1. @browserid-ng/mcp-auth middleware (TS SDK first): embedded 7521 AS, per-call fail-closed status checks, scope->tool mapping, ctx.grantor/grantee/holder, optional per-call attestation hook
2. Flagship demo: warrant-gated GitHub MCP server — 'stop putting PATs in your MCP config'; revoke kills the agent mid-conversation
3. Wallet distribution: registries + MCPB/DXT one-click + Docker catalog; approval-pending push notification

Then: scope conventions registry; later, MCP spec-community engagement from working code.

Open questions in the doc: hosted-AS convenience option, bearer TTL vs per-call check cost, scope negotiation UX, remote-wallet identity portability.
