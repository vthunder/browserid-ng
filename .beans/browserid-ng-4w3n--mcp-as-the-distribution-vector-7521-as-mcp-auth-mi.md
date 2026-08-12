---
# browserid-ng-4w3n
title: 'MCP as the distribution vector: 7521 AS + mcp-auth middleware + flagship warrant-gated server'
status: in-progress
type: epic
priority: normal
created_at: 2026-08-02T21:54:40Z
updated_at: 2026-08-12T07:00:08Z
---

Design: docs/plans/2026-08-02-mcp-distribution-design.md (companion to the 2026-08-02 roadmap doc, Theme 2).

Ride MCP's OAuth 2.1 model via the RFC 7521 assertion grant (ported from the bsky bridge's /browserid/token): each MCP server embeds a tiny AS that redeems warrant presentations for short-lived scoped bearers; hosts run unmodified. Authority stays minted at the issuer (approval hop + status ref), so revocation remains visible and one-click at the issuer's UI (browserid.me/account) no matter how many ASes exist — every AS fail-closes on the issuer's status list, checked per tool call.

First epic = one artifact in three parts:
1. @browserid-ng/mcp-auth middleware (TS SDK first): embedded 7521 AS, per-call fail-closed status checks, scope->tool mapping, ctx.grantor/grantee/holder, optional per-call attestation hook
2. Flagship demo: warrant-gated GitHub MCP server — 'stop putting PATs in your MCP config'; revoke kills the agent mid-conversation
3. Wallet distribution: registries + MCPB/DXT one-click + Docker catalog; approval-pending push notification

Then: scope conventions registry; later, MCP spec-community engagement from working code.

Open questions in the doc: hosted-AS convenience option, bearer TTL vs per-call check cost, scope negotiation UX, remote-wallet identity portability.


## Flight-build slice (2026-08-10)
Concrete autonomously-buildable slice specced in docs/plans/2026-08-10-mcp-auth-flight-build-spec.md: @browserid-ng/mcp-auth (sdk/mcp-auth) = 7521 token endpoint (embedded AS) + requireWarrant() bearer middleware with fail-closed per-call status re-check + OAuth discovery metadata + scope->tool map + ctx(grantor/grantee/holder); retrofit guestbook-mcp onto it as the bearer-flow reference server; unit+integration tests; deploy the reference server; NO npm publish. Verification delegated to the hosted DNSSEC /verify-access (no crypto in JS). Deferred: GitHub flagship (needs OAuth app+creds), Python/FastMCP, MCPB/DXT bundle+registry, scope registry, per-call attestation, remote-wallet portability.

## Flight build SHIPPED (2026-08-10, commit e57e7e4, deployed)

@browserid-ng/mcp-auth (sdk/mcp-auth) + reference server (mcp-demo) built, tested, and deployed live at https://mcp-demo.browserid.me.

- mcp-auth: 7521 jwt-bearer token endpoint (embedded AS) → short-lived scoped bearer; requireWarrant()/authenticate() with FAIL-CLOSED per-call status re-check (via /status/check); OAuth discovery metadata (RFC 9728/8414); scope-as-ceiling (narrow-not-widen); ctx.grantor/grantee/holder attribution. Verification delegated to the hosted DNSSEC /verify-access — no crypto in JS. 16 unit tests green + index.d.ts + README.
- mcp-demo: attributed-action-log reference server on the middleware; verified end-to-end against a mock broker (token→bearer→tools/list) and in prod (discovery + /token wired to the REAL broker: bogus assertion → invalid_grant; /mcp 401 without bearer). Dockerfile + CI workflow (deploy-mcp-demo.yml) + infra conf (sandmill-infra/apps/mcp-demo.conf); dokku app on the id-host, TLS live.
- Deploy path: CI builds+pushes GHCR image; released manually via mini-ops git:from-image (CI ssh step still o7ip).

Left for the user (needs a real warrant approval / creds, not autonomous): the live agent-driven "revoke kills the agent mid-conversation" demo; the GitHub flagship conversion; Python/FastMCP middleware; MCPB/DXT bundle + registry publish; scope-conventions registry; per-call attestation hook; remote-wallet identity portability. npm publish of @browserid-ng/mcp-auth deliberately NOT done (supervised release).

Published to npm 2026-08-12: @browserid-ng/mcp-auth 0.1.0 (zero runtime deps). Also out the same day: verify 0.2.0, express/hono/fastify 0.1.0, wallet 0.4.4 (approval-contract fix). All scratch-install verified.
