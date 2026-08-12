---
# browserid-ng-81s6
title: 'MCP gateway: hobbyist→SaaS pipeline for BrowserID-authed MCP'
status: todo
type: epic
priority: high
created_at: 2026-08-12T12:21:46Z
updated_at: 2026-08-12T12:21:46Z
---

Strategic pivot of the MCP-distribution thesis: from demos-that-prove-capability to a tool people adopt for themselves (Tailscale's playbook). One command wraps ANY stdio MCP server as a remote, BrowserID-gated endpoint — allowlist by email, per-call attribution, per-person revocation — and the same mcp-auth middleware scales to small SaaS. Design: docs/plans/2026-08-12-mcp-gateway-hobbyist-to-saas.md. The critical-path unlock is the authorization-code lane (generic OAuth hosts like claude.ai), which mcp-auth does NOT have today (assertion grant only).
