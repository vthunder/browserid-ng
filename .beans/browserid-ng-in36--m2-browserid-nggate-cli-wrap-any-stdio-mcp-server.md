---
# browserid-ng-in36
title: 'M2: @browserid-ng/gate CLI — wrap any stdio MCP server, gated'
status: todo
type: feature
priority: high
created_at: 2026-08-12T12:21:46Z
updated_at: 2026-08-12T13:29:36Z
parent: browserid-ng-81s6
blocked_by:
    - browserid-ng-b6pp
---

Thin CLI over mcp-auth: run an arbitrary stdio MCP server as a child, proxy JSON-RPC over MCP Streamable HTTP, gate every request through mcp-auth fail-closed. Features: grantor allowlist (--allow emails), tool->scope auto-map (derive tool:<name> from the child's tools/list so approval cards render with zero config), per-call attribution logging (grantee acting for grantor · tool · args-digest). Dogfood by wrapping ONE recognizable local-data OSS server (filesystem or sqlite). Blocked by M1 (needs the auth-code lane for generic hosts). Parent epic browserid-ng-81s6.

DECIDED 2026-08-12: first wrap target = official filesystem server (share a notes folder). Stateless-ish → one shared child is correct. tool→scope literal (tool:read_file, tool:write_file, …).
