---
# browserid-ng-in36
title: 'M2: @browserid-ng/gate CLI — wrap any stdio MCP server, gated'
status: todo
type: feature
priority: high
created_at: 2026-08-12T12:21:46Z
updated_at: 2026-08-12T14:43:24Z
parent: browserid-ng-81s6
blocked_by:
    - browserid-ng-b6pp
---

Thin CLI over mcp-auth: run an arbitrary stdio MCP server as a child, proxy JSON-RPC over MCP Streamable HTTP, gate every request through mcp-auth fail-closed. Features: grantor allowlist (--allow emails), tool->scope auto-map (derive tool:<name> from the child's tools/list so approval cards render with zero config), per-call attribution logging (grantee acting for grantor · tool · args-digest). Dogfood by wrapping ONE recognizable local-data OSS server (filesystem or sqlite). Blocked by M1 (needs the auth-code lane for generic hosts). Parent epic browserid-ng-81s6.

DECIDED 2026-08-12: first wrap target = official filesystem server (share a notes folder). Stateless-ish → one shared child is correct. tool→scope literal (tool:read_file, tool:write_file, …).



## Summary of Changes (agent, worktree agent-a96c5017b4b08eb1b)

Built `sdk/gate/` — the `@browserid-ng/gate` package. NOT marked completed; awaiting human review.

Files:
- `sdk/gate/package.json` — bin `gate`, deps file:../mcp-auth + file:../agent + @modelcontextprotocol/sdk.
- `sdk/gate/src/gate.mjs` — `createGateService()`: connects to the stdio child (MCP SDK Client/StdioClientTransport), auto-maps tools→`tool:<name>` scopes from the child's tools/list, builds mcpAuth + createAuthCodeLane, serves the HTTP surface. /mcp is proxied via a low-level MCP `Server` per request (preserves the child's real JSON schemas) → forwards tools/call to the ONE shared child. Grantor allowlist enforced (403) after authenticate, before any tool runs. One attribution line per call.
- `sdk/gate/src/credential.mjs` — gateway identity: `ensureCredential()` provisions once via requestProvision (prints approve URL, blocks), stores wallet-shape `{ credential }` in ~/.browserid-gate (0600/0700, GATE_HOME override).
- `sdk/gate/bin/gate.mjs` — the CLI: --allow/--name/--port/--resource/--broker + `-- <server cmd>`; provisions the gateway id on first run (approve link as LAST line), then spawns+gates+listens.
- `sdk/gate/index.d.ts`, `sdk/gate/README.md` (quickstart, tunnel recipes tailscale funnel/cloudflared, operator first-run, routes, lanes).
- `sdk/gate/test/gate.test.mjs` + `test/fixtures/fs-child.mjs` — 8 node --test checks, hermetic (mock broker + a REAL-fs stdio child fixture). All green.

Routes mounted: GET /.well-known/oauth-protected-resource, GET /.well-known/oauth-authorization-server (both lanes), POST /register, GET /authorize, GET /authorize/return, POST /token (jwt-bearer + authorization_code), POST /mcp, GET / + /healthz.

Tests prove: discovery serves both lanes; Lane B DCR mounted; child tools proxied with real schemas; a mcp-auth bearer reaches tools/call and gets a real filesystem result; attribution line emitted; allowlist-rejected grantor refused 403 before the tool runs; fail-closed revoke on a proxied call; 401 challenge without bearer. `npm test` = 8 pass / 0 fail.

mcp-auth integration: clean, no bugs found, no mcp-auth/agent/broker code touched. Used createAuthCodeLane for /token so BOTH grants terminate in one handler; lane.authorizationServerMetadata() advertises both lanes. The one ergonomic note: the low-level MCP `Server` (not `McpServer`) was the right proxy primitive — it lets tools/list return the child's JSON-Schema tools verbatim, which McpServer.registerTool (Zod-shape only) can't do.
