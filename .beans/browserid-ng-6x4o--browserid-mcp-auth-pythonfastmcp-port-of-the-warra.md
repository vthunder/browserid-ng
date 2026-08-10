---
# browserid-ng-6x4o
title: 'browserid-mcp-auth: Python/FastMCP port of the warrant-gated MCP middleware'
status: completed
type: feature
priority: normal
created_at: 2026-08-10T06:09:27Z
updated_at: 2026-08-10T08:09:14Z
parent: browserid-ng-4w3n
---

Built 2026-08-10 (commit 3e76328). sdk/python-mcp-auth: 7521 jwt-bearer token endpoint + require_warrant()/authenticate() fail-closed per-call status + OAuth discovery + scope-as-ceiling + ctx attribution. Verification via hosted /verify-access + /status/check (no crypto in Python; stdlib urllib, http_post injectable). FastMCP notes in README. 14 stdlib-unittest tests + pyproject + sdk-tests CI. Deferred: a live FastMCP reference server; PyPI publish.

## Live reference server (2026-08-10, commit c571267): python-mcp-demo — a runnable FastMCP server on browserid-mcp-auth, deployed at https://python-mcp-demo.browserid.me (Python parallel of mcp-demo). 7521 token endpoint + OAuth discovery (custom routes) + on_call_tool middleware gating every tool call on require_warrant (bearer via get_http_headers(include={authorization}), fail-closed status). Integration test (token->bearer->log_action attribution + unauth rejected) gates the deploy CI and passed on a clean runner. Token endpoint wired to the real broker (bogus assertion -> invalid_grant).
