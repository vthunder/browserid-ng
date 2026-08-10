---
# browserid-ng-6x4o
title: 'browserid-mcp-auth: Python/FastMCP port of the warrant-gated MCP middleware'
status: completed
type: feature
created_at: 2026-08-10T06:09:27Z
updated_at: 2026-08-10T06:09:27Z
parent: browserid-ng-4w3n
---

Built 2026-08-10 (commit 3e76328). sdk/python-mcp-auth: 7521 jwt-bearer token endpoint + require_warrant()/authenticate() fail-closed per-call status + OAuth discovery + scope-as-ceiling + ctx attribution. Verification via hosted /verify-access + /status/check (no crypto in Python; stdlib urllib, http_post injectable). FastMCP notes in README. 14 stdlib-unittest tests + pyproject + sdk-tests CI. Deferred: a live FastMCP reference server; PyPI publish.
