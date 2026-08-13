---
# browserid-ng-kpr4
title: 'mcp-demo: mount Lane B (authorization_code) so real MCP hosts can connect'
status: in-progress
type: feature
created_at: 2026-08-13T14:12:48Z
updated_at: 2026-08-13T14:12:48Z
---

mcp-demo only mounted Lane A (7521 jwt-bearer), so no interactive MCP host could add it — the demo was only runnable by simulating MCP over curl (Dan's critique, 2026-08-13). Lane A-only was an implementation artifact, not a design: the durable taxonomy is verifyPresentation for bespoke APIs, Lane B for agents-via-hosts (the normal MCP case), Lane A for headless agents/tests.

## Todo
- [ ] server.mjs: mount createAuthCodeLane (register/authorize/authorize/return; token + AS metadata via the lane, serving BOTH grants); CORS headers (claude.ai preflights); friendly consumed-return page; credential from BROWSERID_CREDENTIAL env (Lane A-only fallback with a warning when absent)
- [ ] local smoke test (fake credential): discovery advertises both lanes, /register works, jwt-bearer lane unchanged
- [ ] provision the demo's service identity (one human approval) + dokku config:set
- [ ] deploy + verify: add as a real connector from Claude Code's MCP machinery end-to-end
- [ ] update /mcp-demo runbook page (no terminal needed) + demos Labs row + llms.txt
