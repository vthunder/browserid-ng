---
# browserid-ng-kpr4
title: 'mcp-demo: mount Lane B (authorization_code) so real MCP hosts can connect'
status: completed
type: feature
priority: normal
created_at: 2026-08-13T14:12:48Z
updated_at: 2026-08-13T15:55:57Z
---

mcp-demo only mounted Lane A (7521 jwt-bearer), so no interactive MCP host could add it — the demo was only runnable by simulating MCP over curl (Dan's critique, 2026-08-13). Lane A-only was an implementation artifact, not a design: the durable taxonomy is verifyPresentation for bespoke APIs, Lane B for agents-via-hosts (the normal MCP case), Lane A for headless agents/tests.

## Todo
- [x] server.mjs: mount createAuthCodeLane (register/authorize/authorize/return; token + AS metadata via the lane, serving BOTH grants); CORS headers (claude.ai preflights); friendly consumed-return page; credential from BROWSERID_CREDENTIAL env (Lane A-only fallback with a warning when absent)
- [x] local smoke test (fake credential): discovery advertises both lanes, /register works, jwt-bearer lane unchanged
- [x] provision the demo's service identity (one human approval) + dokku config:set
- [x] deploy + verify: add as a real connector from Claude Code's MCP machinery end-to-end
- [x] update /mcp-demo runbook page (no terminal needed) + demos Labs row + llms.txt

## Summary of Changes

- mcp-demo mounts createAuthCodeLane alongside the assertion grant: /register, /authorize, /authorize/return; /token + AS metadata serve both grants; CORS for host preflights; friendly consumed-return page; landing page shows the connector URL. Credential via $BROWSERID_CREDENTIAL (Lane A-only fallback + warning without it).
- Service identity provisioned (danmills+mcp-demo2@sandmill.org, sandmill.org IdP; label 'browserid MCP demo'); dokku config:set --encoded on mcp-demo. Took 3 approval links: #1 expired, #2's process died on a transient broker connect timeout mid-poll (fix: retrying fetch wrapper via ensureCredential's http option).
- CI was red before this change: deploy-mcp-demo + sdk-tests never ran npm install for mcp-auth, and the authcode tests (added 8/12) import @browserid-ng/agent — both workflows fixed (commit 1528908).
- Prod verified headlessly: both grants advertised, DCR mints clients, /authorize 302s to a real broker consent URL.
- Site: revoke demo graduated from Labs to main demos row 3 (no terminal needed, copyable connector URL); /mcp-demo runbook is connector-first with the assertion lane documented as the headless path; llms.txt updated. Labs keeps FedCM + mingo.
- NOT yet done: a human-completed connector add from claude.ai (needs Dan's browser). python-mcp-demo remains assertion-lane only, documented as such.
