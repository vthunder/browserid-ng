---
# browserid-ng-oxio
title: 'gate v2: multi-server gateway with a BrowserID-gated admin console'
status: in-progress
type: feature
priority: high
created_at: 2026-08-12T16:11:26Z
updated_at: 2026-08-12T16:11:26Z
parent: browserid-ng-81s6
---

npx @browserid-ng/gate --admin <email> → auto-port + auto-funnel(443) + gateway identity, prints 'configure at https://host/'. Admin signs in with BrowserID (gated to --admin) to a console that adds MCP servers (name, mount path, command, allowlist), each published warrant-gated at https://host/<mount>/mcp. One process, one funnel, N servers. Subsumes dwqa (multi-mount) + k2rz (mgmt UI). Design/spec: docs/plans/2026-08-12-gate-v2-admin-console.md. SECURITY-CRITICAL: public console + arbitrary-command spawn, gated ONLY by the BrowserID admin login — that login (verify presentation, audience==console origin, email==admin exact, signed session, CSRF) must be rock-solid.
