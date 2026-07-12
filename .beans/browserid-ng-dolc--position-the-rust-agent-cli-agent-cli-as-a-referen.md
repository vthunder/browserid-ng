---
# browserid-ng-dolc
title: Position the Rust agent CLI (agent_cli) as a reference tool
status: todo
type: task
priority: normal
created_at: 2026-07-12T10:32:28Z
updated_at: 2026-07-12T10:32:28Z
---

We built browserid-agent/examples/agent_cli.rs as the prod smoke harness, then made the JS @browserid/agent SDK + wallet MCP the primary agent path (removing the JS mint-assertion shell wrapper). The Rust CLI still exists as an example but is no longer surfaced. Extract/position it as a clearly-documented reference tool: a Rust equivalent of the JS SDK flow (provision, grant, assert, identity, warrants, revoke, token) for anyone building agents in Rust or wanting a language-agnostic smoke test. Consider moving/renaming for discoverability, a short README, and linking it from the main README alongside sdk/agent.

- [ ] Decide location/name (keep as example vs. dedicated reference dir)
- [ ] Short README documenting the commands + when to use it (Rust agents, smoke testing)
- [ ] Link from main README next to @browserid/agent
- [ ] Note parity with the JS SDK
