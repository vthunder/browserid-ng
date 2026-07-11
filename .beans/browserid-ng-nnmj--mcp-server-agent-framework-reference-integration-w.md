---
# browserid-ng-nnmj
title: MCP-server / agent-framework reference integration (wedge demo)
status: completed
type: feature
priority: normal
created_at: 2026-07-11T23:39:56Z
updated_at: 2026-07-11T23:55:27Z
---

Per GTM wedge sequencing (dogfood -> frameworks/MCP -> RPs): a reference MCP-server (or agent-framework) integration proving '5-minute agent auth' using browserid-ng agent identity. Most shareable adoption collateral for the agent-identity pitch.

## Summary of Changes

examples/mcp-agent-auth — a reference MCP server whose tools require an agent identity + human-signed warrant. authorize() verifies the caller's assertion via @browserid/verify and enforces the scope the human signed for the server's audience (post_note->post, list_notes->read). client.mjs presents an assertion from the agent CLI; mock-verifier + test.mjs run the full MCP client<->server flow over stdio with no network/consent and assert scope enforcement, agents-only, and fail-closed. Default verifier hosted browserid.me; VERIFIER_URL overrides.
