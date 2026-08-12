---
# browserid-ng-v6am
title: 'SBO/on-chain MCP server: agent posts on-chain via warrant, verifiable end-to-end like mingo.place'
status: todo
type: feature
priority: low
created_at: 2026-08-12T11:34:35Z
updated_at: 2026-08-12T11:34:35Z
---

The mingo/SBO stack already shows an agent acting on-chain on a human's behalf, scoped + revocable, verified on-chain (BrowserID-native both sides — the categorical no-honeypot story). The only gap is an MCP server front-end so an agent in Claude/any MCP host can drive it the way mingo.place does via the web. Build a warrant-gated MCP server (on @browserid-ng/mcp-auth) whose tools post/sign on-chain to SBO, reusing the mingo warrant audience (sbo+raw://...). Caveat noted by the user 2026-08-12: this demo is deeply abstract (identity+blockchain nerd intersection), so it's a 'sometime' build, not a priority — the categorical claim is already provable via mingo.place without it. File now so it's not lost.
