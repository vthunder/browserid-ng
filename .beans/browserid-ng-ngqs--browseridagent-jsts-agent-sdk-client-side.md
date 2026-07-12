---
# browserid-ng-ngqs
title: '@browserid/agent — JS/TS agent SDK (client side)'
status: completed
type: feature
priority: high
created_at: 2026-07-12T08:54:03Z
updated_at: 2026-07-12T09:14:27Z
---

A Node/TS agent-side SDK mirroring browserid-agent (Rust): load credential, provision a delegated identity, request warrants (consent URL + await approval), mint warrant-backed assertions, refresh certs, revoke. Enables Node-only agent integration and lets the MCP demo drop the cargo shell-out + temp-file plumbing and run in pure-MCP clients (Claude Desktop) via a wallet MCP server.

Acceptance: a wallet MCP server (get_assertion tool) built on the SDK, driving the notes-server demo end to end with no Rust and no shell.

Faithful port — must match the Rust wire formats + signing inputs exactly (verified against the same broker/IdP and the Rust test vectors).

- [ ] Map Rust wire protocol + signing (endpoints, request/response shapes, JWS canonicalization)
- [ ] Ed25519 + JWT/JWS primitives (crypto.subtle) with cross-checks vs browserid-core
- [ ] Credential load + identity() (names/patterns)
- [ ] provision (endorse -> mint)
- [ ] requestWarrant/obtainWarrant (consent URL + await approval; scope-aware)
- [ ] assertionFor (agent_cert~warrant~assertion) + cert refresh
- [ ] persistence (save/load identity), revoke
- [ ] typed errors (NeedCredential, AmbiguousName, ...)
- [ ] wallet MCP server demo + turnkey Claude Desktop path
- [ ] tests vs a live/local broker (parity with Rust)
