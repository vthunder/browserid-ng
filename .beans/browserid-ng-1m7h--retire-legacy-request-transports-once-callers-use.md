---
# browserid-ng-1m7h
title: Retire legacy request transports once callers use /api/v1/requests
status: todo
type: task
created_at: 2026-09-11T15:38:03Z
updated_at: 2026-09-11T15:38:03Z
---

Aliases kept by g69e that duplicate the generic lane: POST /warrant/request, /warrant/record-request, /warrant/poll, /agent-provision/request + /agent-provision/poll (filing/poll), plus the cookie+CSRF prepare/complete once they exist on the token lane (1iif). Steps: move callers — sdk/agent (device.mjs), sdk/wallet, sdk/mcp-auth (record-request + poll), browserid-agent (Rust), mingo-idp poster.rs — to POST /api/v1/requests {kind} + GET /api/v1/requests/<code>; then delete the alias routes, their handlers' public surface, and the well-known 'record-grants' advertisement; update registry-api-v1 §5.3 and core §7.5. Not retirable: /authorize and /consent pages (the wallet-hosted cards + the printed/no-JS link), /sign until 3y2q. Related: also let the filed warrant lane route by grantor pin so a service with its own cert (mingo-poster) can file kind warrant instead of riding provisioning.
