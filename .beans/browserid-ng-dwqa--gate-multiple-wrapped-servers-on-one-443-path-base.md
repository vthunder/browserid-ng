---
# browserid-ng-dwqa
title: 'gate: multiple wrapped servers on one 443 (path-based mounting) — hobbyists can''t sacrifice the only https port per server'
status: in-progress
type: feature
priority: high
created_at: 2026-08-12T15:52:27Z
updated_at: 2026-08-12T16:11:26Z
parent: browserid-ng-81s6
---

Finding from M3 (2026-08-12): managed hosts (claude.ai) reject non-standard ports client-side, so a gated MCP server effectively MUST be on 443. Tailscale funnel gives one node one hostname + the funnel ports 443/8443/10000, but only 443 is host-compatible — so a hobbyist can run only ONE gated server without sacrificing their main https port. That's limiting (they may want notes + photos + home-assistant etc.).

Solution: path-based multi-mount on ONE 443 funnel. claude.ai accepts path URLs (https://host/notes/mcp), so this is host-compatible. Two shapes:
(A) gate supports a base path in --resource (e.g. --resource https://host/notes): serve ALL endpoints under that prefix and follow RFC 9728/8414 path-based well-known conventions (protected-resource metadata at /.well-known/oauth-protected-resource/notes; WWW-Authenticate points there); user configures tailscale funnel path routing (tailscale serve/funnel --set-path=/notes http://localhost:8787) per gate. Smaller gate change, more tailscale config.
(B) one gate process mounts multiple wrapped servers under paths: 'gate --mount /notes -- server1 --mount /photos -- server2', one 443 funnel, gate routes internally by path prefix. Cleanest UX, bigger feature. Each mount = its own resource/audience/allowlist/scopes.

Recommend (B) as the product (one command, one funnel, N servers), with (A)'s base-path support as the enabling primitive underneath. Parent epic browserid-ng-81s6.

SUBSUMED by gate v2 (browserid-ng-oxio): multi-mount is a core piece of the console appliance.
