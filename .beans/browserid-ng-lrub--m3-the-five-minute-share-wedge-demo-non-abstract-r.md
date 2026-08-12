---
# browserid-ng-lrub
title: 'M3: the five-minute share (wedge demo, non-abstract, real server)'
status: todo
type: feature
priority: high
created_at: 2026-08-12T12:21:46Z
updated_at: 2026-08-12T13:29:37Z
parent: browserid-ng-81s6
blocked_by:
    - browserid-ng-in36
---

The demo that finally shows pain relief on a real server. Tunnel recipe (tailscale funnel / cloudflared, documented not built) + a 'share your notes vault' quickstart. Add the gated server to claude.ai via URL; a friend with a Gmail address connects via the OIDC-bridge hop; their agent acts, attributed; revoke just them at browserid.me/account -> next call fails closed. Blocked by M2. Parent epic browserid-ng-81s6.

DECIDED 2026-08-12: demo = 'share my notes vault'. Gateway runs on the LAPTOP behind a tunnel (tailscale funnel / cloudflared), URL added to claude.ai; friend on Gmail connects via the OIDC hop; per-friend scope cap (read-only vs read+write) shown; revoke just the friend → next call fails closed.
