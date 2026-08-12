---
# browserid-ng-lrub
title: 'M3: the five-minute share (wedge demo, non-abstract, real server)'
status: todo
type: feature
priority: high
created_at: 2026-08-12T12:21:46Z
updated_at: 2026-08-12T15:52:27Z
parent: browserid-ng-81s6
blocked_by:
    - browserid-ng-in36
---

The demo that finally shows pain relief on a real server. Tunnel recipe (tailscale funnel / cloudflared, documented not built) + a 'share your notes vault' quickstart. Add the gated server to claude.ai via URL; a friend with a Gmail address connects via the OIDC-bridge hop; their agent acts, attributed; revoke just them at browserid.me/account -> next call fails closed. Blocked by M2. Parent epic browserid-ng-81s6.

DECIDED 2026-08-12: demo = 'share my notes vault'. Gateway runs on the LAPTOP behind a tunnel (tailscale funnel / cloudflared), URL added to claude.ai; friend on Gmail connects via the OIDC hop; per-friend scope cap (read-only vs read+write) shown; revoke just the friend → next call fails closed.

## WORKING END TO END 2026-08-12
The five-minute-share demo works: gate wraps the filesystem server, tailscale funnel on 443, claude.ai connects via Lane B (browser approval as danmills@sandmill.org granting to dans-notes), agent reads notes attributed. Bugs found + fixed along the way (all shipped): gate must provision a DISTINCT named agent not the base identity (0.1.2); CORS for browser-based OAuth hosts (0.1.3); tailscale funnel auto-detection (0.2.0); per-request logging (0.2.1). KEY FINDING: claude.ai's connector REJECTS non-standard ports (:8443) client-side — it never sent a request. The gate handles any port fine server-side (proven: a /authorize on :8443 reached the broker and created a pending consent). Fix was moving the funnel to standard 443 (clean URL, no port). => managed hosts require 443; hobbyists running multiple gated servers on one machine/one 443 need path-based mounting (bean filed).
