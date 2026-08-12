---
# browserid-ng-7uzd
title: 'gate: tailscale funnel integration — auto-detect/print the public URL (and the claude.ai + share links)'
status: todo
type: feature
priority: high
created_at: 2026-08-12T15:21:08Z
updated_at: 2026-08-12T15:21:08Z
---

User feedback during M3 (2026-08-12): setting up the tunnel by hand is fiddly and error-prone — the port-443 conflict (funnel needs 443/8443/10000; 443 was taken by an existing serve), and the easy-to-miss requirement that --resource MUST equal the public funnel URL (else the OAuth audience is http://localhost and claude.ai can't reach it / the warrant audience mismatches). Make the gate tailscale-aware:
- On startup, query 'tailscale funnel status' / 'tailscale status --json' to find a funnel mapping to this gate's --port; if found and --resource was not explicitly set, AUTO-USE that public https URL as --resource.
- Print a prominent block: the public MCP endpoint URL to paste into claude.ai (<funnel>/mcp), and a one-line 'share this with a friend' string.
- Optional '--tunnel tailscale' that sets up the funnel itself (tailscale funnel --bg --https=<free port> <localport>, picking 8443/10000 if 443 is taken) and derives --resource from the result; print the 'tailscale funnel --https=<port> off' teardown hint.
- Fall back cleanly (print manual instructions) if tailscale isn't installed/running. Keep cloudflared documented as the alternative. Design note: docs/plans/2026-08-12-mcp-gateway-hobbyist-to-saas.md said 'don't build a tunnel' — this doesn't build one, it DETECTS/derives the URL from the user's existing tunnel, which is the ergonomic gap. Parent epic browserid-ng-81s6.
