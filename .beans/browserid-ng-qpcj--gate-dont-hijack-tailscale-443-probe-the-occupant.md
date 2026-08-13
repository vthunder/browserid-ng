---
# browserid-ng-qpcj
title: 'gate: don''t hijack tailscale :443 — probe the occupant, fall back to 8443 + claude.ai warning'
status: completed
type: bug
created_at: 2026-08-13T08:45:55Z
updated_at: 2026-08-13T08:45:55Z
---

claimFunnel() re-pointed :443 unconditionally, silently stealing it from any other funneled app (the re-point existed for gate's own stale mapping across auto-port restarts). Now it probes the current :443 target first:

- dead target (ECONNREFUSED) → our own stale mapping → re-point silently (old behavior, now justified)
- live target → NEVER steal: claim the next free funnel port (8443/10000) and return a warning — claude.ai requires 443, here's how to free it (stop the app or `tailscale funnel --https=443 off`); a live gate /healthz signature is called out as "another running gate instance"
- 443 live + all other funnel ports taken → actionable error

gateway.start() surfaces this as funnelWarning (logged + returned); the CLI banner prints it. Decided against a --takeover flag and a funnel-ownership state file for now.

## Summary of Changes
- tunnel.mjs: occupantOf() + defaultProbe() (healthz, 1.5s timeout, steal-nothing on uncertainty); claimFunnel returns {url, warning}
- gateway.mjs: accepts string or {url, warning} from funnelFn; start() returns funnelWarning
- bin/gate.mjs: banner prints the warning; index.d.ts updated
- tunnel.test.mjs: stale-reclaim, live-app fallback + warning text, another-gate detection, all-ports-taken error
- 56/56 tests pass
