---
# browserid-ng-8iy8
title: 'gate 0.5.0: console-only CLI + localhost fallback when tailscale is missing'
status: completed
type: feature
created_at: 2026-08-13T08:38:18Z
updated_at: 2026-08-13T08:38:18Z
---

Per Dan: gate should have ONE mode (the console). One-shot mode removed from the CLI (createGateService stays as the library API). And without tailscale the console must still run: gateway.start() now falls back to http://127.0.0.1:<port> when the funnel can't be claimed, returns {public, funnelError}, and the CLI prints a warning that the URL must be tunneled to be publicly usable, recommending tailscale (cloudflared + --resource as the alternative).

## Summary of Changes
- gateway.mjs: funnel failure no longer aborts start — localhost origin fallback, funnelError surfaced
- bin/gate.mjs: console-only; removed --allow/--name/--tunnel/-- (friendly migration error), --admin required, banner warns on local-only startup
- README: console-only docs, Reachability rewritten (funnel recommended / cloudflared / no-tunnel), flags table
- index.d.ts: start() returns {public, funnelError}
- admin.test.mjs: new test — no tunnel → starts on localhost, serves the console, reports why
- 53/53 tests pass; version 0.5.0 (breaking CLI change)
