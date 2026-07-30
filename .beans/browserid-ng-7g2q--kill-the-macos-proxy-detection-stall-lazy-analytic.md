---
# browserid-ng-7g2q
title: 'Kill the macOS proxy-detection stall: lazy analytics client + no_proxy() everywhere'
status: completed
type: bug
priority: high
created_at: 2026-07-29T11:56:36Z
updated_at: 2026-07-29T13:01:52Z
---

From deploy-speed investigation (browserid-ng-0t19). Fix 1: Analytics::disabled() must not construct a reqwest::Client (make client Option/OnceLock; capture() already early-returns on token=None) — analytics.rs ~10 lines, takes broker suite from ~11 min idle to <1 min. Fix 2: add .no_proxy() to every reqwest::ClientBuilder in the workspace (analytics::from_env, verifier status_http, browserid-agent lib.rs:168/:419, browserid-rp lib.rs:535) — saves ~11s off local broker startup, Playwright webServer boots, and each mingo CLI op on macOS. Production Linux unaffected.

## Measured result
Broker suite run phase: main >8min (timed out at 8m20s unfinished) → branch 85s clean (real 85s < user 90s = CPU-bound, parallel; the idle-wait signature is gone). Canary well_known_test: 13.02s → 0.01s. Shipped in c60ba33.
