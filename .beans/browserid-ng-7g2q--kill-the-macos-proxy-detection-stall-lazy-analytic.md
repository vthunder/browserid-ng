---
# browserid-ng-7g2q
title: 'Kill the macOS proxy-detection stall: lazy analytics client + no_proxy() everywhere'
status: in-progress
type: bug
priority: high
created_at: 2026-07-29T11:56:36Z
updated_at: 2026-07-29T11:59:52Z
---

From deploy-speed investigation (browserid-ng-0t19). Fix 1: Analytics::disabled() must not construct a reqwest::Client (make client Option/OnceLock; capture() already early-returns on token=None) — analytics.rs ~10 lines, takes broker suite from ~11 min idle to <1 min. Fix 2: add .no_proxy() to every reqwest::ClientBuilder in the workspace (analytics::from_env, verifier status_http, browserid-agent lib.rs:168/:419, browserid-rp lib.rs:535) — saves ~11s off local broker startup, Playwright webServer boots, and each mingo CLI op on macOS. Production Linux unaffected.
