---
# browserid-ng-bhfi
title: '44jm follow-up: point external repos at /verify (bsky, mingo, sbo)'
status: completed
type: task
priority: normal
created_at: 2026-08-25T20:56:41Z
updated_at: 2026-08-26T08:05:06Z
---

The /verify cutover (bean 44jm) is done in browserid-ng; /verify-access remains a permanent alias so nothing is broken, but external consumers should move to the canonical route:

- [x] browserid-bsky: pds-bridge verify_presentation POSTs {broker}/verify-access (routes.rs) + test mock route
- [x] mingo: checked 2026-08-26 — clean, no /verify-access uses
- [x] sbo: checked 2026-08-26 — clean, no /verify-access uses

Read ~/src/browserid-bsky HANDOFF before touching that repo.

## Sweep results (2026-08-26)

Remaining live call sites, confirmed by grep:

- [x] browserid-bsky: pds-bridge/src/routes.rs:63 `.post(format!("{}/verify-access", state.broker_url))` + the mock in pds-bridge/tests/bridge_test.rs + comments in lib.rs/routes.rs. (The bridge's own `GET /verify` provenance-receipt route is unrelated — different origin, GET, no conflict.)
- [x] **sandmill** (~/src/sandmill — NOT on the original list): app/Http/Controllers/BrowserIdController.php:345 POSTs https://browserid.me/verify-access, plus demo copy in resources/views/browserid/demo.blade.php (lines ~262, ~340). Remember: sandmill is DB-less config-based — small targeted edit.

Dated docs/plans and .beans in those repos left as historical record.

## Summary of Changes

Done 2026-08-26. browserid-bsky: flipped routes.rs POST, both test mocks (bridge_test.rs, relay/dashboard.rs), and comments; 178 workspace tests green; deployed via CI (50450ab, deploy-bridge success, bridge live). sandmill: BrowserIdController.php demoVerify now POSTs browserid.me/verify; demo.blade.php copy updated; the 7 pre-existing phpunit failures are unchanged by this commit (verified by stash/compare); deployed to dokku (5959287) and confirmed live on the demo page. mingo and sbo verified clean. Every known /verify-access consumer in every repo is now on /verify; the alias remains permanently for anything unknown.

Note: sandmill's origin remote (sandmill.org:git/sandmill.git) rejects pushes (auth) and was already one commit stale before this work — the dokku remote is the deploy path and is current.
