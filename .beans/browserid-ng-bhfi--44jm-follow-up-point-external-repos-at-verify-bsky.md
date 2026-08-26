---
# browserid-ng-bhfi
title: '44jm follow-up: point external repos at /verify (bsky, mingo, sbo)'
status: todo
type: task
priority: normal
created_at: 2026-08-25T20:56:41Z
updated_at: 2026-08-26T07:58:50Z
---

The /verify cutover (bean 44jm) is done in browserid-ng; /verify-access remains a permanent alias so nothing is broken, but external consumers should move to the canonical route:

- [ ] browserid-bsky: pds-bridge verify_presentation POSTs {broker}/verify-access (routes.rs) + test mock route
- [x] mingo: checked 2026-08-26 — clean, no /verify-access uses
- [x] sbo: checked 2026-08-26 — clean, no /verify-access uses

Read ~/src/browserid-bsky HANDOFF before touching that repo.

## Sweep results (2026-08-26)

Remaining live call sites, confirmed by grep:

- [ ] browserid-bsky: pds-bridge/src/routes.rs:63 `.post(format!("{}/verify-access", state.broker_url))` + the mock in pds-bridge/tests/bridge_test.rs + comments in lib.rs/routes.rs. (The bridge's own `GET /verify` provenance-receipt route is unrelated — different origin, GET, no conflict.)
- [ ] **sandmill** (~/src/sandmill — NOT on the original list): app/Http/Controllers/BrowserIdController.php:345 POSTs https://browserid.me/verify-access, plus demo copy in resources/views/browserid/demo.blade.php (lines ~262, ~340). Remember: sandmill is DB-less config-based — small targeted edit.

Dated docs/plans and .beans in those repos left as historical record.
