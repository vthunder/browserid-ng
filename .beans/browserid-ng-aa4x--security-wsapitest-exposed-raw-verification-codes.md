---
# browserid-ng-aa4x
title: 'SECURITY: /wsapi/test/* exposed raw verification codes in prod (fixed)'
status: completed
type: bug
priority: critical
created_at: 2026-07-12T21:45:38Z
updated_at: 2026-07-12T21:45:38Z
---

## Vulnerability
`/wsapi/test/pending_verification` was mounted unconditionally and returned HTTP
200 in production (browserid.me). It returns the raw verification/reset code for
ANY email — a full account-takeover primitive:

  stage_reset(victim) -> GET /wsapi/test/pending_verification?email=victim
  -> read code -> complete_reset -> own the account (no email access needed).

Also exposed the mock-primary-IdP controls (/wsapi/test/set_mock_primary_idp etc.),
which could spoof primary-IdP discovery.

## Fix (deployed sha b59ae10, 2026-07-12)
- Added `AppState.test_endpoints_enabled` (default false).
- The 4 `/wsapi/test/*` routes mount only when it's true (routes/mod.rs).
- main wires it to `DISABLE_SMTP` — prod always has real SMTP, so never mounts
  them. Verified live: prod -> 404, dev (DISABLE_SMTP=1) -> 200.
- Rust tests hitting the endpoints over HTTP (browserid-agent/tests/common) set
  the flag; broker tests read codes from the mock sender directly.

## Follow-up worth considering
- Rate-limit stage_reset / stage_user server-side (currently client-cooldown only).
- Audit for any other always-on `/test/`-style routes.
- Consider a compile-time `#[cfg(test)]`/feature gate in addition to the runtime
  flag, so the handlers can't ship in the release binary at all.
