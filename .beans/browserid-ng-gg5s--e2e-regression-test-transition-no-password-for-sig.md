---
# browserid-ng-gg5s
title: 'e2e regression test: transition_no_password for signed-out users routes through reset flow'
status: completed
type: task
priority: normal
created_at: 2026-07-10T17:04:47Z
updated_at: 2026-07-11T00:40:27Z
---

Fixed 2026-07-10: a signed-out user hitting a password-less account (created via primary IdP) with a secondary email got a dead-end setPassword screen (server 401s without a session) with misleading ex-primary copy. Dialog now routes signed-out transition_no_password through stage_reset (emailed code proves ownership, then sets password); signed-in users keep the direct setPassword screen. Needs a Playwright regression test using the mock-primary machinery in primary-idp.spec.ts: sign in via mock primary (creates password-less account), add secondary email, sign out, sign in with the secondary, expect #reset-password-screen (not #set-password-screen).

## Summary of Changes (2026-07-11)

Added e2e-tests/tests/transition-no-password-reset.spec.ts (2 tests, green in the full suite: 84 passed).

- **signed-out** user in transition_no_password lands on #reset-password-screen (active), NOT #set-password-screen, and stage_reset is called — the regression guard.
- **signed-in** contrast: same state keeps the direct #set-password-screen, stage_reset NOT called (pins why the fix discriminates on session).

Constraint found & documented in the test header: the mock primary IdP can't create a genuine password-less account (its fake cert never passes verify_assertion_with_dns, so /wsapi/auth_with_assertion never creates the account), and there's no seed endpoint. So the test drives the REAL dialog (handleNoPasswordTransition + showScreen run for real) and stubs only the two routing INPUTS — address_info (the state) and stage_reset (the reset branch's email) — leaving session_context real for the signed-out case. Screen ids verified against dialog.html; branch logic against dialog.js handleNoPasswordTransition.
