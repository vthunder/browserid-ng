---
# browserid-ng-gg5s
title: 'e2e regression test: transition_no_password for signed-out users routes through reset flow'
status: todo
type: task
created_at: 2026-07-10T17:04:47Z
updated_at: 2026-07-10T17:04:47Z
---

Fixed 2026-07-10: a signed-out user hitting a password-less account (created via primary IdP) with a secondary email got a dead-end setPassword screen (server 401s without a session) with misleading ex-primary copy. Dialog now routes signed-out transition_no_password through stage_reset (emailed code proves ownership, then sets password); signed-in users keep the direct setPassword screen. Needs a Playwright regression test using the mock-primary machinery in primary-idp.spec.ts: sign in via mock primary (creates password-less account), add secondary email, sign out, sign in with the secondary, expect #reset-password-screen (not #set-password-screen).
