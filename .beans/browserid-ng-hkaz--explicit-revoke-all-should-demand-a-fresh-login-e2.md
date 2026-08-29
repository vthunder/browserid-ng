---
# browserid-ng-hkaz
title: Explicit revoke-all should demand a fresh login — E2 identities silently re-issue on a live bridge session
status: todo
type: bug
priority: normal
created_at: 2026-08-29T10:43:40Z
updated_at: 2026-08-29T10:43:46Z
parent: browserid-ng-9yyk
---

Dan's ruling from smoke-testing 2026-08-29 (laptop, no wallet): after removing ALL devices on /account, signing in at an RP as danmills@sandmill.org (E1) correctly demands the primary password again, but vthunder@gmail.com (E2/oidc) did a passwordless bounce (brief flash) and silently minted a fresh pair — the bridge (Google) session was live, and the bridge lane may silently reuse its own session by design (mint.rs E2 comment). Dan: this matches the earlier design but is wrong — an explicit device wipe (which reads as 'log everything out') should require a real login, not a silent bridge bounce. Look into: distinguish explicit revoke-all/sign-out intent from ordinary cold re-issue, e.g. an account-level 'require fresh proof' flag set by the account page's revoke/forget actions that forces prompt=login (OIDC) / interactive re-auth on the next claim, or an issuer-side cooldown after mass revocation. Applies to the bridge claim lanes in the dialog + oidc routes.
