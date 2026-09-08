---
# browserid-ng-r9jo
title: Registry accounts + login + login certificates (replaces the guard)
status: completed
type: feature
priority: high
created_at: 2026-09-08T14:09:50Z
updated_at: 2026-09-08T17:50:01Z
---

Dan's redesign 2026-09-08 after the guard screen confused him on mingo sign-in: accounts are first-class (create explicitly, discover by identity proof); login on an account by a registry-offered method (password first, stored_key = registry-signed login cert, device/identity later) yields a session; every operation runs under a session; guard tokens and fields go. Review draft: docs/plans/2026-09-08-registry-login-draft.md. Blocks nothing until ruled; then: spec edit (§4.2, §4.5, §5.2, §5.1), broker + registrar changes, dialog + wallet, delete /guard + /wsapi/guard.

## Summary of Changes (2026-09-08)

Spec: registry-api-v1 §4.2 login (login_page + stored_key), §4.5 sessions with login-key members, §5.2 accounts/lookup/login-keys/attach/detach/delete, login_required/login_rejected/identity_held reasons, discovery login_methods + browser.login (commit b17f8a7).

Code: registrar account.rs (accounts, lookup, login, login-keys, attach under a session — the header proof may be by a carried cert when the session holds no key yet — detach, delete); session members carry the login key; broker login_certs + login_tokens tables (v39, guard_tokens dropped), `/registry-login` page + `POST /wsapi/registry_login` (password); guard page/endpoint deleted. Web dialog: registry-session.js does lookup → login (password passed through on this origin, popup elsewhere) → attach → login cert in the keystore, headless stored_key logins after. Native wallet: same shape with the login page in its partition. Tests: workspace green; 121 e2e green (28 login certs and 6 stored-key sessions minted during the run).
