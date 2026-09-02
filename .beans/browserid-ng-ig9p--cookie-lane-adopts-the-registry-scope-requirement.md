---
# browserid-ng-ig9p
title: Cookie lane adopts the registry-scope requirement (auth_with_presentation parity with /api/v1/token)
status: in-progress
type: task
priority: normal
created_at: 2026-08-27T15:10:47Z
updated_at: 2026-09-02T16:33:46Z
---

Decided with Dan 2026-08-28 (registry-api-v1 §3.1/§10 item 5): the token exchange requires the exchanged warrant to carry the registry scope. Align the cookie sibling so the bar is identical, not merely 'token lane stricter': POST /wsapi/auth_with_presentation should demand the same scope on broker-audience warrants before minting a session.

Why: presentation-based sessions carry DELEGATED authority — a warrant granted to a third party whose audience happens to be the broker origin must not confer full account control. Password logins are untouched (authenticating at the issuer with the account's own credential is full control by definition).

Mechanics: the only first-party callers (dialog.js post-primary-login session join; wallet gxi9 join) self-sign their login warrants, so adding scopes: [{scope: "registry"}] when audience = broker origin is a small client change, no IdP involvement.

Migration:
- [x] dialog.js mints the registry scope on broker-audience warrants (2026-08-27); the wallet does the same when gxi9 builds it
- [x] broker accepts both, logs scopeless presentations (deprecation window) — auth_with_presentation logs since 2026-08-27
- [ ] enforce: reject scopeless with a clear machine reason
- [ ] update spec invariant 1 wording from 'at least as strict' symmetry note once both lanes match

## 2026-09-02 note (registry-api-v1 decision 10)

The token exchange this bean mirrored was DELETED: the registry API is now cert-authenticated on every call, with no warrant and no scope in the picture. The cookie lane's delegated-authority concern still stands on its own merits (a third-party warrant with audience = broker origin must not mint a full session), but there is no longer a token-lane bar to align with. Re-decide: keep as a standalone cookie-lane hardening, or scrap.
