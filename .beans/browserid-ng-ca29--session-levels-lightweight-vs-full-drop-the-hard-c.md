---
# browserid-ng-ca29
title: 'Session levels: lightweight vs full (drop the hard-coded auth_level)'
status: todo
type: task
priority: high
created_at: 2026-08-19T13:33:45Z
updated_at: 2026-08-19T13:33:45Z
parent: browserid-ng-shyj
---

Give broker sessions a real level and stop pretending every session is password-authed.

## Changes
- Add a level/created_via field to the Session model + sqlite/memory stores (schema migration). Values: Full (password login) vs Lightweight (E1/E2 proof: primary presentation, OIDC/bsky bridge, email verification).
- Set it at every session creation site: auth.rs authenticate_user -> Full; auth.rs update_password re-mint -> Full; oidc.rs attach_verified, handle_claim.rs, primary.rs auth_with_presentation, account.rs complete_user_creation -> Lightweight.
- Replace the hard-coded auth_level = Some("password") in session.rs:69-80 with the real level; expose it in /wsapi/session_context so the dialog can branch.
- Rollout forces re-auth (owner decision): existing session rows have no level after migration -> treat as requiring re-auth (do NOT default to Full). Decide mechanism: null-level rows rejected by get_session_from_cookies, or a one-time table wipe.

## Blocks
Chokepoint (mint decisions need the level) and reset re-verification build on this.
