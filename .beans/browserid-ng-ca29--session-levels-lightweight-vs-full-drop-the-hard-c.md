---
# browserid-ng-ca29
title: 'Session levels: lightweight vs full (drop the hard-coded auth_level)'
status: completed
type: task
priority: high
created_at: 2026-08-19T13:33:45Z
updated_at: 2026-08-19T14:47:38Z
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

## Summary of Changes (2026-08-19)

**Model & stores**
- `SessionLevel { Lightweight, Full }` in store/models.rs with `as_str()`/`parse()` (unknown tokens parse to Lightweight — least privilege). `Session` gains a `level` field.
- `SessionStore::create(user_id, level)` — the compiler now forces every creation site to state how the session was established.
- Sqlite migration v30: `DELETE FROM sessions` then `ALTER TABLE sessions ADD COLUMN level TEXT NOT NULL DEFAULT 'lightweight'`. Rollout mechanism chosen: the one-time wipe — pre-level rows can't be trusted at either level and the owner decided rollout forces re-auth. The DEFAULT is only ALTER scaffolding; inserts are always explicit.

**Creation sites**
- Full: auth.rs authenticate_user; auth.rs update_password re-mint.
- Lightweight: oidc.rs attach_verified cold claim; handle_claim.rs cold claim; primary.rs auth_with_presentation; account.rs complete_user_creation (completion proves the mailbox, not the staged password — per this bean).
- NEW site (from iudv, decided here): /wsapi/set_password upgrades the current session to Full — the caller just chose the account password, and without the upgrade set-on-add would demand the same password again at the next E3 mint. Only the current session is re-minted (rotated id); other live sessions keep their level (not a recovery event).

**Wire**
- session.rs: hard-coded auth_level gone. session_context now reports `session_level` ("full"/"lightweight") plus auth_level mapped "password"/"assertion". Verified nothing (JS or tests) consumed the old hard-coded value.

**Tests** — tests/session_level_test.rs (7 tests) + updated set_password_test; full broker suite + workspace build green:
- password login → full; user-creation completion → lightweight; store-minted lightweight reported in session_context.
- set_password upgrades to full and kills the old lightweight session id; update_password re-mint stays full.
- SqliteStore round-trips both levels.
- Migration test: hand-built v29 DB with a session row → open → row is gone (re-auth forced).

Unblocks u4xz (chokepoint) and kgb9 (reset re-verification).
