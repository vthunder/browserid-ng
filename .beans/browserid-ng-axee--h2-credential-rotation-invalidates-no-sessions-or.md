---
# browserid-ng-axee
title: '[H2] Credential rotation invalidates no sessions or device certs'
status: completed
type: bug
priority: high
created_at: 2026-07-28T23:53:20Z
updated_at: 2026-07-29T01:18:04Z
parent: browserid-ng-wre6
---

Full detail in docs/security-audit-2026-07-29.md (H2). complete_reset (reset.rs:139) and update_password (auth.rs:168) call only update_password (bare UPDATE users SET password_hash, sqlite.rs:1043). SessionStore trait exposes only create/get/delete-by-id — no delete-by-user, no DELETE FROM sessions WHERE user_id. Sessions live 30 days. A takeover-recovery reset cannot evict an established attacker session; attacker-minted device certs survive to 90-day expiry.

- [ ] Add SessionStore::delete_sessions_by_user (sqlite + memory)
- [ ] Call it on password change and reset
- [ ] Optionally flip status bit on device certs issued before the reset

## Summary of Changes
H2 fixed: SessionStore::delete_by_user; reset evicts all sessions, password-change evicts all then re-mints caller session. Test updated to follow rotated cookie.
