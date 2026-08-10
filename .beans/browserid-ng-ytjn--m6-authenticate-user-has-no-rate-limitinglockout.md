---
# browserid-ng-ytjn
title: '[M6] authenticate_user has no rate limiting/lockout'
status: completed
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-08-10T07:01:41Z
parent: browserid-ng-wre6
---

docs/security-audit-2026-07-29.md (M6). broker/routes/auth.rs:37 — only bcrypt-12 bounds online guessing.
- [ ] Add per-IP/per-account throttling + backoff on login

## Fixed 2026-08-10 (commit pushed): per-IP fixed-window throttle on /wsapi/authenticate_user (10 fails/5min -> 429; auto-resets, IP-keyed so no victim lockout). Test added; full suite green.
