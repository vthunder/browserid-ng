---
# browserid-ng-l7oq
title: '[M8] Broker root signing key written world-readable (0644)'
status: completed
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-07-29T01:18:04Z
parent: browserid-ng-wre6
---

docs/security-audit-2026-07-29.md (M8). broker/config.rs:122 save_keypair uses fs::write with no mode → 0644. Readable file = full issuer-key recovery.
- [ ] Write broker key with 0600

## Summary of Changes
M8 fixed: broker key written 0600 on save.
