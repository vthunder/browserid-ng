---
# browserid-ng-9rkv
title: 'wallet-service: account page — connected apps, audit log, revocation'
status: todo
type: feature
created_at: 2026-07-29T09:17:46Z
updated_at: 2026-07-29T09:17:46Z
---

Post-MVP (design doc §9, §12 'out of MVP'): a signed-in account page at wallet.browserid.me showing connected OAuth clients (with token revocation), the tenant audit log ('everything your hosted agent signed'), and a forget/revoke path that also offers server-side revocation at the broker. The audit write path already exists (audit_log table).
