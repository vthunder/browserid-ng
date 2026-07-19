---
# browserid-ng-g2yb
title: FedCM re-spike on device certs
status: in-progress
type: feature
priority: normal
created_at: 2026-07-19T14:09:58Z
updated_at: 2026-07-19T14:15:01Z
parent: browserid-ng-oup3
---

Restore the FedCM silent-login lane, minting a device-model presentation server-side at /fedcm/assertion (same server-custody trade-off the classic lane had; RPs verify via /verify-access — no dual wire).

- [x] Port fedcm.rs: assertion endpoint mints access_cert~assertion~warrant~config_cert server-side (ephemeral request-scoped keys)
- [x] Restore /fedcm/* + /.well-known/web-identity routes
- [x] Restore fedcm session cookie (session.rs)
- [x] Restore include.js silent lanes + dialog opt-in checkbox
- [x] Port fedcm_test.rs (token verifies via verify_access_with_dns; audience + fallback binding held)
- [ ] Deploy + verify
