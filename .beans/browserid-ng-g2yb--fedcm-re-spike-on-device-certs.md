---
# browserid-ng-g2yb
title: FedCM re-spike on device certs
status: completed
type: feature
priority: normal
created_at: 2026-07-19T14:09:58Z
updated_at: 2026-07-19T14:25:10Z
parent: browserid-ng-oup3
---

Restore the FedCM silent-login lane, minting a device-model presentation server-side at /fedcm/assertion (same server-custody trade-off the classic lane had; RPs verify via /verify-access — no dual wire).

- [x] Port fedcm.rs: assertion endpoint mints access_cert~assertion~warrant~config_cert server-side (ephemeral request-scoped keys)
- [x] Restore /fedcm/* + /.well-known/web-identity routes
- [x] Restore fedcm session cookie (session.rs)
- [x] Restore include.js silent lanes + dialog opt-in checkbox
- [x] Port fedcm_test.rs (token verifies via verify_access_with_dns; audience + fallback binding held)
- [x] Deploy + verify (fedcm/config.json + web-identity live on browserid.me; include.js silent lanes served)

## Summary of Changes
Restored the FedCM silent-login lane on the device-cert model. /fedcm/assertion mints the 4-object presentation server-side with request-scoped ephemeral keys (same server-custody property as the classic lane); Sec-Fetch-Dest gating, the (session,RP) silent-consent store, /fedcm/reset, the /fedcm cookie, include.js trySilentFedCM/establishFedCMGrant, and the dialog opt-in checkbox are all back verbatim. Tokens verify through the unchanged /verify-access. 4 fedcm tests + 29 broker suites green; deployed to browserid.me.
