---
# browserid-ng-mmnp
title: '[M1] Mint does not check device cert revocation status'
status: todo
type: bug
priority: normal
created_at: 2026-08-07T16:03:17Z
updated_at: 2026-08-07T16:03:17Z
parent: browserid-ng-8g49
---

spec §4.2/§6.4 promise 'a revoked device cert mints no new access cert'; access_mint (browserid-broker/src/routes/device.rs:274-329) never consults the device cert status index. Bounded: minted access cert inherits device status ref (routes/device.rs:320-323) so status-checking RPs reject, but spec mint-side kill unenforced. Check device status index at mint. See audit M1.
