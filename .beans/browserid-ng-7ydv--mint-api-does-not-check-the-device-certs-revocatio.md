---
# browserid-ng-7ydv
title: Mint API does not check the device cert's revocation status
status: todo
type: bug
priority: high
created_at: 2026-07-24T13:50:33Z
updated_at: 2026-07-24T13:50:33Z
---

routes/device.rs access_mint verifies the device cert signature (263) and the access request signature (274), and inherits the device's status ref onto the access cert (292-296) — but never checks is_status_revoked_idx for the device cert's own bit. A REVOKED device keeps minting fresh access certs until its cert expires (90d). Spec §4.2: the IdP verifies the device cert 'own signature, unrevoked, in validity, identity in its list'; the design's 'instant revocation at the mint' claim depends on this. Observed live (2026-07-24): after Dan removed a device at browserid.me/account, the device still minted successfully; only the warrant status bit (checked by the bsky bridge per-use) stopped the delegated post. Related: 68av (jti replay, same handler), 4lxl (deployed broker also predates status checks at /verify-access — redeploy pending mingo status-list check).
