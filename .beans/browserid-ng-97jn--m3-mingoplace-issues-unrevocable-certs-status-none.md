---
# browserid-ng-97jn
title: '[M3] mingo.place issues unrevocable certs (status: None)'
status: todo
type: bug
priority: normal
created_at: 2026-08-07T16:03:17Z
updated_at: 2026-08-07T16:03:17Z
parent: browserid-ng-8g49
---

mingo-idp passes None for status on device/config/access certs (mingo-idp/src/device.rs:135,152,333). RP fail-closed status check only fires when a ref is present (browserid-rp/src/lib.rs:321-328), so mingo.place certs can never be revoked short of IdP key rotation. Allocate status indices at issuance like broker/sandmill. See audit M3.
