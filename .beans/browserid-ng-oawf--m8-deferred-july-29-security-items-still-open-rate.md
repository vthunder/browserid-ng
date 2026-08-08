---
# browserid-ng-oawf
title: '[M8] Deferred July-29 security items still open (rate-limit, enumeration, fallback pw-bypass)'
status: todo
type: bug
priority: normal
created_at: 2026-08-07T16:03:44Z
updated_at: 2026-08-07T16:03:44Z
parent: browserid-ng-8g49
---

Re-confirmed open in code: authenticate_user has no rate-limit/lockout (routes/auth.rs, bean ytjn); unauthenticated account enumeration (bean dw35); fallback /auth/device_cert password-bypass (bean 7ww7). Consciously deferred for product/infra decisions; this just verifies no regression. See audit M8. Cross-ref epic browserid-ng-wre6.
