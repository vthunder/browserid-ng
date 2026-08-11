---
# browserid-ng-790g
title: Tenant policy + mint stamping (issuance side)
status: completed
type: task
priority: normal
created_at: 2026-08-11T12:29:56Z
updated_at: 2026-08-11T13:29:05Z
parent: browserid-ng-4vu7
blocked_by:
    - browserid-ng-x0wx
---

Access request: optional `audience` claim (core struct + mint route), honored ONLY when the requesting device cert carries managed:true; reject otherwise. Tenant policy store: per-tenant management config (enabled, posture broad|per-audience, audience allowlist + per-tenant salt, scopes, max-ttl) + migration. Hosted /idp/device_cert stamps managed:true when tenant management enabled (marker MUST precede any stamping — enable flow must reissue or wait for natural reissue; decide). Mint stamps constraints per policy; distinct refusal error ('identity not permitted at this site'). Admin console: policy page on tenant admin surface (roster + constraints + revoke = the console).

## Summary of Changes
ManagementPolicy + tenants.management (v25), set_tenant_management/tenant_status_revoke_all, managed:true at tenant issuance, policy-aware mint (broad + per-audience postures, early refusals), GET/POST /wsapi/tenant/management with revoke-on-enable, domains console policy panel. 2 integration tests. Live at browserid.me a04ddf7.
