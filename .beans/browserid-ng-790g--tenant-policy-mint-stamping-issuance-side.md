---
# browserid-ng-790g
title: Tenant policy + mint stamping (issuance side)
status: todo
type: task
created_at: 2026-08-11T12:29:56Z
updated_at: 2026-08-11T12:29:56Z
parent: browserid-ng-4vu7
blocked_by:
    - browserid-ng-x0wx
---

Access request: optional `audience` claim (core struct + mint route), honored ONLY when the requesting device cert carries managed:true; reject otherwise. Tenant policy store: per-tenant management config (enabled, posture broad|per-audience, audience allowlist + per-tenant salt, scopes, max-ttl) + migration. Hosted /idp/device_cert stamps managed:true when tenant management enabled (marker MUST precede any stamping — enable flow must reissue or wait for natural reissue; decide). Mint stamps constraints per policy; distinct refusal error ('identity not permitted at this site'). Admin console: policy page on tenant admin surface (roster + constraints + revoke = the console).
