---
# browserid-ng-fl6r
title: 'Native wallet UI: device management over the registry API'
status: todo
type: feature
priority: low
created_at: 2026-08-27T21:06:38Z
updated_at: 2026-08-28T21:18:17Z
parent: browserid-ng-9yyk
---

Consume the §5.3/§5.4 registry-API endpoints (shipped with bw9q) from the wallet UI: list the account's devices/holders, rename, revoke, forget, move between namespaces — so device hygiene doesn't require opening the /account web page. The wallet already holds a registry token (inbox watch); this is UI + a handful of client calls in wallet/src/registry.js.
