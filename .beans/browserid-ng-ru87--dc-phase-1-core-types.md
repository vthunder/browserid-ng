---
# browserid-ng-ru87
title: DC Phase 1 — Core types
status: completed
type: task
priority: normal
created_at: 2026-07-18T19:40:58Z
updated_at: 2026-07-18T22:11:06Z
parent: browserid-ng-oup3
blocked_by:
    - browserid-ng-ga3w
---

browserid-core: DeviceCert{purpose,subject,identities,validity,key,iss}; AccessRequestToken; AccessCert (fresh key, revocation ref); Warrant re-cut to (identifier,subject,audience,scopes)+revocation ref; purpose/subject enums fail-closed. Retire user-signed ProvisioningCert path. See docs/plans/2026-07-18-device-cert-model-migration-plan.md.

## Done: core device-cert types + golden vectors (frozen wire contract). 7 tests, no regression.
