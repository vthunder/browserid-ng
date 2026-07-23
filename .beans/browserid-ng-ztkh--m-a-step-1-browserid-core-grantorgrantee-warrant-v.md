---
# browserid-ng-ztkh
title: 'M-A step 1: browserid-core grantor/grantee warrant + verify rework'
status: in-progress
type: task
priority: high
created_at: 2026-07-23T14:02:51Z
updated_at: 2026-07-23T14:02:51Z
parent: browserid-ng-atge
---

Rename WarrantClaims.identifier -> grantor+grantee (both required). Warrant::create takes grantor+grantee. verify: effective author=grantor; config authorizes grantor under cc.iss; access under ac.iss; drop iss-equality; grantee==access.identity; keep holder match vs access.holder. VerifiedAccess.email=grantor, issuer=cc.iss, add grantee(+issuer). Regenerate golden vectors; update core conformance tests. Compile-driven fallout in broker/registrar/agent to follow.
