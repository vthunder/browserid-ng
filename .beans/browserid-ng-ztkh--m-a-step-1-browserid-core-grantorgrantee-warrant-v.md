---
# browserid-ng-ztkh
title: 'M-A step 1: browserid-core grantor/grantee warrant + verify rework'
status: completed
type: task
priority: high
created_at: 2026-07-23T14:02:51Z
updated_at: 2026-07-23T14:17:49Z
parent: browserid-ng-atge
---

Rename WarrantClaims.identifier -> grantor+grantee (both required). Warrant::create takes grantor+grantee. verify: effective author=grantor; config authorizes grantor under cc.iss; access under ac.iss; drop iss-equality; grantee==access.identity; keep holder match vs access.holder. VerifiedAccess.email=grantor, issuer=cc.iss, add grantee(+issuer). Regenerate golden vectors; update core conformance tests. Compile-driven fallout in broker/registrar/agent to follow.

## Summary
Done + committed (workspace 44 suites green). WarrantClaims.identifier -> grantor+grantee; verify single-path (effective author=grantor, config authorizes grantor under config.iss, access under access.iss, iss-equality dropped, grantee==access.identity, holder match kept); VerifiedAccess exposes email=grantor, grantee, issuer=grantor issuer, grantee_issuer. Fallout: agent/registrar/fedcm/rp + all test callers + client JS builders (all as-you) + golden vectors + CSP hashes. Next: s7gp (sbo).
