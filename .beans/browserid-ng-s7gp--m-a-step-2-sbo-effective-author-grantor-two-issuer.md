---
# browserid-ng-s7gp
title: 'M-A step 2: sbo effective-author = grantor + two-issuer DNSSEC resolution'
status: todo
type: task
priority: high
created_at: 2026-07-23T14:02:51Z
updated_at: 2026-07-23T14:02:51Z
parent: browserid-ng-atge
blocked_by:
    - browserid-ng-ztkh
---

device_attribution/authorize: attributed email = warrant grantor (revive effective-author, config-signed). owner==grantor via existing email match. Daemon resolve_evidence: resolve BOTH issuers' on-chain /sys/dnssec (grantee ac.iss + grantor cc.iss). Two-issuer key resolver. Bump core rev.
