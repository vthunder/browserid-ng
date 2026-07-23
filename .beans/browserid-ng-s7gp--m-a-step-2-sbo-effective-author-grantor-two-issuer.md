---
# browserid-ng-s7gp
title: 'M-A step 2: sbo effective-author = grantor + two-issuer DNSSEC resolution'
status: completed
type: task
priority: high
created_at: 2026-07-23T14:02:51Z
updated_at: 2026-07-23T14:59:13Z
parent: browserid-ng-atge
blocked_by:
    - browserid-ng-ztkh
---

device_attribution/authorize: attributed email = warrant grantor (revive effective-author, config-signed). owner==grantor via existing email match. Daemon resolve_evidence: resolve BOTH issuers' on-chain /sys/dnssec (grantee ac.iss + grantor cc.iss). Two-issuer key resolver. Bump core rev.

## Summary
Done + committed (sbo main ae1a998, pushed; workspace green). DeviceAttribution.email=grantor (effective author) + grantee/grantee_issuer (actor/provenance). verify_device_attribution takes a per-issuer evidence resolver, proves both grantee (access.iss) + grantor (config.iss) issuers, domain-binds both. Daemon resolve_issuer_evidence resolves each on-chain /sys/dnssec (no new wire field). sbo-capture ported to holder model; unified on browserid-core 2582555. New delegated test (grantor!=grantee) proves attribution lands on grantor. Next: nrwd.
