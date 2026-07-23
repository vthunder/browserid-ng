---
# browserid-ng-i9rr
title: Hosted /verify-access rejects cross-issuer bundles that core accepts (B1)
status: todo
type: bug
priority: high
created_at: 2026-07-23T21:40:54Z
updated_at: 2026-07-23T21:40:54Z
---

Core (device.rs:607-622) deliberately allows config_cert.iss != access_cert.iss (cross-issuer delegated grants, bean yhcx), but the broker hosted verifier is still single-issuer: verifier.rs:164-183 runs conformance on the ACCESS cert identity domain (grantee), resolves one idp_key for ac.iss, and the closure at verifier.rs:189-194 errors for any other issuer — so cross-issuer bundles fail at /verify-access and the grantor's issuer is never discovered/validated.

Fix: bring the broker verifier to core parity — resolve both issuers (DNSSEC each), run conformance on the GRANTOR's domain (attribution target), surface grantee/grantee_issuer in the response (couples with audit item D2).

From docs/plans/2026-07-23-spec-code-divergence-audit.md (B1). Spec-side rewrite tracked in ga3w.
