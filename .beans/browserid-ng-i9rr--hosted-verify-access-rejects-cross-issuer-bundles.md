---
# browserid-ng-i9rr
title: Hosted /verify-access rejects cross-issuer bundles that core accepts (B1)
status: completed
type: bug
priority: high
created_at: 2026-07-23T21:40:54Z
updated_at: 2026-08-25T20:57:10Z
---

Core (device.rs:607-622) deliberately allows config_cert.iss != access_cert.iss (cross-issuer delegated grants, bean yhcx), but the broker hosted verifier is still single-issuer: verifier.rs:164-183 runs conformance on the ACCESS cert identity domain (grantee), resolves one idp_key for ac.iss, and the closure at verifier.rs:189-194 errors for any other issuer — so cross-issuer bundles fail at /verify-access and the grantor's issuer is never discovered/validated.

Fix: bring the broker verifier to core parity — resolve both issuers (DNSSEC each), run conformance on the GRANTOR's domain (attribution target), surface grantee/grantee_issuer in the response (couples with audit item D2).

From docs/plans/2026-07-23-spec-code-divergence-audit.md (B1). Spec-side rewrite tracked in ga3w.

## Status re-check (2026-08-25)

Core fix ALREADY LANDED: commit aa56b93 (F10) + `resolve_conformant_key` — both issuers resolved via DNSSEC, conformance applied per identity's own domain; response surfaces grantee/holder/issuer/status_refs. Line refs in the description are stale.

Remaining to close:
- [x] Add `grantee_issuer` to the /verify(-access) response (audit D2 coupling)
- [x] Cross-issuer regression test (verifier_test.rs asserts issuer + grantee_issuer on the F10 accept test; route is a thin wrapper covered by agent_surface alias test)
- [x] Verify a cross-issuer bundle passes on prod (the fix commit aa56b93 has been deployed for a while — the browserid-bsky bridge exercises cross-issuer bundles against the hosted verifier in production; /verify + alias verified live 2026-08-25)

## Summary of Changes

The core fix (resolve both issuers via DNSSEC, conformance per identity own domain) had already landed in aa56b93 (F10). This pass added the missing response field `grantee_issuer` (audit D2), asserted issuer + grantee_issuer in the cross-issuer regression test, documented the field in openapi.json, and verified the endpoint on prod. Response fields now match core VerifiedAccess.
