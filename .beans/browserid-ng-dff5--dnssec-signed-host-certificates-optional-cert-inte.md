---
# browserid-ng-dff5
title: DNSSEC-signed host certificates (optional cert intermediate)
status: todo
type: feature
priority: normal
created_at: 2026-07-10T11:17:13Z
updated_at: 2026-07-10T11:17:13Z
---

Optional intermediate in the browserid-ng cert chain (split out of 28uc, whose Phase 1 — DNSSEC-required sole-root + unified verifier — shipped and deployed). Design is settled (28uc FINAL decision); this is the remaining implementation + spec §4.2.

## Model
DNSSEC key K_dns -> (optional) host cert (K_host, principal={host:<domain>}, signed by K_dns) -> user cert -> assertion. A user cert is valid if signed directly by K_dns OR by a K_host whose host cert is signed by K_dns. No endpoints in the cert (they stay in .well-known).

## Why
- Separate the DNS admin (holds K_dns, cold) from the IdP operator (holds K_host, signs user certs).
- Rotate the operational key by issuing a new host cert, WITHOUT a DNS change — mitigates the key<->DNS drift footgun hit this session.

## Implementation
- Reinstate the host principal on certificates (browserid-core/src/certificate.rs — Phase 1 kept email-only).
- Verifier hook (identified by the Phase 1 agent): the final cert check in browserid-broker/src/verifier.rs verify_signatures_with_doc — after resolving K_dns, if the user cert isn't signed by K_dns directly, verify a K_dns-signed host cert (delivered via .well-known or the bundle) authorizing the signer, then verify the user cert against K_host.
- Host cert delivery via .well-known (support document) — optional field.
- Attribution generalization: SBO Attribution Spec §4 step 5 must verify the chain up to K_dns (sbo repo) once host certs exist.

## Tests
- User cert signed directly by K_dns still verifies (no host cert).
- User cert via a valid K_dns-signed host cert verifies.
- Host cert NOT signed by K_dns is rejected.
- Rotation: new host cert with a new K_host verifies without a DNS change.

## Spec
Finalize browserid-ng-protocol.md §4.2 (currently marked as planned/not-yet-implemented) and update the SBO Attribution Spec step 5.

## Related
Parent decision: browserid-ng-28uc (completed). Spec: docs/specs/browserid-ng-protocol.md §4.2.
