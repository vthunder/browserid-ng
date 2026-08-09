---
# browserid-ng-k3rg
title: 'On-chain / SBO verifier: make it DNSSEC-conformant (key from _browserid, not .well-known)'
status: todo
type: feature
created_at: 2026-08-09T15:33:33Z
updated_at: 2026-08-09T15:33:33Z
parent: browserid-ng-g5qt
---

Deferred sibling of browserid-ng-0p5f. The SBO/on-chain attribution verifier resolves an issuer's signing key to check attributed actions ("action X by agent Y under authority Z, verifiable offline/on-chain"). It must root trust the same way as the other verifiers: resolve the key from the authenticated _browserid DNSSEC record (+ support host=), NEVER from .well-known — otherwise it breaks for hosted-primary tenants and violates the spec (§3: DNSSEC is the sole root of trust).

## To do
- [ ] Locate the SBO/on-chain verifier (likely in ~/src/mingo sbo-core / poster path, or an on-chain module) and how it currently resolves issuer keys.
- [ ] If it reads keys from .well-known or a pinned config, switch it to the shared browserid-dnssec resolver (resolve_idp_key), or — where an on-chain context can't do live DNS — pin a DNSSEC-obtained key with a documented refresh, never a .well-known-fetched one.
- [ ] For truly offline/on-chain verification, define how a DNSSEC proof (detached) accompanies the attribution so a verifier without live DNS can still root trust (relates to core §6.2 detached-DNSSEC proofs).
- [ ] Tests + conformance note.

## Context
Shared resolver landed in browserid-ng-0p5f (crate browserid-dnssec). mingo's login verifier + browserid-rp were fixed there. This bean is the third verifier the user flagged. On-chain adds the wrinkle that live DNS may be unavailable at verify time, so detached DNSSEC proofs may be needed.
