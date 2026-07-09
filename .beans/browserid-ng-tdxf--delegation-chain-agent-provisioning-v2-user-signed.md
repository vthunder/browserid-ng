---
# browserid-ng-tdxf
title: 'Delegation-chain agent provisioning (v2): user-signed provisioning certs + broker endorsement + key-management UI'
status: completed
type: feature
priority: high
created_at: 2026-07-09T12:12:18Z
updated_at: 2026-07-09T13:21:03Z
---

Supersedes the bearer bidk_ API-key scheme from l8lw with a cryptographic delegation chain (2026-07-09 design discussion): user identity key signs a provisioning cert for the agent's provisioning keypair; broker co-signs each provisioning request per policy (sybil/quota, revocation); the parent identity's root IdP verifies the dual-signed request and mints the agent cert. Key management centralizes at browserid.me (UI to create/list/revoke), trust flows to the IdP, the API-key secret never transits the wire, and the broker never holds it.

- [x] Design doc — docs/plans/2026-07-09-agent-delegation-chain-design.md
- [x] Spec v0.2 — §4 rewritten around the provisioning-request protocol (delegation chain, endorsement, signing-time semantics); §5 unchanged
- [x] browserid-core::provisioning — cert/request/bundle/endorsement types, chain verification w/ signing-time semantics + typ domain separation (8 tests)
- [x] broker: provisioning_certs registry (migration v5), /wsapi/{register,list,revoke}_provisioning_cert (session+CSRF), /provision/endorse, /provision/{mint,list,revoke} as target IdP; bidk_ dropped (9 tests)
- [x] broker UI /agents: signs P_cert with the identity's OWN stored key (localStorage `emails` → {priv,cert}, via jwcrypto-compat — same machinery as sbo-signer), generates P keypair in-page, registers the U_cert~P_cert bundle, credential shown/downloaded once, list+revoke. Handles BOTH fallback and primary identities (idp derived from the cert issuer); no ephemeral key, no cert_key round-trip.
- [x] browserid-agent SDK: AgentCredential file (P_priv+delegation+broker+idp); provision/remint/revoke sign→endorse→mint; agent keypair stays local (tests reworked green)
- [ ] Downstream rework tracked in mingo-ua8w (mingo-idp auth swap, sbo provision-agent)

## browserid-ng side COMPLETE (2026-07-09)

Core, broker, SDK, and UI all reworked to the delegation chain and tested (43 test binaries green, clippy clean). Commits: 409bed8 (design+spec) → provisioning core → broker rework → SDK rework → UI.

## Open question for downstream (mingo-ua8w)

Creating a credential delegated from a PRIMARY identity (dan@mingo.place) needs the primary IdP to certify the in-browser ephemeral identity key, since browserid.me cert_key only issues for its own verified emails. Flow becomes cross-origin: U_cert from mingo.place, sign P_cert, register at browserid.me (needs dan@mingo.place added to the browserid.me account via primary-IdP add-email — exists). Options: (a) agent-key UI on mingo.place handing back the U_cert; (b) a CLI credential-creation command. mingo-idp mint + endorsement verification is unaffected and buildable/testable now against Rust-constructed bundles.


## Correction (2026-07-09): primary-credential "open question" was wrong

The earlier open question (primary identities needing the primary IdP to certify a fresh key) was a mistake from mirroring the test harness. The browser already holds the identity private key for EVERY logged-in identity (fallback or primary) in the browserid.me-origin `emails` localStorage store, alongside its IdP-issued cert — this is what sbo-signer.js signs SBO envelopes with. So /agents signs the P_cert with that existing key and delegates from the existing cert; the target IdP is read from the cert issuer. One UI, both rooting paths, no cross-origin dance. The design doc already specified this correctly; only the first implementation drifted. RESOLVED.

## Downstream complete + deployed (2026-07-09)

browserid.me DEPLOYED with v2 (commit 480a4be): migration v4→v5 clean, /provision/{endorse,mint,list,revoke} live, /agents UI serving, old bearer /agent/* gone (404). mingo-idp reworked to a v2 target IdP + sbo id provision-agent consumes a credential file (both tracked in mingo-ua8w, committed). All test suites green: browserid-core provisioning (8), broker (9), SDK e2e, mingo-idp conformance (4).
