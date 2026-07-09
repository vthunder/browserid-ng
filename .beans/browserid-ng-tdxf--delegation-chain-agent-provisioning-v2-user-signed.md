---
# browserid-ng-tdxf
title: 'Delegation-chain agent provisioning (v2): user-signed provisioning certs + broker endorsement + key-management UI'
status: in-progress
type: feature
priority: high
created_at: 2026-07-09T12:12:18Z
updated_at: 2026-07-09T12:40:18Z
---

Supersedes the bearer bidk_ API-key scheme from l8lw with a cryptographic delegation chain (2026-07-09 design discussion): user identity key signs a provisioning cert for the agent's provisioning keypair; broker co-signs each provisioning request per policy (sybil/quota, revocation); the parent identity's root IdP verifies the dual-signed request and mints the agent cert. Key management centralizes at browserid.me (UI to create/list/revoke), trust flows to the IdP, the API-key secret never transits the wire, and the broker never holds it.

- [x] Design doc — docs/plans/2026-07-09-agent-delegation-chain-design.md
- [x] Spec v0.2 — §4 rewritten around the provisioning-request protocol (delegation chain, endorsement, signing-time semantics); §5 unchanged
- [x] browserid-core::provisioning — cert/request/bundle/endorsement types, chain verification w/ signing-time semantics + typ domain separation (8 tests)
- [x] broker: provisioning_certs registry (migration v5), /wsapi/{register,list,revoke}_provisioning_cert (session+CSRF), /provision/endorse, /provision/{mint,list,revoke} as target IdP; bidk_ dropped (9 tests)
- [x] broker UI /agents: WebCrypto Ed25519 keygen + P_cert signing in-page, cert_key for U_cert, register bundle, credential shown/downloaded once, list+revoke. Handles FALLBACK identities; primary-rooted credential creation deferred (see open question)
- [x] browserid-agent SDK: AgentCredential file (P_priv+delegation+broker+idp); provision/remint/revoke sign→endorse→mint; agent keypair stays local (tests reworked green)
- [ ] Downstream rework tracked in mingo-ua8w (mingo-idp auth swap, sbo provision-agent)

## browserid-ng side COMPLETE (2026-07-09)

Core, broker, SDK, and UI all reworked to the delegation chain and tested (43 test binaries green, clippy clean). Commits: 409bed8 (design+spec) → provisioning core → broker rework → SDK rework → UI.

## Open question for downstream (mingo-ua8w)

Creating a credential delegated from a PRIMARY identity (dan@mingo.place) needs the primary IdP to certify the in-browser ephemeral identity key, since browserid.me cert_key only issues for its own verified emails. Flow becomes cross-origin: U_cert from mingo.place, sign P_cert, register at browserid.me (needs dan@mingo.place added to the browserid.me account via primary-IdP add-email — exists). Options: (a) agent-key UI on mingo.place handing back the U_cert; (b) a CLI credential-creation command. mingo-idp mint + endorsement verification is unaffected and buildable/testable now against Rust-constructed bundles.
