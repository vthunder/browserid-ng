---
# browserid-ng-tdxf
title: 'Delegation-chain agent provisioning (v2): user-signed provisioning certs + broker endorsement + key-management UI'
status: in-progress
type: feature
priority: high
created_at: 2026-07-09T12:12:18Z
updated_at: 2026-07-09T12:15:06Z
---

Supersedes the bearer bidk_ API-key scheme from l8lw with a cryptographic delegation chain (2026-07-09 design discussion): user identity key signs a provisioning cert for the agent's provisioning keypair; broker co-signs each provisioning request per policy (sybil/quota, revocation); the parent identity's root IdP verifies the dual-signed request and mints the agent cert. Key management centralizes at browserid.me (UI to create/list/revoke), trust flows to the IdP, the API-key secret never transits the wire, and the broker never holds it.

- [x] Design doc — docs/plans/2026-07-09-agent-delegation-chain-design.md
- [x] Spec v0.2 — §4 rewritten around the provisioning-request protocol (delegation chain, endorsement, signing-time semantics); §5 unchanged
- [ ] browserid-core: provisioning module (pcert/request/endorsement types, chain verification) + tests
- [ ] broker: provisioning-cert registry, /provision/endorse, /provision/* mint path (replaces bearer /agent/*), drop bidk_ scheme
- [ ] broker UI: create/list/revoke agent keys on browserid.me (in-page P-keypair gen + typed signing with the identity key; secret shown once, never sent to server)
- [ ] browserid-agent SDK: rework around credential file (P_priv + delegation chain) + endorse→mint flow
- [ ] Downstream rework tracked in mingo-ua8w (mingo-idp auth swap, sbo provision-agent)
