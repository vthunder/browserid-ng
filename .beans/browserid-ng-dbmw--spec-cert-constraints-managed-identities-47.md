---
# browserid-ng-dbmw
title: 'Spec: cert constraints & managed identities (§4.7)'
status: completed
type: feature
priority: normal
created_at: 2026-08-11T12:03:09Z
updated_at: 2026-08-11T12:15:14Z
---

Integrate the constraints/managed-identity design into the core protocol spec: constraints claim on IdP-signed certs (aud hashed allowlist, scopes, max-ttl), fail-closed unknown keys, verification step, mint inheritance, UA disclosure SHOULDs, terms in support doc, privacy+deployment notes. Design settled in chat 2026-08-10/11; implementation (hosted tenant mint-time stamping + verifier checks) is follow-up.

## Summary of Changes

Integrated into docs/specs/browserid-ng-protocol.md (house "planned extension" marker, same as §4.4 host certs):

- New §4.7 "Constraints & managed identities": `constraints` claim on any
  IdP-signed cert; v1 vocabulary `aud` (salted-hash allowlist), `scopes`,
  `max-ttl`; presentation-binding semantics evaluated on certs AS PRESENTED
  (policy freshness = presented-cert TTL, TTL is the IdP's knob, access-cert
  mint is the natural ~24h policy point governing humans and agents uniformly);
  MUST-reject unknown keys; authored-by-IdPs / enforced-by-verifiers /
  disclosed-by-UAs role split; UA SHOULD duties (claims-derived disclosure,
  distinct treatment, re-disclose on any change, no-expectation-of-privacy
  teaching); privacy (mint stays RP-blind — allowed-set visibility, not
  used-set); deployment note (binds only at conforming verifiers).
- §6.1: new step 7 (enforce constraints), status checks renumbered to step 8,
  return to 9; conformance sentence updated; §6.3 cross-ref fixed.
- §7.2: mint inheritance — access cert MUST NOT be weaker than its device
  cert's constraints; mint MAY add its own; access request stays audience-free.
- §3.1: optional `terms` support-doc field. §4.1/§4.2 claims tables: 
  `constraints` rows. specs README summary line updated.

Design history (chat 2026-08-10/11): cosign considered and rejected — the
access cert already IS the per-24h online IdP-signed approval; retroactive
config-cert rebinding claim was WRONG (no key-continuity guarantee across
reissue) and is moot with cert-side constraints. `holders` constraint rejected
(namespaces are broker-randomized, deliberately opaque to IdP). Implementation
profile (follow-up, not started): hosted tenant stamps constraints at the
access-cert mint only; verifier checks needed across hosted /verify-access,
SDK verifiers, mingo, on-chain before any tenant enables constraints.

## Follow-up (2026-08-11, same commit thread)

Corrected after review: device-cert constraints are a DECLARATION (issuance-time
disclosure basis), not a mint-enforced mechanism — MUST-not-be-weaker downgraded
to SHOULD-not-stamp-looser (both certs come from the same authority; nothing to
enforce). Added optional `audience` to the access request: managing IdPs MAY
require it and mint audience-scoped access certs (several concurrent per
identity allowed) — recovers cosign's used-set visibility as an opt-in posture
with zero new endpoints; mint refusal surfaces org policy at login time.
Guardrail: IdP MUST NOT require `audience` for unmanaged identities (RP-blind
stays the consumer invariant). §4.7 Privacy rewritten to the two-posture model.
