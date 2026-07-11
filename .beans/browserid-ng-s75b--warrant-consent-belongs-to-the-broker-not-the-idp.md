---
# browserid-ng-s75b
title: Warrant consent belongs to the broker, not the IdP — corrected registrar role decomposition
status: completed
type: feature
priority: normal
created_at: 2026-07-11T08:51:02Z
updated_at: 2026-07-11T10:18:23Z
blocking:
    - browserid-ng-0efn
---

Design correction that supersedes the role model in the (completed) 1pnf extraction. Surfaced in discussion with vthunder (2026-07-11).

## Principles (ratified)

1. Issuing identities (user + agent certs) is the IdP's job.
2. Issuing a warrant is rooted in **user consent**, signed by the user's own key — NOT the IdP.
3. The IdP must not decide what the user can consent to, and must not even be *able* to see what the user is consenting to.

Together these mean the IdP is not the issuer, governor, or verifier of warrants and **must never see one**. The IdP mints certs, publishes a verification key, and can do coarse identity-revocation (kill the whole agent cert) — nothing warrant-specific.

## What 1pnf got wrong

- **Default registrar = the IdP.** Under principle 3 that's backwards: by default your IdP would witness every warrant's audience + scopes and gate the request. The default registrar must be a party the user chose, and by default NOT the IdP. (mingo avoided this only by explicitly using external-registrar mode = browserid.me; the *default* was the bug.)
- **Fused two roles with different trust needs:** the **minting gate** (provisioning-cert registry + endorsement — sybil/quota control over agent-identity minting; legitimately IdP/broker-adjacent, never needs warrant contents) and **warrant consent/registry/revocation** (must be the user's chosen broker, IdP-blind). These should be split.

## Corrected decomposition

- **IdP** — mint identity + agent certs; publish verification key; coarse identity revocation. Never sees warrants. Sees only the registrar *endpoint URL* baked into the cert (may refuse to sign if it dislikes it — visible, low-risk, possibly a feature).
- **Broker / registrar** — the user-agent stand-in the user chose. Hosts the consent UI; is the **origin the user's (ideally non-extractable) signing key is bound to** (signing is client-side there — the service never holds raw keys; see [[implement-non-extractable-key-custody-agent-privat]] e2fi); holds the warrant registry (jipx); publishes the revocation status list (egr7). It DOES see warrant contents — that's fine and enables good UX (cross-browser sign-in-and-revoke needs server-side storage), because it's a party the user picked, not the IdP. "delegation registrar" is just *the broker, persisted into the agent cert* so a headless agent can find it.
- **Verifier** (RP-side / hosted /verify) — trusts IdP-key -> user-cert -> user-signed-warrant. The registrar is NOT in this identity-trust chain, which is exactly what frees it to be user-chosen without RP negotiation. It reads the warrant's status-list URI for revocation *freshness* only.

## Concrete changes to pursue

- [x] Default registrar != IdP; make the registrar an explicit, user-chosen endpoint.
- [x] **Bake the registrar endpoint into the agent cert** (a claim/link). Solves "which broker?" for a headless agent with no live browser to negotiate. Bonus: the RP can cross-check that a warrant's status-list URI matches the registrar the identity committed to — detects a phished "registrar that never revokes." (Currently the endpoint lives client-side in the agent credential file; moving it into the cert makes it authoritative + RP-visible.)
- [x] (deferred) Split the **minting gate** (endorsement / P_cert registry / quota) from **warrant consent + registry + revocation** in the browserid-registrar crate — different trust requirements, possibly different hosts.
- [x] Decentralization path (agents): different broker -> bakes a different registrar endpoint into certs. (Login-path decentralization is the sibling polyfill bean.)

## Accepted costs

- Revocation availability coupling moves to the (possibly self-run) registrar: RP checks revocation via the warrant's status URI. Must be a conscious **fail-open vs fail-closed** policy on status-list-unavailable; a reason users pick a broker with good SLAs.
- Rotating your registrar means re-minting agent certs (short-lived, so it propagates fast).

## Optional harder variant

Registrar-as-relay: because signing is client-side, the consent UI can render audience/scopes from the RP challenge in the browser and the server can store only the opaque signed blob, never parsing it — a blinder registrar. A dial, not required by the principles (which only bind the IdP).

## Related

Supersedes the role model in browserid-ng-1pnf (kept closed; extraction was still useful groundwork). Related: egr7 (revocation/status list), e85i (grant identity), e2fi (non-extractable custody), and the sibling login-path decentralization bean (polyfill-selectable broker).

## Build progress (2026-07-11)

Decisions locked: broker-declared registrar (endorser = registrar); strict verification (no carve-out — dev mode, existing warrants killed); crate split deferred.

- [x] Phase 0 spec — v0.5: registrar is the user's broker, `registrar` cert claim, warrant status pinned to it
- [x] Phase 1 core — `registrar` cert claim + strict warrant verify (status required + origin == cert registrar)
- [x] Phase 2 broker/registrar — endorsement carries the registrar; broker mints with its own origin; 366 workspace tests green
- [x] Phase 3 mingo-idp — bump core rev a39b5ea; copy endorsement registrar into the minted cert; 12 tests green
- [x] Phase 4 deploy — broker (a39b5ea) + mingo-idp (6fcd5cc) live
- [x] Phase 4 smoke test — see below


## Summary of Changes (2026-07-11) — SHIPPED

Corrected the registrar trust model per the three ratified principles: the registrar is the user's broker, never the IdP; the IdP mints + publishes a key and never sees a warrant.

- **Spec v0.5** (agent-provisioning-and-grant-api.md): registrar = user's broker; new `registrar` cert claim carried from endorsement → cert; agent warrants MUST carry a status ref pinned to the cert's registrar origin.
- **browserid-core**: `registrar` cert claim; endorsement carries the registrar origin; `Warrant::verify_for` strict — rejects a warrant with no status, a cert with no registrar, or a status URI whose origin ≠ the cert's registrar. No transitional leniency (dev-mode decision: existing warrants killed).
- **broker/registrar crate**: `/provision/endorse` names its own origin as the registrar; broker-minted agents get the broker's own origin.
- **mingo-idp** (separate repo, pinned to core a39b5ea): copies the endorsement's registrar into every minted agent cert.

Decisions (via AskUserQuestion): broker-declared registrar (endorser=registrar); strict verification (no carve-out); crate split deferred (both roles stay broker-side, no adoption scenario needs them separated).

**Live smoke test on browserid.me + mingo.place:**
1. Fresh `tester@mingo.place` cert carries `registrar: https://browserid.me` (mingo copied it from the endorsement). ✓
2. Consent-approved warrant's status ref = `https://browserid.me/.well-known/browserid-status`, pinned to the cert registrar. ✓
3. Positive `/verify`: `okay`, `agent.parent=dan@mingo.place`, `scopes=[post,read]`. ✓
4. Negative: pre-v0.5 cert (no registrar) rejected — "agent cert names no registrar". ✓
5. Negative: wrong-audience replay rejected. ✓
6. Status-origin-mismatch: covered by core unit test `warrant_status_not_at_cert_registrar_rejected` (can't forge live without the delegator's browser key).

Tests: core 51, workspace 366, mingo-idp 12 — all green.

Follow-ups: cert-baked endpoint currently equals the endorser (endorser=registrar); decoupling registrar from endorser is future work. Sibling login-path decentralization is [[polyfill-selectable-broker-endpoint-user-chosen-broker-for-the-login-path]] (0efn).
