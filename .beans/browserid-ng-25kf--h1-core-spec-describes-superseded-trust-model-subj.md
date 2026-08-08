---
# browserid-ng-25kf
title: '[H1] Core spec describes superseded trust model (subject/identifier + config.iss==access.iss binding)'
status: todo
type: bug
priority: high
created_at: 2026-08-07T16:03:17Z
updated_at: 2026-08-08T10:42:22Z
parent: browserid-ng-8g49
---

docs/specs/browserid-ng-protocol.md §4-§6 still describe subject{user,agent}+identifier and mandate config_cert.iss==access_cert.iss (§4.3/§6.2 step2/§8/§9b), but code uses holder+grantor/grantee and AccessPresentation::verify (browserid-core/src/device.rs:616-632) deliberately removed that binding for the cross-issuer delegated model. Spec normatively mandates a check the reference verifier does not perform and mis-states the trust argument. Rewrite §4-§6 against code; design doc docs/design/browserid-end-to-end-flow.md already reflects the new model. See docs/spec-code-audit-2026-08-07.md H1.

## Corrected actor/artifact model (review discussion 2026-08-08)

The spec rewrite should be built on this model (validated against code in this discussion):

**Actors**
- **IdP** — a domain authoritative for its own identities. Issues device certs (purpose `authentication` = can mint access certs; purpose `authorization` = a *config cert* = can sign warrants) and runs the mint API.
- **Grantor** — an identity holder with an authorization (config) cert; authorizes new permissions FOR that identity by signing warrants. Pinned: the config cert's issuer must be authoritative for the grantor identity (`config_cert.authorizes_identity(grantor)` + resolver binds cc.iss to grantor's domain).
- **Grantee** — an identity holder who acts / accesses a resource; proven live at presentation by the assertion signed by its access cert's fresh key.

**Grantor/grantee asymmetry (the key correction)**
- At warrant-**signing** time the grantee is arbitrary — the grantor freely chooses any grantee.
- At **presentation** time the grantee is NOT arbitrary — `verify()` requires `warrant.grantee == access_cert.identity` (device.rs:666). The grantor end is always pinned to the grantor's domain; only the grantee end is open.

**Why the config cert (not a grantor access cert) is presented**
Not because the grantor can't get an access cert — it can. By design: warrants must be long-lived and device-agnostically reusable, so they are signed by the durable config cert (90d) rather than a short-lived access cert (24h). The config cert accompanies the warrant so the verifier can check the warrant's signature and root the grantor in its IdP. (The grantor also has no liveness to prove at presentation — only the grantee acts.)

**Holder dimension (missing from the spec entirely)**
The access cert carries an opaque broker-assigned holder; the warrant carries a holder matcher (`*` / `<ns>.*` / `<id>`) that must cover it (anti-fungibility — the grant binds to a specific credential/device family, not just the identity). This replaced the old `subject{user,agent}` axis.

## Corrected actor/artifact model (review discussion 2026-08-08)

The spec rewrite should be built on this model (validated against code in this discussion):

**Actors**
- **IdP** — a domain authoritative for its own identities. Issues device certs (purpose `authentication` = can mint access certs; purpose `authorization` = a *config cert* = can sign warrants) and runs the mint API.
- **Grantor** — an identity holder with an authorization (config) cert; authorizes new permissions FOR that identity by signing warrants. Pinned: the config cert's issuer must be authoritative for the grantor identity (`config_cert.authorizes_identity(grantor)` + the resolver binds cc.iss to the grantor's domain).
- **Grantee** — an identity holder who acts / accesses a resource; proven live at presentation by the assertion signed by its access cert's fresh key.

**Grantor/grantee asymmetry (the key correction)**
- At warrant-**signing** time the grantee is arbitrary — the grantor freely chooses any grantee.
- At **presentation** time the grantee is NOT arbitrary — `verify()` requires `warrant.grantee == access_cert.identity` (device.rs:666). The grantor end is always pinned to the grantor's domain; only the grantee end is open.

**Why the config cert (not a grantor access cert) is presented**
Not because the grantor can't get an access cert — it can. By design: warrants must be long-lived and device-agnostically reusable, so they are signed by the durable config cert (90d) rather than a short-lived access cert (24h). The config cert accompanies the warrant so the verifier can check the warrant's signature and root the grantor in its IdP. (The grantor also has no liveness to prove at presentation — only the grantee acts.)

**Holder dimension (missing from the spec entirely)**
The access cert carries an opaque broker-assigned holder; the warrant carries a holder matcher (`*` / `<ns>.*` / `<id>`) that must cover it (anti-fungibility — the grant binds to a specific credential/device family, not just the identity). This replaced the old `subject{user,agent}` axis.

## Progress (2026-08-08): core protocol spec reconciled

`docs/specs/browserid-ng-protocol.md` updated to the current model:
- §3.1 support-doc fields corrected (no `mint`; real fields device-cert/access-cert/device-authorization/agent-device-authorization/device-revoke) — closes M2 (browserid-ng-o68b) for the support doc.
- §4 axes: dropped `subject{user,agent}`, added the opaque `holder`; shorthand table now device cert / config cert.
- §4.1/§4.2 claim tables: subject→holder on device cert, access request, access cert.
- §4.3: removed the `config_cert.iss == access_cert.iss` binding; reframed as "config cert issuer must be authoritative for the warrant grantor" + a cross-issuer note + the implementer caveat that core verify() does not enforce the binding (the resolver must).
- §4.5 Holders and §4.6 Subaddressing added as new subsections.
- §5 warrant claims: identifier/subject → grantor/grantee/holder-matcher; softened the "don't publish" note to "bulk publication only" (individual publish OK, e.g. SBO on-chain).
- §6.1 verify API: /verify + `assertion` field → /verify-access + `presentation` field + accepted_fallbacks; return shape (email=grantor, grantee, holder, issuers, scopes; no subject) — closes M2 for the verify endpoint.
- §6.2 algorithm: rewrote the join to (grantee==access identity, holder∈matcher, audience) attributing to grantor; step 2 is now per-identity issuer authority (not the equality); renumbered; return has no subject.
- §7/§8/§9/§10: mint→access-cert, dropped `subject: agent`, SMTP→"or another supported proof", conformance boundary + clause (b) reworded to per-identity authority.

Remaining spec work (still old-model):
- H4 (browserid-ng-rsh1): docs/specs/agent-provisioning-and-grant-api.md — 36 subject / 12 identifier / 0 holder; needs the same pass.
- README.md: "agent model in one picture" (subject=agent), the /verify example (r.subject, {email,subject,scopes,issuer}), and the "checks config_cert.iss == access_cert.iss" line.

## Spec revision pass 2 (2026-08-08, review feedback)

Reworked `docs/specs/browserid-ng-protocol.md` per review:
- STATUS block trimmed to a plain "draft" note (no bean/doc/code links).
- §1 now names actors properly: Identity vs Holder vs Grantor vs Grantee, each grantor/grantee an (identity, holder) pair — and states that **authorization attaches to (identity, holder)**, not identity alone.
- §2: explained why not JWK (fixed-alg ⇒ JWK carries redundant constants + an attacker-controllable alg/crv; bare 32-byte key removes the confusion class).
- §4 shorthand: made explicit both are device certs — "authentication device cert" + "config cert (authorization)".
- §4.3: removed the cross-issuer/historical note + implementer caveat (moved the cross-issuer explanation to §5; verification enforcement is in §6); no historical framing.
- §4.4/§4.5/§4.6: removed bean ref; removed the "former subject" mention; removed code refs.
- §5: added "grantor and grantee are independent identities (possibly different IdPs)" explanation here.
- §6: removed §6.1 HTTP verifier API (the /verify-access endpoint is a convenience service, not protocol — belongs in verify-quickstart.md); §6 now opens by describing how to verify a presentation; renumbered 6.1 algorithm / 6.2 offline / 6.3 status.
- §7 rewritten as "IdP operations" (7.1 issuance, 7.2 mint, 7.3 web login exchange) describing how login works positively (a first-party login mediator + popup), not "does not use navigator.id".
- Removed ALL code-path/line references and bean references throughout; moved BrowserID lineage to Appendix A.
- Applied the SMTP→"or another supported proof" and warrant bulk-publish softening spec-wide.

Filed separately: /verify-access → /verify endpoint rename.
Still remaining: H4 agent-provisioning module + README (same subject→holder/grantor pass).

## Spec revision pass 3 (2026-08-08, review feedback)

- Tightened verbose passages (§1.2/§4.5/§6.2, JWK rationale); removed the "load-bearing" cliché.
- §1 restructured: §1.1 Actors = Identity, IdP, RP (primary); §1.2 Holders and roles (grantor/grantee as (identity,holder) pairs); §1.3 Infrastructure = the broker (user-agent sense; client + hosted components; MAY also be a fallback IdP but that is a separate role, verifies nothing). Fallback IdP no longer listed as a standalone actor.
- §3: dropped the "no dual path / .well-known key NOT trusted / advisory" framing entirely; §3.1 support-doc no longer has a public-key field (document carries no key). Filed browserid-ng-zexp to remove the advisory public-key from the discovery struct + broker route + consumers.
- §4 shorthand: renamed "authentication device cert" → "auth cert".
- §4.6 subaddressing qualified: authorization-only. A config cert for foo@domain may grant for foo+tag@domain; an auth cert for foo@domain mints for foo@domain EXACTLY — acting as foo+tag needs its own auth cert. Filed browserid-ng-bls2 for the code fix (mint currently uses identity_matches with subaddressing on the auth path).
