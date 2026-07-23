---
# browserid-ng-atge
title: 'Delegated attribution: dedicated grantee identity + on-chain acting-for (model A)'
status: completed
type: epic
priority: high
created_at: 2026-07-23T13:32:55Z
updated_at: 2026-07-23T18:17:51Z
blocked_by:
    - browserid-ng-yhcx
---

Restore VERIFIABLE delegated attribution on top of the holder model. A write is signed on-chain by a distinct GRANTEE identity (e.g. mingo-poster@mingo.place) but authorized + attributed to a GRANTOR identity (e.g. dan@mingo.place), proven by the grantor's config-cert signature over the warrant. Clients see "grantee acting for grantor" from chain data — provenance is intrinsic, not a bolted-on badge.

## Decision (2026-07-23, with Dan): build MODEL A
Two attribution models were on the table:
- (A) Full delegated attribution — grantee is a distinct on-chain principal; its key signs; sbo resolves the attributed author back to the grantor. Provenance is a consequence of the authorization structure, verifiable end-to-end.
- (B) As-you signing + a verifiable provenance marker (owner stays the user; a bound creator/agent marker names the actor). Lighter; no chain surgery. REJECTED — Dan wants the grantee to be a real, distinct, revocable on-chain principal.

## Two-identity abstraction (the generalization)
A grant pins TWO independently-choosable identities:
- GRANTING identity (authorizer/delegator): whose config key signs the approval + who the write attributes to.
- RECEIVING identity (grantee): who gets the access cert and signs on-chain (Warrant.identifier).
When equal => today's holder-model as-you (degenerate case, keep working). When they diverge => delegated on-behalf (this epic).

## Grounded current state (traced 2026-07-23)
The holder migration (sbo ac48868) COLLAPSED grantor+grantee into one identity and DELETED delegated attribution:
- Warrant (browserid-core/src/device.rs:445): identifier/holder/audience/scopes/status — NO delegator field.
- Certs dropped is_agent + parent; human/agent axis explicitly gone (device.rs:526-527).
- sbo authorize (authorize.rs:289 authorized_write_email) returns attr.email; is_authorized (resolve.rs:171) requires attributed_email == owner. No signer!=attributed path. `as:` is a vestigial no-op (authorize.rs:259).
- The old warrant_effective_email / agent_effective_email (signer=agent, attributed=delegator via as:<delegator>+path:) were removed in ac48868. Model A re-introduces this, but PROPERLY: grantor binding is config-cert-SIGNED (not the self-asserted `subject` the holder model rightly killed).

## Key design tensions to resolve during build
- Warrant encoding for divergence: identifier=grantee + new on_behalf_of=grantor? And warrant signed by grantor's config key.
- Presentation shape breaks the issuer-consistency rule (config.iss==access.iss) when grantee issuer != grantor issuer => needs TWO issuer DNSSEC proofs. Reuse the cross-issuer work (bean yhcx), don't reinvent.
- sbo: revive effective-author resolution (attributed = grantor when a valid signed grantor binding is present; signer/access-cert identity = grantee).

## Workstreams (children)
1. Point 1 (independent, now): explicit legible failure — no silent poll timeout on identity mismatch.
2. Point 2: /agent-provision/request pins granting + receiving identities (each optionally required/locked); account approval respects the pins.
3. Point 3: sbo delegated attribution (revive effective-author) + cross-issuer second-issuer proof + browserid-core warrant fields + mingo mints/holds a dedicated mingo-poster@mingo.place identity again.

Blocks/relates: browserid-ng-yhcx (cross-issuer warrants — foundation), browserid-ng-esuk (post provenance — subsumed by A), browserid-ng-3b8m (poster), mingo-3f3i (superseded as-you poster).


## Design map (grounded 2026-07-23) — the presentation stays 4 objects

Verification traced: AccessPresentation `access_cert ~ assertion ~ warrant ~ config_cert` (device.rs:535-566); verify at device.rs:573-644. Key invariants today:
- config.iss == access.iss (device.rs:584) — the exact rule divergence breaks.
- warrant signed by CONFIG cert key (device.rs:618); warrant.identifier == access.identity (device.rs:622); warrant.holder matches access.holder (device.rs:625).
- config cert = Authorization purpose, authorizes the ACCESS identity (device.rs:610-615).
- sbo device_attribution single-issuer only; auth_evidence is ONE Option; daemon resolves the single presentation issuer's /sys/dnssec on-chain when evidence absent (validate.rs:222-238).

CORRECTION: cross-issuer (yhcx) is NOT actually in the tree. Only DNSSEC primitives + a DEAD `CrossIssuerMissingEvidence` variant survive in sbo attribution.rs; the registrar `external` flag is inert scaffolding (never set true); `warrant_external`/effective-author hooks are dangling doc refs. So model A BUILDS cross-issuer, not reuses it. (Un-block atge from yhcx — yhcx is a stale claim.)

### The shape (elegant result): delegated attribution keeps the 4-object presentation
`access_cert(G) ~ assertion(G) ~ warrant(D→G) ~ config_cert(D)` where G=grantee (mingo-poster@mingo.place), D=grantor (dan@…). The access cert stands alone (proves G holds the signing key, verified under issuer_G). The warrant is the delegation instrument, signed by D's config cert. Changes:
- WarrantClaims gains `on_behalf_of: Option<String>` (= D). Absent ⇒ as-you (today's path, unchanged).
- verify branches: when on_behalf_of present, config authorizes D (not G); warrant.identifier still == access.identity (G); EFFECTIVE AUTHOR = on_behalf_of (D).
- sbo: revive effective-author = on_behalf_of (properly bound this time — config-cert-signed, not self-asserted). owner == D via existing email match.

### Phasing (de-risked — same-issuer first delivers the demo)
Milestone 1 — SAME-ISSUER delegated attribution (mingo-poster@mingo.place acting for dan@mingo.place). issuer_G == issuer_D == mingo.place, so config.iss==access.iss STILL HOLDS — no cross-issuer, no second proof. Needs only: warrant on_behalf_of + verify branch (config authorizes grantor; effective author = grantor) + sbo effective-author + registrar/account approval for a distinct same-issuer grantee + mingo revives mingo-poster@mingo.place (stale poster_key + create_agent_identity infra is the seed). DELIVERS the dan@mingo.place demo.
Milestone 2 — CROSS-ISSUER (external-email grantors, e.g. dan@sandmill.org → mingo-poster@mingo.place). Relax config.iss==access.iss under on_behalf_of; two-issuer key resolution; SECOND DNSSEC proof resolved on-chain for BOTH /sys/dnssec/<issuer_G> and /<issuer_D> (poster keeps both fresh — no new wire field). Registrar external-warrant path (activate the inert `external` scaffold).

### Open decisions (need Dan)
- D1 Holder binding for delegated grants: warrant.holder currently binds to access.holder (G's, assigned by G's issuer). For a distinct service identity, isolate/revoke via the warrant's own status ref instead? (lean: keep identifier==access.identity binding; revocation via warrant status ref in D's registry; holder matcher = G-side or `*`.)
- D2 Second-issuer proof mechanism (M2): resolve both issuers' /sys/dnssec on-chain (no wire change) vs add a second auth_evidence slot. (lean: on-chain both.)
- D3 Encoding: identifier=grantee(G) + new on_behalf_of=grantor(D), keeping the existing identifier==access.identity binding intact. (lean: yes — least churn.)


## Decisions FINALIZED (2026-07-23, with Dan) — proceeding to build
- RENAME: WarrantClaims.identifier -> grantor + grantee, BOTH always required (as-you = grantor==grantee). Single verify code path, no Option branch. Breaking warrant format; regenerate golden vectors.
- KEEP the holder binding (D1 resolved): warrant.holder still matches the GRANTEE's access-cert holder (anti-fungibility preserved). `<id>` matcher is issuer-agnostic, so D pins mingo-poster's mingo-assigned holder directly. Revocation via warrant status ref. Nothing weakened. Grantee device cert needs a STABLE holder; grantee's holder is supplied by the request (not broker-assigned in prepare).
- ONE build, not two milestones (cross-issuer is a small generalization): remove `config.iss==access.iss`; verify access under access.iss + config under config.iss; daemon resolves BOTH issuers' on-chain /sys/dnssec. Same-issuer is the degenerate case.

## Verify rework (browserid-core device.rs:573-644) — exact
- effective author = grantor (was access.identity). This is WHY cross-issuer is safe: a warrant signed by issuer X's config cert can only attribute to an identity X vouches for.
- config authorizes GRANTOR (was access.identity); config verified under cc.iss key; access under ac.iss key; drop the iss-equality check.
- wc.grantee == ac.identity (the actor/signer). holder matcher still vs ac.holder.
- VerifiedAccess: email = grantor; issuer = cc.iss (grantor's issuer, for domain-binding of the attributed identity); ADD grantee (+ grantee issuer) for provenance.

## SHIPPED (2026-07-23) — all 4 steps built, tested, deployed
- Step 1 core grantor/grantee (browserid-ng 2582555)
- Step 2 sbo delegated attribution + two-issuer (sbo ae1a998)
- Step 3 registrar delegated approval + account card (browserid-ng, deployed 7a9960f)
- Step 4 mingo-poster@mingo.place delegated service identity (mingo c7a9169)
Deployed + verified live: browserid.me (broker+registrar) 200, mingo.place 200, sbo-daemon ae1a998 health 200. Live smoke: deployed registrar accepts grantor/grantee delegated request + echoes pins. Coordinated breaking wire-format flip complete. Awaiting Dan's interactive poster e2e.
