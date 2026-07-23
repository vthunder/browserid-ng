# Spec ⇄ code divergence audit (2026-07-23)

**Status:** findings recorded; per-item decisions tracked in beans (see end).
**Specs audited:** `docs/specs/browserid-ng-protocol.md` (core),
`docs/specs/agent-provisioning-and-grant-api.md` (v0.6).
**Ground truth:** `browserid-core/src/{device,assertion,discovery,status,rp_auth}.rs`,
`browserid-broker/src/{verifier.rs,routes/*}`, `browserid-registrar/src/consent.rs`,
`browserid-rp/src/lib.rs`, `test-vectors/device-cert-v1.json`.

**Headline:** both specs are still written to the `subject: user|agent` +
warrant-`identifier` model. Code replaced that with an opaque
`Holder`/`HolderMatcher` axis and a `grantor`/`grantee` warrant — and went
further than a rename: the warrant now carries two distinct identities
(grantor = attributed author, grantee = actor), i.e. delegated/on-behalf
grants are a new capability with no spec concept. The old
`config.iss == access.iss` binding is fully removed in core (bean
`browserid-ng-yhcx`, cross-issuer third-party delegation), but the hosted
broker verifier still enforces single-issuer — core and broker contradict
each other.

Legend: **(A)** intentional rename — update spec; **(B)** needs decision;
**(C)** code may violate spec intent; **(D)** code ahead of spec;
**(E)** spec claim unimplemented.

---

## Group B — Needs decision (most consequential)

### B1. Core removed the config-cert issuer binding; broker verifier did not — they disagree

- Spec mandates `config_cert.iss == access_cert.iss` in: §4.3
  (protocol.md:216-218), §6.2 step 2 (protocol.md:319-321), §8
  (protocol.md:477-479), §9 (protocol.md:534); agent-api §3 (api.md:121-123),
  §5.3 step 2 (api.md:312), §8 (api.md:508-510). All frame it as THE
  privilege-escalation guard.
- Core deliberately dropped it: `device.rs:618-622` resolves the config cert
  under its own issuer when `cc.iss != ac.iss`; rationale `device.rs:607-615`
  ("safe WITHOUT the old rule because the write attributes to the GRANTOR… a
  warrant signed by issuer X's authorization cert can only ever attribute to
  an identity X vouches for"). This is bean `browserid-ng-yhcx`.
- Broker hosted verifier is still single-issuer and CANNOT do cross-issuer:
  `verifier.rs:164-183` runs conformance on the ACCESS cert's identity domain
  (the grantee), resolves one `idp_key` for `ac.iss`, and the closure at
  `verifier.rs:189-194` returns Err for any `req_iss != iss`. So
  `cc.iss != ac.iss` → error → `/verify-access` rejects. It also never
  discovers/validates the grantor's issuer. **Cross-issuer bundles that
  verify in core/`browserid-rp` FAIL at hosted `/verify-access`.**
- Decision: (1) confirm cross-issuer is intended (it is, per yhcx);
  (2) rewrite the issuer-binding spec sections around grantor-attribution as
  the new guard — new security text must state: the write attributes to the
  grantor, the config cert must be authoritative for the grantor
  (`device.rs:643-648`), grantee is bound separately via
  `wc.grantee == ac.identity` (`device.rs:657-659`), and the holder matcher
  prevents fungibility (`device.rs:663-665`); (3) bring the broker verifier
  up to core's cross-issuer capability.

### B2. Reference verifiers are fail-OPEN on revocation; spec requires fail-CLOSED

- Spec: §6.4 (protocol.md:408-412) "All three checks are fail-closed"; §9
  (protocol.md:534); agent-api §3/§8 (api.md:143-147, 537-538).
- Broker `/verify-access` checks NONE of the three status refs:
  `verifier.rs:135-137` NOTE "Revocation is therefore not yet enforced";
  `verify_access_with_dns` (verifier.rs:138-206) never touches them.
  Contradicts §6.4's claim (protocol.md:372-376) that the broker "checks its
  own credentials authoritatively at /verify."
- `browserid-rp` defaults fail-open: `StatusCache::new()` sets
  `fail_closed:false` (lib.rs:483-492); `Verifier::verify` passes `Unknown`
  unless opted in (lib.rs:242-247); fail-closed is opt-in via `fail_closed()`
  (lib.rs:494-498).
- Decision: flip reference defaults to fail-closed + implement broker
  checking, or downgrade the spec MUST to a policy knob and mark broker
  enforcement planned.

### B3. Access-request `jti` replay protection unimplemented at the mint

- Spec §4.2 (protocol.md:186), §8 (api.md:214-216, 526-528).
- `jti` claim exists (device.rs:298) but `access_mint` has
  `// TODO (B2): single-use jti replay cache` (routes/device.rs:278) and
  never checks it.
- Decision: implement, or mark as known gap.

---

## Group A — Intentional subject→holder / identifier→grantor,grantee rename (spec update, no decision needed)

Largest work item. Every `subject` and `identifier` mention in both specs is
stale.

- **protocol.md:** §4 axes text + shorthand table (lines 131-142); §4.1
  `subject` row (156); §4.2 access-request/access-cert `subject` (187, 198);
  §4.3 (211-212); §5 warrant table `identifier`/`subject` (253, 263, 264) +
  "(identifier, subject)→audience" (254-256); §6.1 "returns … subject" (296);
  §6.2 step 1 (318), step 6 (331-332), step 7 "warrant.identifier ==
  access_cert.identity, warrant.subject == access_cert.subject" (334-336),
  step 9 (343).
- **Code truth:** `DeviceCertClaims.holder` (device.rs:201-203);
  `AccessRequestClaims.holder` (device.rs:305); `AccessCertClaims.holder`
  (device.rs:378); `WarrantClaims{grantor,grantee,holder:HolderMatcher}`
  (device.rs:446-469) — no identifier/subject; verify join = grantee ==
  identity + matcher-covers-holder (device.rs:657-665). "subject axis
  replaced" is explicit at device.rs:97-98.
- **api.md:** `subject:agent`/`identifier` load-bearing throughout — §1
  (75-78), §2 (96-113), §3 (118-152), §4.1 example (176-188), §4.2 example
  (202-212), §5.1 example (239-253), §5.2 warrant example+fields (262-296),
  §5.3 steps (306-322), §6.2 request example (348-359), §7.3 body (477-481).
  The "subject:agent IS the attribution" thesis (251-253, 539-541) must be
  re-expressed as grantor/grantee provenance.
- **Test vector confirms wire form:** certs carry `holder:"br.main"`; warrant
  carries grantor/grantee/`holder:"br.*"`; `reject_cases`
  (device-cert-v1.json:84-91) enumerate the new join rules. No `subject`
  anywhere.
- **New capability with NO spec concept:** grantor (attributed) vs grantee
  (actor) split for delegated on-behalf grants (device.rs:452-459;
  `VerifiedAccess.email/grantee/issuer/grantee_issuer` device.rs:536-559) —
  substance of beans esuk/8cow. Needs a fresh §5 write-up, not a rename.

---

## Group D — Code ahead of spec (spec stale)

- **D1** Support-document fields (§3.1, protocol.md:108-115): spec `mint` →
  code field `access-cert` (discovery.rs:45, served /access/mint
  well_known.rs:29); code adds `device-cert`, `device-authorization`,
  `agent-device-authorization` (discovery.rs:40, 54, 63) not in spec; broker
  serves authentication/provisioning/device-cert/access-cert only
  (well_known.rs:23-31), no `mint`/`authority`.
- **D2** `/verify` endpoint (§6.1, protocol.md:295-299): actual route is
  `/verify-access` (routes/mod.rs:126); no `/verify`. Response
  `AccessVerificationResult` = {status, email, holder, scopes, issuer,
  reason} (verifier.rs:104-119) — `holder` not `subject`, and drops
  grantee/grantee_issuer that core computes (device.rs:542-548).
  `browserid-rp::VerifiedIdentity` also drops grantee (lib.rs:96-108).
- **D3** Grant-exchange token body (§7.3, api.md:477-481): `TokenResponse`
  has `holder` not `subject` (rp_auth.rs:156-174).
- **D4** `login` scope sentinel: undocumented. exchange filters "login"
  (lib.rs:405-410); login-only/empty warrant → unscoped token; empty
  otherwise → full RP set (grant_scopes lib.rs:421-424); test vector uses
  `scopes:["login"]`. Spec §7.3 (api.md:469-473) mentions only "warrant
  without scopes."
- **D5** Consent request/poll shapes (§6.2/§6.4): request is plain JSON
  {device_cert, identity, grants, label} authed by embedded device cert
  (consent.rs:642-654), NOT a self-signed `browserid-warrant-request-v1` JWS
  (that typ doesn't exist; only 4 typs device.rs:34-37); grant cap 1-10
  (consent.rs:711) vs spec 1-8; response adds `verification_uri_complete`
  (consent.rs:661); poll response {success, status, grants:[{audience,
  warrant}]} where warrant = `warrant~config_cert` pair (consent.rs:250-253,
  782-796) vs spec {status, warrants[], warrant}; expiry returns NotFound
  not HTTP 410, slow-down returns ValidationError not HTTP 429
  (consent.rs:809-819).
- **D6** External-service "§6.6" flow has NO spec section: code references
  §6.6 external/foreign-IdP consent (consent.rs:119-123, 146-147, 159;
  `external` flag, redirect-tied /consent/<code>). yhcx/8eld feature
  entirely unspecified. Couples with B1.
- **D7** Management surfaces beyond spec: wsapi warrant_requests / respond /
  warrants / register_warrant / allocate_warrant_status / forget /
  revoke_warrant (consent.rs); device_certs / browser_holder /
  revoke_device_cert + the whole holders/namespace API
  (routes/mod.rs:127-137). Holder-namespace model (browsers namespace,
  holder moves, labels) unspecified.

---

## Group C — Possible compliance gaps

- **C1** Per-user agent-cert quota (SHOULD, default 5; api.md:152, 193-194):
  no quota check found in routes/device.rs. Likely unimplemented.
- **C2** `oauth_metadata` (§7.4, api.md:488-499) omits `scopes_supported`
  (lib.rs:436-445); only the separate `oauth_metadata_with_scopes` includes
  it (lib.rs:538-546).

---

## Group E — Unimplemented spec claims

- §4.4 host certificate — honestly marked planned (protocol.md:220-224, bean
  dff5). No code. OK.
- §6.3 offline detached-DNSSEC (RFC 9102) verification — presented with no
  "planned" caveat (protocol.md:349-368), but no RFC 9102 code in
  browserid-core; lives in the sbo repo. Add a "planned / in sbo" note.
- jti replay cache (B3) and broker fail-closed status checking (B2) — both
  TODO in code, presented as done in spec.

---

## Not fully audited

DNSSEC §3 MUSTs (DNS-over-TLS, EDNS DO bit, AD-flag required,
SERVFAIL→hard-reject) — dns_fetcher.rs / fallback_fetcher.rs not read
line-by-line. Verify those MUSTs before closing the audit.

## Triage order

1. B1 (broker vs core cross-issuer contradiction)
2. B2/B3 (security posture)
3. A (bulk spec rewrite — bean ga3w)
4. D6/D7 (missing sections)
5. D1-D5, C1-C2, E
