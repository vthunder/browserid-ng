# Adversarial security review — device-cert model + migration plan

Scope: `docs/design/browserid-end-to-end-flow.md`, `docs/plans/2026-07-18-device-cert-model-migration-plan.md`,
`docs/plans/2026-07-18-divergence-analysis/*`. Claims verified against
`browserid-core`, `browserid-broker`, `browserid-registrar`, `browserid-rp`.

The model's central security bet is sound: **the access cert is the authentication
anchor** (fresh key, minted only by the identity's authoritative IdP, gated online),
and warrants are authorization-only and "useless without a matching access cert"
(design L112-115). Verified: today's assertion is signed by the leaf cert's key and
the RP roots the cert at the DNSSEC domain key (`assertion.rs:317,345-347`), and the
primary/fallback conformance rule is already enforced (`verifier.rs:223-233`). So
warrant *forgery alone* is not account takeover.

But the warrant is the **user-authorization / consent artifact**, and the plan
weakens the properties that bind it to the real user. The findings below attack that.

---

## BLOCKER 1 — Config-cert → identity-domain binding is unspecified; warrant signer is unrooted

**Attack.** The design's join is *only* "(identity, subject, audience)" (design
L106, L131-134). It never states that the **config cert that signs a warrant must
be issued by the identity's authoritative IdP** and list that identity. `grep` for
"issuer"/"issued by"/"authoritative" in the design returns **nothing** for the
config cert. So as written, an RP would accept `warrant` signed by *any*
`authorization`-purpose cert from *any* IdP the RP can resolve a key for.

Consequence: an agent that legitimately holds an access cert for `agent@victim`
(subject=agent) can self-issue a config cert from a **rogue/attacker-run IdP**
granting itself elevated scopes / new audiences, and the RP's join succeeds — the
config cert need not be the *user's* consent cert at all. The whole point of a
warrant (user authorization, least privilege) is defeated. This is a
**consent-bypass / privilege-escalation**, worst for agents.

**Regresses vs today?** YES. Current `Warrant::verify_for` pins the delegator to
the agent's own IdP: `parent.issuer() != agent_cert.issuer()` is rejected
(`warrant.rs:189-195`), and the embedded parent cert is verified under the same
`issuer_key` rooted at the DNSSEC domain key (`assertion.rs:376-378`,
`verifier.rs:313-324`). The current model *cannot* accept a delegator from a
foreign/rogue IdP. The device-cert design drops this pin unless re-added.

**Fix.** Spec MUST require: `config_cert.iss == domain(identity)`, resolved via the
same DNSSEC primary/fallback path as the access cert (reuse `verifier.rs:216-258`);
the identity MUST be in the config cert's identity list; and `config_cert.purpose ==
authorization`. Add to the join key, with a conformance test. Add this to P1
(`AccessPresentation verify`) and P6 as an explicit fail-closed check — the plan's
"join by (identity,subject,audience)" wording does not currently include it.

---

## BLOCKER 2 — Server-side config certs convert authorization from a user-key op to a broker-key op

**Attack.** Design L46-49 blesses a config cert living **server-side at the hosted
broker** ("convenient … a storage choice, not a protocol distinction"). The hosted
broker is *also* the fallback IdP that mints access certs for every fallback-hosted
identity (`fallback_idp.rs`, `cert.rs`). So a compromised broker holding a
server-side `authorization` config cert can, for every fallback identity, **both**
mint an access cert **and** sign a warrant — silent, complete impersonation with no
user device and no user key ever involved. If BLOCKER 1 is unfixed it extends to
primary identities too.

**Regresses vs today?** YES, specifically for the *authorization* half. A
compromised IdP has always been able to mint identity/access certs (inherent IdP
trust — unchanged). But **today a warrant requires `U_priv`, the user's identity
key, exercised in-browser at consent** (`warrant.rs:91-138` `create(identity_key)`;
`consent.rs respond()` validates a client-signed warrant). That key is **not held
server-side**. The device-cert design's server-side config cert removes the "the
user's own signing key must participate in every authorization" property — a real
reduction in what a server compromise yields (authorization, not just
authentication).

**Fix.** Treat server-side config certs as a documented trust downgrade, not a mere
"storage choice." At minimum: forbid server-side storage for `authorization+agent`
and `authorization+any` (the powerful combos); require config-cert private keys to
be non-extractable and device-resident for anything that can authorize agents;
surface "this warrant was signed by a broker-held key" in the RP's verified result
so RPs can policy-gate it. Revisit the design L46-49 framing.

---

## MAJOR 3 — Foreign status-list revocation is fail-open (and unimplemented in the hosted verifier)

**Attack.** The design mandates two revocation authorities: access cert → IdP list,
warrant → broker list (design L133-134). The hosted verifier checks **only** refs
whose `uri == own_uri` and explicitly skips foreign issuers
(`verify.rs:72-75,89-103` — "no federated IdP issues status claims today"). Under
the new model primaries (e.g. sandmill.org, plan P10) issue access/device certs
carrying **their own** status list — a foreign list the hosted verifier never
fetches → **revocation of a stolen access/device cert is invisible** at the hosted
verifier. `browserid-rp`'s `StatusCache` exists but defaults `fail_closed=false`
with a 600s grace (`lib.rs:458,474-476,508-520`) → `Unknown` degrades to
"allowed". Both default fail-open.

Note the **device cert** is the sharp edge: unlike short-lived IdP-gated access
certs, "revoke one to log that device/agent out" (design L72) has **no online gate
except the mint endpoint's own revocation check**. If the mint endpoint doesn't
hard-check device-cert revocation, a stolen device cert keeps minting until its
short access certs are individually caught — which the fail-open lists won't do.

**Regresses vs today?** Equal *today* (single own-list, no federation), but the new
model **requires** federation and the design leans on foreign-list revocation as a
named authority while the code path is unimplemented + fail-open by default. So the
design over-promises a control the impl doesn't deliver.

**Fix.** P6 must port `StatusCache` into the hosted verifier AND set the posture:
warrant + device-cert status **fail-closed** (short grace acceptable); make the
**mint endpoint's device-cert revocation check** the load-bearing, non-optional
gate (P2). Add a conformance test that a revoked device cert cannot mint and a
revoked warrant is rejected even when the foreign list fetch fails.

---

## MAJOR 4 — Mandatory headless mint: retirement of endorsement removes the second-party gate; replay/DoS unaddressed

**Attack.** Today every mint requires a **fresh registrar/broker endorsement bound
to the exact bundle** — a second online party with a real-time veto/throttle/audit,
independent of the IdP (`agent.rs:102-108` `verify_as_target_idp`;
`Endorsement::verify_for`). The plan retires endorsement entirely (plan §4, P2:
"Remove `/provision/endorse`") and makes the IdP mint endpoint the **sole**,
device-cert-signature-only gate, mandatory and headless (design L84-97). Two losses:

- **Defense-in-depth gone.** A compromised-but-not-yet-revoked device cert now mints
  unlimited access certs against one endpoint with no second-party approval and (in
  the design) no specified rate limit/quota. Design L92 "may refuse" is discretionary,
  not a required control.
- **Replay of the access-request token.** The design doesn't state the
  access-request token is single-use / nonce'd / short-lived. Today `R` is a fresh
  per-request signed object inside the chain; the new token must be equally
  replay-proof or a captured token re-mints.

**Regresses vs today?** YES for the two-party property and the endorsement
throttle/veto. Neutral-to-better on simplicity, but the plan doesn't replace the
removed control.

**Fix.** Spec the access-request token with a nonce + tight expiry + audience(=IdP)
binding and single-use enforcement (P1/P2). Require the mint endpoint to implement
per-device-cert rate limiting + revocation check + refusal signalling as
**conformance** items, not discretionary. Consider retaining an optional endorsement
hook for high-value IdPs.

---

## MAJOR 5 — Loss of the warrant's temporal (signing-time) binding

**Attack.** Current warrants are bound to a specific short-lived U_cert via
signing-time semantics: signed while the embedded parent cert was valid, verified
under that cert's exact key (`warrant.rs:198-212`, `parent.public_key()`). New
warrants are **long-lived, stored, reused device-agnostically** (design L104-110)
and signed by a **long-lived** config cert. A leaked/rogue warrant (see BLOCKER 1)
or a warrant signed by a since-rotated config key has no temporal safety net except
the broker status list — which fails open (MAJOR 3). So the config cert's own
rotation/revocation must propagate to *every* warrant it signed, a **third**
propagation path the design doesn't describe (access→IdP, warrant→broker, but
**config-cert→its warrants** is unspecified).

**Regresses vs today?** YES on temporal binding; the plan trades it for
registry+status-list, which is only as good as MAJOR 3's fix.

**Fix.** Define config-cert revocation → warrant invalidation (e.g. warrant status
entries indexed under the signing config cert, revoked en masse when it is). State
it in P4 (config-cert registry) and P2/P3 (status kinds).

---

## MINOR 6 — Blank/`any` subject collapses the least-privilege axis

The "config cert" default in the design table is `subject: (blank/any)` (design
L32), i.e. one cert authorizes **both** user logins and agents. That is the most
powerful credential in the system and the design presents it as the *default* config
cert. A user's blank-subject authorization cert (especially server-side, BLOCKER 2)
can silently authorize agents the user never consented to per-agent.

**Fix.** Default-deny blank subject; require explicit `authorization+user` vs
`authorization+agent`; treat blank/`any` as an advanced/discouraged combo. Ensure
verifiers enforce **subject equality across access cert and warrant** in the join
(design lists subject in the join but there is no code/test yet — `is_agent()` is
the only axis today, `certificate.rs`), else an agent-subject access cert could ride
a user-subject auto-warrant. Add conformance tests (P6).

## MINOR 7 — purpose/subject fail-closed is claimed but not yet real

Design L37 "Verifiers reject unknown purpose/subject" is correct discipline and
matches the existing `typ` domain-separation idiom (`provisioning.rs:33-35`,
`Certificate::parse` rejects unknown typs). But the axes don't exist in
`CertificateClaims` yet (`certificate.rs:59-101`, only `is_agent()`). Ensure the
new fields are **required** (absent ⇒ reject) and that `authentication` certs can
*only* mint and `authorization` certs can *only* sign warrants, enforced at the
verifier, with tests. Additive, but easy to ship half-open.

---

## Net assessment

The authentication core (access cert rooted at the identity's IdP, fresh-key-bound
assertion) is at least as strong as today. The **regressions are all on the
authorization/consent side**: unrooted warrant signer (BLOCKER 1), broker-held
authorization keys (BLOCKER 2), and the fail-open federated revocation the new model
newly depends on (MAJOR 3). Fix 1+2 at the design level before building; 3-5 are
plan/impl conformance gaps to pin down in P1/P2/P4/P6.
