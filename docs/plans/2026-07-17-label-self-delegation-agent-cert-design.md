# Self-Derivation Certificates — Design Spec & Change Inventory

Status: DESIGN (no production code). Author: agent for team-lead / dan.
Date: 2026-07-17. Version: **v2** (generalized self-derivation primitive; v1 was
+label-agent-only — see the changelog at the end).
Roadmap: item 4 of epic `browserid-ng-mr2n` (CLI-auth / agent identities for
external-primary IdP users). Bean `browserid-ng-u7t8`. Chosen by dan over item 3
(`browserid-ng-pv9b`, browserid.me-rooted agent).

Specification and precise, file:function-level change inventory. Does **not**
implement anything. Builds on the exploration verdicts in `browserid-ng-u7t8`
and `browserid-ng-pv9b`.

---

## 1. Motivation

A user whose home IdP (`sandmill.org`) is a **classic primary** — it publishes
`_browserid.sandmill.org` and serves interactive provisioning at
`/.well-known/browserid`, but has **no agent-mint endpoint** (`/provision/mint`
→ 404, not a `browserid-broker`) — cannot today obtain a CLI agent identity
(bug `browserid-ng-3nsg`). There is no agent-mint endpoint anywhere for a
`sandmill.org`-rooted delegator.

The fix removes any dependency on an IdP mint: the user's **existing**
`danmills@sandmill.org` identity key self-signs the credential it needs. v1 did
this for one case (a `+label` agent cert). v2 **generalizes** to a single
self-derivation primitive covering four cases with one verification path.

### Why this is real work, not a free cheat

The core requirement that an agent leaf be signed by the IdP's DNSSEC domain key
is enforced **independently in two security-critical verifiers** — browserid-core
(`assertion.rs` `verify`/`check_structure`, `warrant.rs` `verify_for`) and
sbo-core (`attribution.rs`, which re-verifies the agent cert against the
`_browserid.<iss>` DNSSEC key). Self-derivation adds a **new, constrained trust
path** that both must honor. To avoid drift, the path is implemented **once** in
browserid-core and **called** by sbo-core (decision F, §7).

---

## 2. The self-derivation primitive (the generalization)

**One rule.** A base identity `user@domain` — holding its **domain-signed base
cert** and the matching key — MAY self-sign a *derived cert* whose:

- **principal** ∈ { `user@domain` (same as base), `user+<label>@domain`
  (RFC 5233 subaddress of base) }; and
- **type** ∈ { agent, regular-identity }.

**Name constraint.** The derived principal local-part is exactly the base
local-part, or `base-local + "+" + <label>` (non-empty label, first-`+` split);
same `domain` as the base; and the derived cert's `iss` is the **base
identity's email** (see §5, issuer semantics — this is *self*-issuance, so the
issuer is the signer's identity, not the domain).

### 2.1 The four cases (all one primitive)

1. **Agent, principal = self** (`danmills@sandmill.org`): an agent that **acts as
   the base user**. This is the mingo-CLI-admin case and the phase-1 target (§8).
2. **Agent, principal = +label** (`danmills+mingo-cli@sandmill.org`): a distinct
   agent identity that **acts as itself** (that subaddress).
3. **Regular identity, principal = +label**: a per-site subaddress **login
   identity** (privacy — a distinct principal per RP), no warrant, full authority
   as that subaddress. This is the classic BrowserID "directed identity" benefit,
   now user-derivable without IdP cooperation.
4. **The base itself**: the domain-signed root, unchanged — the trust anchor the
   other three chain to.

### 2.2 Chain shape

```
domain key (sandmill.org, via _browserid DNSSEC)
  └─signs→  BASE cert   principal=danmills@sandmill.org   iss=sandmill.org   (domain-signed, short-lived)
              └─signs→  DERIVED cert
                          principal ∈ { danmills@ , danmills+label@ }  (same domain)
                          iss = danmills@sandmill.org          ← self-issued: issuer is the base IDENTITY
                          typ = self-derived (distinct typ; §3.1)
                          authority = open|closed              ← universal field; §3.2 / decision E
                          [agent case] agent.parent = danmills@sandmill.org
                          [agent case] status = <revocation URI>
```

Presentation embeds the fresh base cert so it is self-contained and
offline-verifiable (exactly as a warrant embeds its `parent-cert`):

```
[ base_cert(domain-signed) , derived_cert(identity-signed) ]  ~ [warrant~]  assertion
```

The base cert is domain-signed and **fresh** (short-lived, re-minted by the human
re-authenticating). A warrant is present **iff** the derived cert is an agent
cert (mandatory + audience-bound; §4). A regular-identity derived cert (cases 3,
4) carries no warrant.

### 2.3 Verification algorithm (ordered checklist, one path)

Implemented once in browserid-core (§7, decision F). Given a presentation:

1. **Parse** `[base, derived]` (or just `[base]`). Detect the self-derived typ on
   the derived cert (§3.1). If absent → classic domain-signed path, unchanged.
2. **Base cert domain-signed & fresh**: `base.iss == base` principal domain;
   `base.verify(domain_key)` under the DNSSEC domain key; `!base.is_expired()`
   (hard expiry — this is the freshness/chain-revocation lever, §6.1).
3. **Derived signed by the base key**: `derived.verify(base.public_key())`.
4. **Name constraint**: `derived` principal local == base local, or
   `base-local + "+" + <label>` (non-empty label); same domain.
5. **Issuer semantics** (decision D): `derived.iss == base.principal.email`
   (self-issued *by* the base identity).
6. **Type-specific:**
   - *agent*: `agent.parent == derived.iss == base.principal.email`
     (see §4 for who the agent acts as); a `status` ref MUST be present (§6.2);
     a warrant MUST accompany (structural `WarrantRequired`).
   - *regular identity*: no warrant; authority is full as the derived principal.
7. **authority field** (§3.2): read the explicit `authority` value; agent certs
   MUST be `closed`, regular/login certs `open`.
8. **Warrant** (agent only): run §4 checks with the base cert as parent-cert.

Accept only if all pass. The acting identity is the **derived cert's principal**
(decision B) — no `as:` resolution.

---

## 3. Certificate format additions

Extends `Certificate` / `CertificateClaims` in
`browserid-core/src/certificate.rs`.

### 3.1 (a) Verification marker — "self-signed, not domain-signed" (distinct typ)

Add a distinct `typ` so a verifier selects the constrained path and old verifiers
**fail closed** (the existing `Certificate::parse` matcher, `certificate.rs:223-241`,
rejects unknown `typ`s). Because a derived cert can be agent *or* regular, either
introduce two typs (`browserid-self-agent-cert-v1`, `browserid-self-id-cert-v1`)
or one self-derived typ plus the existing `agent` block to distinguish agent from
regular. Preference: **one self-derived typ marker + agent block presence** to
keep "is it an agent?" answered by the same `agent` field everywhere. Decide at
implementation (OQ-4 is about a *different* field — see H below).

This marker answers **how to verify** (which key signed it). It is kept
**distinct** from the `authority` field below, which answers **what it grants**
(decision H). Both exist; they answer different questions.

### 3.2 (b) Universal `authority` field (decision E.2, dan's refinement)

Add an **explicit `authority` claim to ALL cert types** (not agent-only, not
inferred from `typ`):

- `authority = "open"` on identity/login certs (base, regular subaddress): full
  authority **as the principal**.
- `authority = "closed"` on agent certs: authority is **warrant-defined** — an RP
  SHOULD consult the warrant's scopes, not the principal alone.

Explicit + universal is deliberate: a verifier is far more likely to read a field
that is present and meaningful on *every* cert than an agent-only flag it can
skip on the common path. A fully-naive verifier can still ignore it (that's why
the verifier-API mitigation, §3.4 / E.1, is the strongest layer), but
universality raises the odds it is honored.

### 3.3 (c) Status / revocation URI (agent certs)

Reuse the existing `status: Option<StatusRef>` field (`certificate.rs:99-100`).
**Mandatory** on self-derived agent certs; its `uri` names the revocation
authority the base identity chose (browserid.me by default). The verifier follows
whatever endpoint the cert names — **no pinning** (decision G, §6.2). No
`registrar` (that is the domain-signed concept).

### 3.4 New constructors

`Certificate::create_self_derived{_agent,_id}(base_cert, principal, base_key,
validity, authority, [status])`: assert the name constraint (§2.1), set `iss =
base_cert.principal.email` (decision D), set the self-derived typ + `authority`,
and (agent) `agent.parent = base principal` + mandatory `status`; sign with the
**base key**. Mirrors `create_agent` (`certificate.rs:164-207`).

### 3.5 Naive-RP mitigations, three layers (decision E)

In order of strength:

1. **STRONGEST — verifier API surface (a MUST on conformant verifiers).** A
   conformant verifier MUST surface agent-ness + scopes prominently — return an
   `AgentResult { acts_as, scopes }` (or make the agent attribution a
   non-optional, structurally-distinct part of the result), **never** a bare
   principal string a caller can mistake for "full access." Today
   `VerifiedPresentation { email, agent: Option<AgentAttribution> }`
   (`assertion.rs`) already carries agent attribution but as an easily-ignored
   `Option`; this hardens the contract so a library-using RP cannot reduce an
   agent presentation to its principal.
2. **Universal `authority` field** (§3.2) — better than an agent-only flag
   because it is meaningful on every cert.
3. **SHOULD directive**: for an agent cert the PRINCIPAL is *who it acts as*, not
   *what it may do*; authority = the warrant scopes. `SHOULD`, not `MUST` — an RP
   MAY consciously treat an agent-as-self as full power.

Reaffirmed structural backstop: an agent cert is **inert without a warrant**
(`check_structure` → `WarrantRequired`, `assertion.rs:264-265`).

---

## 4. Warrant stays SEPARATE from the cert (decision C)

We do **not** collapse the warrant into the cert, even though the IdP-privacy
rationale (warrants never transit the IdP) is moot for a self-signed cert.
Rationale recorded:

- **(i) Uniformity** — one presentation format works for self-signed *and* future
  IdP-issued agents.
- **(ii) Clean identity/authorization separation** — cert = WHO you are, warrant
  = WHAT you may do; same separation-of-concerns as SBO's identity-vs-govern.
- **(iii)** The warrant's per-audience + scope + status factoring is well-built.

The warrant stays **mandatory** and **audience-bound** for agent certs; **agent
authority = the warrant's scopes.** The hinge to record: collapsing cert+warrant
would become attractive **only if IdP-issued agents are ruled out** — until then,
keep them separate.

### 4.1 Changes to `Warrant::verify_for` (`warrant.rs:178-278`)

For self-derivation the delegator **is** the base identity; the warrant's
`parent-cert` is the **base cert** (domain-signed), signed by the base key (the
same key that signed the derived agent leaf).

- **Issuer match (`warrant.rs:189-195`) — CORRECTION vs v1.** v1 claimed "no
  change." That was a **bug** (dan caught it): a self-issued derived cert's `iss`
  is the base *identity*, not the domain, so `parent.issuer() ==
  agent_cert.issuer()` is **false** for the self-derived path (parent/base
  issuer = `sandmill.org`; agent issuer = `danmills@sandmill.org`). Generalize:
  for the self-derived path require **`agent_cert.issuer() ==
  parent.principal.email`** (the agent was issued *by* the base identity, which
  is the delegator/parent). The classic domain-signed path keeps the existing
  `parent.issuer() == agent_cert.issuer()` check.
- **Delegator consistency (`warrant.rs:214-233`)**: `warrant.iss ==
  parent_email == agent_cert.agent_parent()` — holds unchanged for the self case.
- **Revocation authority (`warrant.rs:254-275`)**: today pins the warrant's
  `status` origin to the cert's `registrar`. A self-derived agent cert has no
  `registrar` but has a `status` authority. Generalize the pin **and** apply
  decision G: for self-derived agents, follow the cert's status endpoint (no
  registrar pin, no origin-equality requirement). Fail-open within the cache/TTL
  window if unreachable (§6.2).

The `Warrant::create` guard "an agent identity cannot be a delegator"
(`warrant.rs:114-116`) is unaffected — the base is a plain identity cert.

---

## 5. Effective-author: retire the `as:` hack (decision B)

The acting identity is now the **verified derived cert's principal**, full stop:

- agent-as-self (principal `danmills@sandmill.org`) acts as `danmills@sandmill.org`;
- agent-as-subaddress (principal `danmills+mingo-cli@sandmill.org`) acts as that
  subaddress.

The SBO daemon's effective-author logic changes from "resolve `as:`" to "trust
the verified derived cert's principal" (`sbo-daemon` / `sbo-core`
`authorize.rs::warrant_effective_email`, `validate.rs::resolve_creator`).

**No transition window, no re-genesis.** Warrants are **not** persistent on-chain
objects — they ride inside a write's `auth_warrant` and are checked at validation
time. So invalidating all existing warrants is a **daemon code change, not a
chain event**: already-accepted writes stay valid (they were validated under the
old rules at their inclusion time); only *new* writes use the new model. Record
this explicitly in the spec so no one plans a migration/re-genesis.

Role/owner matching then works directly: `roles.admin =
["danmills@sandmill.org"]` matches an agent-as-self write because the effective
author **is** `danmills@sandmill.org` (the derived cert's principal) — no `as:`
plumbing, no canonicalization.

---

## 6. Revocation

Primary (`sandmill.org`) stays **dumb** — no revocation infrastructure there.

### 6.1 Chain revocation (expiry-driven)

Verifiers check the whole chain, so **not renewing the short-lived base cert
instantly invalidates every derived cert** under it (step 2 uses a hard
`is_expired()`). Expiry-driven; no CRL at the primary. This is also the backstop
that lets us drop status-endpoint pinning (§6.2): a compromised base key that
names a dishonest status endpoint is still killed by base-cert non-renewal, which
takes down all its derived certs regardless of endpoint. Matches the SBO spec's
existing **expiry-over-revocation** stance ("SBO Attestation Specification.md"
§ "expiry over revocation proofs"; browserid certs are short-lived and re-minted,
not revoked).

### 6.2 Per-agent revocation (browserid.me status authority), no pinning (decision G)

A self-derived agent cert bakes in a `status` ref (§3.3) pointing at a status
authority the base identity chose (browserid.me default). browserid.me publishes
a signed status list and a `/account` revoke control; the owner authenticates by
a **normal browserid assertion to browserid.me as an RP** and flips a specific
agent's status bit.

- **No pinning** (decision G): the verifier follows whatever endpoint the cert
  names. An honest base key names an honest endpoint; a compromised base key is
  backstopped by chain revocation (§6.1).
- **Fail-open within cache/TTL** (decision G): when the named status endpoint is
  **unreachable**, the verifier treats the cert as *not revoked* for the duration
  of the cache/TTL window (so a status-authority outage does not brick every
  agent). Revocation still propagates once the endpoint is reachable and the cache
  expires.

### 6.3 On-chain revocation for SBO (alternative anchor)

For SBO, on-chain revocation = **submit a revocation record on-chain that the
daemon reads offline** (NOT an online CRL). Prior art check: SBO **has no existing
status/revocation-object design** — the "SBO Attestation Specification.md"
explicitly uses **expiry-and-re-issuance** and defers strong revocation ("Strong
revocation MAY be layered on later; it is out of scope for this version"), and
"domain-self-certification.md" likewise defers lapse/transfer/revocation. So an
on-chain agent-revocation object would be **new design** — flagged as an open item
(OQ-onchain, §9), not something to reinvent silently. A natural shape following
the attestation model: an issuer-namespace revocation object keyed to the agent
cert, the daemon reading it as freshness state at validation time.

---

## 7. Change inventory (v2 — generalized primitive)

Design principle (decision F): the self-derivation verification lives **once** in
browserid-core as a shared function; sbo-core **calls** it (sbo-core already
depends on browserid-core, pinned `rev = "e572cda"` in
`crates/sbo-core/Cargo.toml:24`). Shared test vectors, no hand-synced copies.

### browserid-core (`/Users/thunder/src/browserid-ng/browserid-core`)

- **`certificate.rs`** — MEDIUM. Self-derived typ marker (§3.1);
  **universal `authority` claim on `CertificateClaims`** (new field, all certs)
  + accessor; extend the `parse` matcher (`certificate.rs:223-241`) to accept the
  self-derived arms and require `authority` per type; new
  `create_self_derived_{agent,id}` constructors (§3.4), enforcing the name
  constraint and setting `iss = base principal` (decision D); helper to parse
  `<base>+<label>@<domain>`.
- **`assertion.rs`** — MEDIUM/LARGE (security-critical). **NEW shared verifier
  fn** (e.g. `verify_self_derived_chain(base, derived, domain_key) -> …`) that
  runs the §2.3 checklist; call it from `verify` (`assertion.rs:295-392`, building
  on the multi-cert chain branch `assertion.rs:349-371`). Extend `check_structure`
  (`assertion.rs:250-271`) to allow a self-derived derived-leaf preceded by
  exactly one plain base cert (agent leaf still requires a warrant; regular
  derived leaf forbids one). **Harden the verifier result contract** (decision
  E.1): make agent attribution structurally prominent (`AgentResult { acts_as,
  scopes }` or non-optional agent block) rather than an easily-dropped `Option`.
- **`warrant.rs`** — SMALL/MEDIUM. Generalize the issuer-match check
  (`warrant.rs:189-195`) to `agent_cert.issuer() == parent.principal.email` on the
  self-derived path (decision D — the v1 "no change" was wrong); generalize the
  revocation-authority block (`warrant.rs:254-275`) to follow the cert's status
  endpoint with no pinning + fail-open (decision G).

### sbo-core (`/Users/thunder/src/sbo/crates/sbo-core`)

- **`attribution.rs`** — SMALL/MEDIUM (down from v1's Medium/Large, because of
  decision F). Instead of re-implementing the constrained path, **call the shared
  browserid-core verifier**. `verify_attribution_with_warrant`
  (`attribution.rs:~355-424`) and `verify_warrant_with_provider_key`
  (`attribution.rs:248-337`): when the leaf is self-derived, verify the base cert
  against the DNSSEC domain key (existing `extract_provider_key`) and delegate the
  base→derived link + name constraint to the shared fn; the warrant's `parent-cert`
  is the base cert. May require bumping the browserid-core pin
  (`Cargo.toml:24`) to a rev that exports the shared fn.
- **`sbo-daemon` effective-author** (`validate.rs::resolve_creator`,
  `authorize.rs::warrant_effective_email`) — MEDIUM (behavior change, decision B).
  Replace `as:` resolution with "effective author = the verified derived cert's
  principal." Invalidate all existing warrants by code change (no chain event, no
  re-genesis — §5). This is the most behaviorally significant SBO change.

### browserid-broker / registrar — MEDIUM

- NEW status-authority service for self-derived agent certs (register status
  subject, publish signed status list — reuse the existing warrant status-list
  publisher + `StatusRef` shape, no pinning per decision G).
- **`browserid-broker/static/account.html`** — SMALL/MEDIUM: revoke control UI
  (list owner's self-derived agents + revoke). CSP gotcha: editing broker inline
  scripts requires updating `INLINE_SCRIPT_HASHES` in `routes/mod.rs`
  (repo memory `csp-inline-script-hashes`).
- Owner auth: no new auth — a normal browserid assertion to browserid.me as an RP.

### browserid-agent SDK + mingo — MEDIUM

- **`browserid-agent/src/lib.rs`** (`AgentIdentity` provision/refresh path):
  NEW self-derive path — take the human-approved base credential, self-sign the
  derived cert with the base key (`create_self_derived_*`), register the status
  subject at browserid.me, embed the **fresh** base cert, persist. Replaces the
  `/provision/mint` POST that 404s for sandmill.org. `mingo login --idp` becomes
  unnecessary for this path.
- **`sdk/agent`** (TS SDK): mirror for JS clients (can defer).
- **mingo `mingo-app/src/login.rs`**: replace the failed-mint fail-fast (commit
  c88d23e) with the self-derive flow; CLI label hint (roadmap item 7) → `<label>`.

### Size summary

| Piece | Size | Risk | Note |
|---|---|---|---|
| browserid-core `certificate.rs` | Medium | Low | + universal `authority` field |
| browserid-core `assertion.rs` | Medium/Large | High | shared verifier fn + hardened result contract |
| browserid-core `warrant.rs` | Small/Medium | Medium | issuer-match correction + no-pin/fail-open |
| sbo-core `attribution.rs` | Small/Medium | Medium | **calls** shared fn (F), not a copy |
| sbo-daemon effective-author | Medium | Medium/High | retire `as:`, invalidate warrants (code-only) |
| broker/registrar status authority | Medium | Medium | no pinning |
| `account.html` revoke UI | Small/Medium | Low | CSP hash gotcha |
| agent SDK + mingo self-derive | Medium | Medium | |

---

## 8. Phasing (build order, decision J)

1. **agent-as-self FIRST** (case 1). Unblocks the mingo admin migration
   (`mingo-3mhi`) and exercises the whole chain — self-signing, base-cert embed,
   warrant, two-verifier path, effective-author-by-principal — end to end.
2. **subaddress-regular** (case 3, per-site login) and **subaddress-agent**
   (case 2) on the same primitive, once case 1 is proven.

---

## 9. Open questions

- **OQ-1 (status-subject registration).** How does the base identity register a
  self-derived agent cert's status subject at browserid.me *before* first use,
  without browserid.me having minted anything? Likely one online step: owner
  authenticates as an RP and pre-allocates a status index the client embeds.
  Determines whether self-derivation is fully offline or needs one registration
  round-trip.
- **OQ-3 (base-key stability — the one factual thing to confirm before
  implementing).** Is a classic primary's identity **key** stable across base-cert
  refreshes, or does it rotate per login?
  - *Stable* → derived agent certs signed by it **survive** base-cert refreshes,
    can be long-lived, and need only a fresh base cert embedded at presentation.
  - *Rotates per login* → derived agent certs are bounded by the base cert and
    must be re-issued on rotation; dan's "≥8h base validity when minting" rule
    applies. The CLI's **own** agent key is stable regardless; this question is
    only about the base identity key the derived cert is signed by.
- **OQ-onchain (SBO on-chain revocation design).** No prior SBO status/revocation
  object exists (§6.3) — SBO defers strong revocation to expiry. An on-chain
  agent-revocation record (issuer-namespace object the daemon reads as freshness
  state) is **new design** if pursued; scope it deliberately or stay expiry-only.

**Decided (were open in v1):** OQ-2 revocation pinning → **dropped** (follow the
named endpoint, fail-open in cache window; decision G). OQ-4 marker → the
**verification typ** (how to verify) is kept **distinct** from the **`authority`
field** (what it grants); both exist (decision H). OQ-5 anti-drift → **shared
verifier fn in browserid-core called by sbo-core** + shared test vectors
(decision F). The old OQ-6 ("web RPs treat `x+label@d` as distinct") is now a
*feature* (case 3, per-site login identities), not a caveat.

---

## Changelog — what changed from v1

v1 (earlier same day) specified a **+label-agent-only** self-delegation cert. v2
generalizes and corrects it per dan + team-lead alignment:

- **Generalized to one self-derivation primitive** (A): base `user@domain` may
  self-sign a derived cert with principal ∈ {self, +label} and type ∈ {agent,
  regular} — four cases, one rule, one verification path (was: +label agent
  only). Adds per-site subaddress **login** identities (case 3).
- **Retired the `as:` scope hack** (B): the acting identity is now the derived
  cert's **principal**; the daemon trusts the verified principal instead of
  resolving `as:`. Warrant invalidation is a **code change, not a chain event** —
  no transition window, no re-genesis.
- **Corrected the issuer semantics** (D): a self-issued derived cert's `iss` is
  the **base identity**, not the domain. v1 §4's "warrant.rs:189 needs no change"
  was **wrong**; the issuer-match check is generalized to `agent_cert.issuer() ==
  parent.principal.email`.
- **Kept cert and warrant separate** (C), with the rationale (uniformity,
  identity/authorization separation, well-built warrant factoring) and the hinge
  (collapse only becomes attractive if IdP-issued agents are ruled out) recorded.
- **Naive-RP mitigations** (E): hardened verifier result contract (MUST surface
  agent-ness + scopes), a **universal explicit `authority` field** on all cert
  types (open vs closed), and a SHOULD directive; plus the reaffirmed
  WarrantRequired backstop.
- **Anti-drift decided** (F): one shared verifier in browserid-core, called by
  sbo-core (pin `e572cda`) — sbo-core `attribution.rs` drops from Medium/Large to
  Small/Medium.
- **Revocation pinning dropped** (G): follow the cert's named status endpoint,
  fail-open within the cache/TTL window; on-chain revocation for SBO noted as new
  design (no prior SBO status object).
- **Markers clarified** (H): verification typ (how to verify) distinct from the
  `authority` field (what it grants).
- **OQ-3 sharpened** (I): the key factual pre-implementation check is base-key
  stability across refreshes.
- **Phasing** (J): agent-as-self first, then subaddress cases.
