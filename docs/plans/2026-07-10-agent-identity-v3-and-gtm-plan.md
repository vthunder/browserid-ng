<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Plan — Agent identity v3 (warrants, revocation, registrar) + GTM positioning

**Date:** 2026-07-10
**Status:** Agreed direction (design-level); each track has a bean.
**Supersedes / extends:** `2026-07-09-agent-delegation-chain-design.md` (v2) —
v2's chain and endorsement machinery is kept; this plan adds scoping
(warrants), real revocation, and unbundles the broker's registrar role.
**Beans:** epic `browserid-ng-gsnm` with children `5zdh` (warrants), `egr7`
(revocation), `1pnf` (registrar unbundling), `pz0f` (JIT consent flow,
blocked by 5zdh); standalone GTM beans `w7xu` (landing repositioning) and
`exj6` (verifier SDKs).

---

## 1. Positioning decision (context for everything below)

**Lead with agents, not passwordless human login.** "Better login for people"
is a crowded market (passkeys, magic links, OAuth buttons) where our
differentiators don't drive switching. Delegated **agent identity** is an
unsolved, currently-on-fire problem: in 2026 agents authenticate by borrowed
passwords, scraped sessions, and god-mode API keys. Nobody has shipped a
simple open answer to *"this action was taken by agent X, delegated by
alice@acme.com, with scope Y, revocable by Alice."* We have a spec and a
working implementation.

The pitch inverts: not "Persona reborn, now with agents" but **"the identity
layer for agents acting on behalf of people — which also gives you
passwordless human sign-in for free."** This defuses the Persona-failure
narrative (different market) and stops competing with passkeys.

Consequences:

- **RP-side value prop = attribution**: know which agent, for whom, with what
  permissions; per-agent rate limits; agent-aware abuse policy. This requires
  agent-ness to be **protocol-visible** — reversing the v2 invisibility rule
  (see §2).
- **Adoption wedge**: RPs drowning in agent traffic (attribution/compliance is
  a budget line), agent frameworks/MCP servers (one framework integration is
  worth a hundred RP integrations), our own ecosystem (mingo, sbo) as live
  proof.
- **Business model = Tailscale, not Auth0**: protocol open and free; revenue
  from opt-in hosted infrastructure (managed registrar/IdP, key custody,
  status-list hosting, and — post-adoption — enterprise agent governance).
  Solo project, no grants/sponsorship sought; near-term sustainability is
  low burn, which the current stack already achieves.
- **Deliberately deferred**: standards track (huge time sink; revisit if a
  platform-proprietary competitor emerges), enterprise governance dashboard
  (needs adoption first), escrow/trust-by-bond (bean `dj9p`, stays deferred).

### Ratified decisions (2026-07-10)

1. Agent-ness becomes protocol-visible; **invisible-agent mode is removed**
   (no compat mode). Rationale: the agent already presents a different email
   than its principal, so v2's indistinguishability provided no real privacy
   while blocking the entire attribution value prop.
2. **Parent disclosure default-on** (`agent.parent` claim). Attribution is the
   product. An opt-out (or pairwise parent) may be added later if demand
   appears; not in v3.
3. **Scoping is fixed at delegation time by the user.** No agent-side
   re-delegation or downscoping; an agent can request authority (§4) but
   never self-issue or widen it.
4. **Audience privacy is preserved** (the Persona property): neither the IdP
   nor the registrar learns where an agent acts, and no RP learns the roster
   of other RPs. Achieved structurally via per-audience warrants (§3), not
   cryptographically (hashing fails to top-sites brute force).
5. **Warrants ride inside the tilde chain** (`agent_cert~warrant~assertion`)
   and **agent certs get their own `typ`** — fail-closed at every verifier by
   construction, not by RP diligence (§3.3).
6. **Revocation is layered**: short TTL floor + delegation-root revocation +
   an IETF-format signed status list (§5).
7. **The endorser role is a *registrar*, defaulting to the IdP itself.**
   browserid.me's mandatory position in federated agent flows is removed; a
   hosted registrar becomes the opt-in managed product (§6).

---

## 2. The agent claims block (distinguishability + attribution)

The IdP-minted agent certificate carries a spec'd block:

```json
"agent": {
  "parent": "a@b.c",          // the delegator (default-on)
  "name": "researcher"         // the agent handle
}
```

- Presence of the block is the distinguishability signal; it is issuer-signed
  so RPs trust it with no callback.
- **No audiences and no scopes in the cert** — those live in warrants (§3),
  keeping the IdP blind to where the agent acts.
- `purpose` strings: dropped from the cert for v3 (belongs in the warrant if
  anywhere; revisit with real RP demand).

Spec home: core §4 (certificate) gains the block; the agent module references
it. Supersedes the v2 line "agent-ness is issuer-side metadata, never a
protocol-visible type" (spec §1).

## 3. Warrants — user-signed, per-audience authorization

### 3.1 Model

At authorization time the **user's certified identity key** signs one small
**warrant per audience**:

```json
{
  "typ": "browserid-agent-warrant-v1",
  "agent": "researcher",                  // or P_pub binding; decide in spec
  "aud": "https://api.mingo.place",       // exact origin, no wildcards in v3
  "scopes": ["post", "read"],             // opaque strings, RP vocabulary
  "iat": ..., "exp": ...
}
```

Verified against the same chain machinery as `P_cert` (`U_cert~warrant`,
signing-time semantics per agent-spec §3: warrant `iat` within `U_cert`
validity).

Privacy properties (structural, no new crypto):

- RP X sees only its own warrant — the "list of sites" never exists as a
  single artifact anywhere.
- The IdP and registrar never see warrants; they don't transit either party.
- Scopes ride inside each warrant → no cross-audience leakage.
- `aud` pins each warrant to one RP; X cannot replay at Y.

Trust story: the RP verifies *the user's own key* authorized this agent, at
this RP, with these scopes — user-signed authorization end to end (v2's core
principle), not an IdP paraphrase.

### 3.2 Where each constraint is enforced

| Layer | Constraint | Enforcer | Why it works |
|---|---|---|---|
| Warrant `aud` | which RPs | any verifier | no vocabulary needed: "am I the audience?" |
| Warrant `scopes` | what actions | RP, at grant exchange (§5.3 token endpoint intersects with its own vocabulary) | scopes are RP-local; OAuth-shaped layer is where devs expect them |
| Cert TTL + status (§5) | liveness | any verifier | offline-friendly |
| SDK fail-closed defaults | all of the above | `browserid-rp` + ports | most RPs run the SDK, not the spec |

Explicitly rejected for v3: caveat-based attenuation tokens
(Biscuits/macaroons). Elegant, but a research project; audience+scopes covers
near-term demand and the design doesn't foreclose adding attenuation later.

### 3.3 Fail-closed hardening (cert/warrant separation risk)

Threat considered: agent cert+key leak used *without* warrants at a naive RP
that only checks "valid email cert." Two structural fixes:

1. **Distinct cert `typ`** (`browserid-agent-cert-v1`). Core verification
   (§6.2) rejects certs with unrecognized `typ`. A verifier that predates
   agents *cannot* accept an agent cert — rejection by construction. Zero
   cost given invisible mode is dead.
2. **Warrant in the chain**: the agent's presented credential is
   `agent_cert~warrant~assertion`. One artifact on the wire; a legacy
   verifier fails to parse; an agent-aware verifier cannot skip the warrant
   because it is load-bearing in the format. "Forgot to check the warrant"
   stops being expressible.

Resulting blast radius: cert+key alone → useless everywhere. Cert+key+warrants
→ exactly the agent's own authorized authority, revocable via §5. Separation
never widens what the user authorized.

## 4. JIT consent flow (audience UX)

Nobody types an audience string, ever. The RP names its own audience —
authoritatively — in the §5.2 `WWW-Authenticate` challenge; the flow inverts
from "configure" to "request":

1. Agent contacts RP → challenge with `audience=` (+ small spec addition:
   requested scopes).
2. Agent can't sign a warrant; it raises a **consent request** to the user's
   registrar — device-authorization-grant shape (RFC 8628): link/notification
   to the user.
3. Consent page (served by the registrar, where the identity key already
   lives per agent-spec §4.6 typed-signing) shows *"**researcher** wants to
   act for you at **mingo.place** with **post, read**"* — audience and scopes
   prefilled from the challenge. User approves → key signs warrant → agent
   picks it up (poll/callback) and proceeds.

Notes:

- Warrants become **just-in-time**: no upfront audience enumeration, no
  speculative over-granting. Still user-signed at the moment of
  authorization; agent can request but never self-issue (decision 3).
- Policy knobs on the consent screen: deny, "always ask," per-agent standing
  preferences.
- Imported risk = OAuth's consent fatigue / look-alike prompts. The consent
  surface must show the verified origin prominently and keep approval
  deliberate.
- RPs publishing §5.4 metadata get richer consent screens (display name) as
  polish.
- MVP fallback: manual audience entry in the registrar UI (nearly free);
  the request flow is the real v1 UX.
- `aud` is **exact origin only** in v3; wildcard patterns reopen a
  disclosure/scope-creep surface — revisit only with concrete demand.

## 5. Revocation stack (bean `egr7`)

Layered; each layer independent, honest failure modes:

1. **Short TTL floor** (24 h / 1 h ephemeral — unchanged). Everything else
   can fail without certs living forever. Do **not** crank TTLs to minutes to
   fake fast revocation — every re-mint is a registrar round trip, and short
   TTLs convert the registrar into an HA-critical path (worsens §6).
2. **Delegation-root revocation** (already shipped, under-claimed): revoking
   the `P_cert` at the registrar starves endorsements → no re-mint. The
   "kill this agent" primitive; weakness = outstanding-cert window.
3. **Signed status list** for the fast path: certs carry
   `status: {uri, index}`; the IdP publishes a compact signed bitmap; RPs
   fetch + cache ~5 min. **Adopt the IETF OAuth Token Status List format**
   (don't invent one — credibility + future RP-side libraries). Privacy: RP
   fetches the whole list, learns nothing about which subject it checks.
   Online dependency is soft: list unreachable → TTL semantics; fail-open vs
   fail-closed is RP policy (SDK default: fail-open with a short grace, then
   closed — confirm during spec work).
4. **User-key compromise**: user certs get status entries too; epoch
   bump/rotation remains the nuclear option.
5. **Offline/on-chain consumers** (sbo): a detached status-list snapshot with
   a freshness window composes with §6.3 detached DNSSEC proofs ("valid as
   of T").

Warrants need no separate revocation machinery: they are only meaningful
alongside a live agent cert, so killing the agent kills every warrant.

Resulting story: revocation is instant for new sign-ins at status-checking
RPs; ≤ cache window for sessions at status-checking RPs; ≤ TTL for naive RPs.

## 6. Registrar unbundling (new bean)

v2 conflated three roles under "broker"; unbundle them:

| Role | What it is | v3 change |
|---|---|---|
| **Fallback IdP** | certs for emails whose domain lacks native support | unchanged |
| **Mediator / UX** | login dialog, remembered identities, include.js relay | unchanged (agents are headless; never used it) |
| **Registrar** (was "endorser") | `P_cert` registry, key-management UI, revocation switch, endorsement signing | **defaults to the IdP that roots the delegator's identity** |

Rationale: under the identity-domain rule an agent always mints at its
delegator's own IdP, which issued the `U_cert`, knows its own users, and can
run its own quota — there is no cross-IdP sybil surface requiring a global
view. Mandatory browserid.me endorsement for federated IdPs adds nothing
those IdPs can't do, while granting browserid.me visibility into and a veto
over other domains' agent activity, plus an availability coupling (broker
down → every federated agent dead within one TTL). That's the "Persona
centralization" critique handed to critics.

Changes:

- Spec: rename endorsement issuer broker→**registrar**; IdP config
  "accepted brokers" → "accepted registrars," **default = self**. Endorser
  and issuer collapse exactly like the broker-rooted path already does; wire
  formats unchanged.
- Broker-rooted users (`alice@gmail.com`): registrar *is* browserid.me —
  nothing changes for the long tail.
- Natively-rooted users (`alice@mingo.place`): mingo-idp is the registrar;
  browserid.me is not in the path at all.
- **Managed registrar = the product**: an IdP MAY configure an external
  registrar (browserid.me) to outsource registry, abuse policy, key-mgmt UI,
  and consent surface. Opt-in hosted control plane, not mandatory dependency.
- Implementation cost (honest): v2 deleted mingo-idp's key management
  ("key mgmt is broker-only"); registrar-default-self means federated IdPs
  regain registry + endorsement signer + UI. Ship it as a **reusable
  component** in the reference stack — that component *is* the self-host
  story. Relates to bean `btmg` (key-mgmt UI) — that UI becomes part of the
  registrar component, not broker-only.
- Coherent user story: **you manage your agents where your identity lives.**

## 7. GTM track

1. **Landing page repositioning** (new bean): agents take the headline;
   human sign-in demoted to a supporting feature. Keep claims honest — the
   hero card currently shows `post · read` scope badges and "revocable,"
   which only become true when §3/§5 land; until then mark aspirational
   claims or gate the copy on shipping. Marketing language leads with the
   capability ("delegated agent identity"), not the protocol name
   ("BrowserID" is an awkward flag for headless identity; no protocol rename
   now).
2. **Verifier availability** (new bean): tiny verifier libs beyond Rust
   (JS/Python/Go priority order by RP demand) + hosted `/verify`, so "add
   agent auth" is five minutes in any stack. Rust-only is a silent adoption
   ceiling. Fail-closed agent handling (§3.3) baked into every port from day
   one.
3. **Wedge sequencing**: dogfood (mingo/sbo) → agent frameworks / MCP-server
   integration → RPs with agent-traffic pain. Revenue lines activate only
   after adoption: managed registrar/IdP hosting → key custody (`e2fi`) →
   status-list/verification services → enterprise governance.

## 8. Sequencing & dependencies

Phase 1 — **Spec v0.4** (all text, no code): agent claims block + cert `typ`
(§2, §3.3) → warrant format + chain framing (§3) → consent-request flow +
challenge scope param (§4) → registrar rename/defaults (§6) → status claim +
list format (§5). One coherent rev of `agent-provisioning-and-grant-api.md`
plus a core-spec touch (§4 cert, §6.2 verification).

Phase 2 — **Implementation**: `browserid-core` (warrant type, chain parsing,
`typ` enforcement) → broker/registrar component (registry, endorsement,
consent UI, status list) → `browserid-agent` (challenge → consent request →
warrant storage) → `browserid-rp` (fail-closed verification, scope
intersection at token endpoint) → mingo-idp registrar adoption.

Phase 3 — **GTM**: landing repositioning (can start immediately for the
agents-first framing; scoped/revocable claims flip on as Phase 2 ships) →
verifier SDK ports → framework/MCP integration outreach.

Dependency notes: consent flow (§4) depends on warrants (§3). Status list
(§5) and registrar unbundling (§6) are independent of both and of each
other. Landing repositioning is independent; its *claims* gate on Phase 2.

## 9. Open questions (deliberately unresolved)

- Warrant `agent` binding: by name or by `P_pub`? (Name survives agent-key
  rotation; key is tighter. Decide in spec drafting.)
- Warrant TTL + renewal UX (silent renewal at consent-time policy vs
  re-prompt).
- Status-list SDK default: fail-open grace window length vs hard fail-closed.
- Scope-string conventions worth *recommending* (not normatively defining)
  so consent screens render well.
- Pairwise/undisclosed parent as a later privacy option (explicitly out of
  v3).
