# BrowserID Agent Provisioning, Warrants & Grant Exchange — API Specification

**Version:** 0.4 (draft)
**Date:** 2026-07-10
**Status:** Design-complete; §5 (agent certificates & warrants), §6 (consent
flow), the registrar-defaults-to-self rule (§3), and the `status` claim are
**new in v0.4 and not yet implemented** in the reference stack — see plan
`docs/plans/2026-07-10-agent-identity-v3-and-gtm-plan.md` and epic
`browserid-ng-gsnm`. The v0.3 provisioning surface (§4) is implemented and
deployed. v0.2 replaced v0.1's bearer API keys with a user-signed
**delegation chain** plus per-request endorsement (design:
`docs/plans/2026-07-09-agent-delegation-chain-design.md`).

### Changes in v0.4

1. **Agent identities are protocol-visible.** Agent certificates carry their
   own `typ` and an `agent` claims block (§5.1). v0.3's rule that "an RP
   cannot tell an agent-held identity from any other" is **reversed**:
   attribution is the point. There is no invisible-agent compatibility mode.
2. **Warrants** (§5.2) — per-audience, user-signed authorization objects
   carrying opaque scopes. Audience and scope restrictions live *only* in
   warrants, never in certificates, preserving the BrowserID privacy
   property: the IdP and registrar never learn where an agent acts, and no
   RP learns the roster of other RPs.
3. **Warrant-in-chain presentation** (§5.3) — an agent's backed assertion is
   `agent_cert~warrant~assertion`. Combined with the distinct cert `typ`,
   verification is fail-closed by construction: a verifier that predates
   agents cannot accept an agent credential, and an agent-aware verifier
   cannot skip the warrant.
4. **Consent flow** (§6) — warrants are requested (RFC 8628 shape), not
   configured: the RP's `WWW-Authenticate` challenge names the audience and
   requested scopes; the user approves at their registrar. Nobody types an
   audience string.
5. **Registrar** (§2, §3) — the endorser role is renamed from "broker" to
   **registrar** and **defaults to the delegator's own IdP**. browserid.me is
   the registrar for identities it roots and MAY be configured as an
   external registrar by other IdPs; it is no longer a mandatory party in
   federated agent flows.
6. Certificates MAY carry a **`status`** claim for fast revocation via a
   signed status list (core spec §6.4).

## 1. Purpose and scope

This document specifies the HTTP surfaces that make BrowserID usable by
software agents without a browser:

1. **Provisioning protocol** (§4) — how an agent holding a **provisioning
   credential** (a private key whose public half was delegated by a user's
   certified identity key) obtains and renews a certified identity from an
   IdP, with a registrar co-signing each request per policy.
2. **Agent certificates & warrants** (§5) — what an agent's certificate
   asserts, and how a user-signed warrant authorizes the agent at a specific
   relying party with specific scopes.
3. **Consent flow** (§6) — how an agent obtains a warrant for a new RP
   just-in-time, with the user approving at their registrar.
4. **Grant exchange** (§7) — how an agent authenticates to an API relying
   party by swapping a warrant-backed assertion for the RP's own bearer
   token, including in-band (`WWW-Authenticate`) and out-of-band (RFC 8414)
   discovery.

Downstream of provisioning, the agent's certificate chain verifies exactly
like any BrowserID chain (core §6.2), with two additions an agent-aware
verifier enforces: the agent cert `typ` and the warrant segment (§5.3).
**Agent-ness is protocol-visible and attributable**: every agent credential
names its delegator, and every use is confined to audiences the delegator
authorized.

Out of scope: browser session establishment at RPs, and escrow/stake trust
models. The registrar's key-management UI is described non-normatively
(§4.6).

## 2. Terminology

- **IdP** — a BrowserID identity provider implementing §4. It is
  authoritative for identities under its own domain.
- **Registrar** — the service that registers provisioning certificates,
  applies account-level policy (sybil/quota/rate), endorses provisioning
  requests, hosts the key-management UI, and hosts the consent surface
  (§6). **Every IdP is its own registrar by default.** An IdP MAY instead
  configure an external registrar it trusts. *(v0.3 called this role the
  "broker"; a broker — a fallback IdP such as browserid.me — is simply the
  registrar for the identities it roots, and may additionally serve as an
  external registrar for other IdPs.)*
- **Agent** — a headless client holding the provisioning private key and its
  own (separate) identity keypair.
- **Delegator / parent identity** — the user identity (`a@b.c`) whose
  certified key signed the delegation. Every agent identity MUST chain to
  one. An agent identity MUST NOT serve as a delegator.
- **U_cert** — the delegator's ordinary identity certificate (IdP-signed,
  binds `U_pub` to `a@b.c`).
- **P_cert** — the provisioning certificate: signed by `U_priv`, binds the
  provisioning public key `P_pub` to the delegation.
- **Delegation bundle** — `U_cert~P_cert` (the `~` framing of backed
  assertions).
- **Request bundle** — `U_cert~P_cert~R` where `R` is a provisioning
  request signed by `P_priv`.
- **Endorsement (E)** — the registrar's short-lived signature over a
  specific request bundle.
- **Agent identity** — `<name>@<idp-domain>`, certified by the IdP for the
  agent's own key `A_pub`. The agent's handle is the local part of its
  identity.
- **Warrant (W)** — a user-signed authorization binding one agent identity
  to one RP audience, optionally with scopes (§5.2).

Key words MUST/SHOULD/MAY are RFC 2119.

## 3. Trust model (normative summary)

- **Authorization is user-signed.** An IdP MUST NOT mint an agent identity
  without a valid chain terminating in a `P_cert` signed by the delegator's
  certified key. A registrar endorsement alone authorizes nothing.
  Likewise, an RP MUST NOT accept an agent presentation without a valid
  **warrant** signed by the delegator's certified key (§5.3). Neither the
  IdP nor the registrar can fabricate either.
- **Policy is registrar-signed.** An IdP MUST also require a fresh
  endorsement from a registrar it accepts. **The accepted-registrars set
  defaults to the IdP itself** — an IdP that runs its own registry needs no
  external party. An IdP MAY accept an external registrar (e.g.
  browserid.me) to outsource registry, policy, key-management UI, and the
  consent surface.
- **Identity-domain rule.** The agent's identity domain is the domain of the
  IdP that roots the delegator's identity. Consequently the `U_cert` an IdP
  verifies is always its own issuance; the delegator and the agent share one
  IdP and one DNSSEC trust root; and for delegators rooted at a
  broker/fallback IdP, registrar and issuer are the same party (one code
  path, two roles).
- **Signing-time semantics.** `U_cert` is short-lived; `P_cert` and warrants
  are long-lived. Verifiers MUST require `P_cert.iat` (respectively
  `W.iat`) to fall within the corresponding `U_cert`'s validity window and
  MUST NOT require that `U_cert` to be currently unexpired. An IdP MAY
  additionally consult its own issuance records for `U_pub`.
- **Audience confinement is user-signed and RP-enforced.** Certificates
  carry no audiences and no scopes. A warrant confines the agent to one
  audience; scopes within it are opaque to the registrar and are
  interpreted only by the RP (§7.3). An RP sees only warrants addressed to
  it — no artifact an RP receives ever carries the delegator's roster of
  other audiences. The **registrar** (which hosts the consent surface and
  key custody, and already mediates the identities it roots) MAY retain
  warrant records — agent, audience, scopes, expiry, the signed JWS — for
  the delegator's own account view and future revocation tooling; a
  self-hosted registrar holds only its own users' records.
- **Revocation is layered** (see core §6.4 and bean `browserid-ng-egr7`):
  agent certificates MUST be short-lived (reference: 24 h, 1 h ephemeral);
  every mint — including routine re-mints — requires a fresh endorsement,
  so revoking a provisioning certificate at the registrar takes effect
  within one certificate TTL; certificates MAY carry a `status` claim for
  sub-TTL revocation via a signed status list; IdPs MAY additionally revoke
  identities locally (§4.5). Warrants need no separate revocation channel:
  a warrant is only meaningful alongside a live agent certificate.
- **Scope of the provisioning credential.** A request bundle MUST only
  enable operations on *agent* identities delegated by its own chain. It
  MUST NOT permit reading account data, altering credentials, or acting on
  the delegator's (or anyone's) human identities. `P_priv` never transits
  the wire; only signatures do.
- **Quota is layered.** The registrar enforces account-level policy at
  endorsement time; IdPs SHOULD additionally enforce a per-delegator quota
  of active agent identities (reference default: 5).

## 4. Provisioning protocol

### 4.1 Claim formats

All of `P_cert`, `R`, `E` (and the warrant, §5.2) are Ed25519 JWS with an
explicit `typ` claim for domain separation. Verifiers MUST reject a token
whose `typ` does not match the expected value. None of these shapes is
parseable as an identity certificate (no `principal`) or an assertion (no
`aud` on `P_cert`/`R`).

**Provisioning certificate (`P_cert`)** — signed by the delegator's identity
key:

```json
{
  "typ": "browserid-provisioning-cert-v1",
  "iss": "a@b.c",
  "iat": 1783600000,
  "exp": 1791376000,
  "public-key": { "algorithm": "Ed25519", "publicKey": "<P_pub base64url>" },
  "constraint": {
    "names": ["attestor2", "worker"],
    "patterns": ["dan+*"]
  }
}
```

`iss` MUST equal the `principal.email` of the accompanying `U_cert`.
Reference validity: 90 days.

**Constraint (REQUIRED).** A `P_cert` MUST carry a `constraint` that
authorizes at least one identity — an unconstrained key (empty constraint)
MUST be rejected. It has two optional arrays, at least one non-empty:

- `names`: exact agent handles the key may mint. These SHOULD be **reserved**
  at key-creation (§4.2a) so the mint can't later be refused.
- `patterns`: `<prefix>+*` subaddress grants — the key may mint any
  `<prefix>+<non-empty-suffix>`. `<prefix>` MUST be a valid handle; a naked
  `*` (or any pattern without the `+*` suffix) MUST be rejected. Patterns are
  not reserved (unbounded); the per-delegator quota still bounds the count.
  A pattern SHOULD be under a handle the delegator controls (e.g. their own
  handle or one of `names`), keeping every minted identity attributable.

An IdP and the registrar MUST enforce that a mint's `name` is authorized by
the constraint (exact `names` match, or a `patterns` match). Agent names may
contain `+` (for subaddressing); human handles may not.

**Provisioning request (`R`)** — signed by `P_priv`:

```json
{
  "typ": "browserid-provisioning-request-v1",
  "iat": 1783600000,
  "exp": 1783600600,
  "action": "mint",
  "domain": "mingo.place",
  "name": "attestor2",
  "agent-key": { "algorithm": "Ed25519", "publicKey": "<A_pub base64url>" },
  "ephemeral": false
}
```

- `action` ∈ `mint` | `list` | `revoke` | `reserve` | `warrant` (§6). `name`
  is required for `mint`/`revoke`; `agent-key` (and optional `ephemeral`)
  for `mint`; `warrant` carries `name` plus `warrant-grants` (§6.2).
  `reserve` carries neither `name` nor `agent-key` — it acts on the
  `P_cert`'s `constraint.names`.
- `domain` MUST equal the target IdP's domain (audience pinning).
- Requests MUST be short-lived (≤ 10 min recommended).

**Endorsement (`E`)** — signed by the registrar's published key:

```json
{
  "typ": "browserid-provisioning-endorsement-v1",
  "iss": "mingo.place",
  "aud": "mingo.place",
  "sub": "sha256:<hex of the exact request-bundle string>",
  "delegator": "a@b.c",
  "iat": 1783600000,
  "exp": 1783600600
}
```

`iss` is the registrar's domain — equal to `aud` when the IdP is its own
registrar (the default), or the external registrar's domain otherwise.
`sub` binds the endorsement to one specific request bundle. `delegator` is
the identity the registrar verified from the chain. Endorsements MUST be
short-lived (≤ 10 min recommended).

### 4.2 Registrar: `POST /provision/endorse`

Request: `{ "request_bundle": "<U_cert~P_cert~R>" }`. No other
authentication — the bundle is the credential.

The registrar MUST: verify the request signature (`R` under `P_cert`'s key)
and that the request is unexpired; require the `P_cert` to be **registered
and unrevoked** in its registry (§4.6) — the registry established the
`U_cert`→`P_cert` delegation at registration time, so the registrar need not
re-verify `U_cert` here; apply account-level policy; then return
`200 { "success": true, "endorsement": "<E JWS>" }` with `aud` = `R.domain`.
(The user-signed authorization is still verified end to end — the target IdP
verifies the whole chain at mint, §4.3 — so a registrar endorsement never
substitutes for it.)

Errors (shape `{"success": false, "reason": "…"}`):

| Status | Meaning |
|---|---|
| 400 | Malformed bundle / bad chain / expired request |
| 403 | Chain valid but not registered, revoked, or refused by policy (incl. a mint whose `name` the constraint doesn't authorize) |
| 429 | Endorsement rate limit |

### 4.2a IdP: `POST /provision/reserve`

Request: `{ "request_bundle": "<… action=reserve>", "endorsement": "<E>" }`.
Reserves **all** of the `P_cert`'s `constraint.names` for the delegator's
account, all-or-nothing: if any name is already taken by another account (or
is a human handle), the whole request MUST fail (`409`) and reserve nothing.
Reservation pre-allocates the identity (no certificate yet) and consumes
quota, so a later `mint` of a reserved name cannot be refused. Idempotent for
names already reserved by the same delegator.

Performed once at key-creation, in the browser, using the just-generated
provisioning key (the same key the agent later mints with). Returns
`{ "success": true }`.

### 4.3 IdP: `POST /provision/mint`

Request:

```json
{ "request_bundle": "<U_cert~P_cert~R with action=mint>",
  "endorsement": "<E JWS>" }
```

The IdP MUST verify, in addition to §3's chain rules: `R.domain` and
`E.aud` equal its own domain; `E` is signed by an accepted registrar (self
by default), fresh, and `E.sub` matches the hash of the exact
`request_bundle` string; the `U_cert` is its own issuance for the delegator.

Semantics: names share one `<local>@<domain>` namespace with human
identities and MUST be validated (including any reserved-name policy);
minting is **idempotent** for an existing active identity of the same
delegator (returns a fresh certificate for the presented `agent-key`, which
MAY rotate freely); revoked names are never recycled; new identities count
against the delegator's quota.

The minted certificate is an **agent certificate** per §5.1 (distinct
`typ`, `agent` block naming the delegator).

Response: `{ "success": true, "email": "attestor2@mingo.place",
"cert": "<JWS>" }`.

| Status | Meaning |
|---|---|
| 400 | Malformed / bad chain / bad `typ` / expired |
| 401 | Chain verifies but endorsement missing, stale, wrong `aud`, hash mismatch, or from an unaccepted registrar |
| 403 | Identity exists but is revoked |
| 404 | Provisioning disabled (indistinguishable from unknown routes) |
| 409 | Name taken by another delegator or a human identity |
| 429 | Per-delegator quota exceeded |

### 4.4 IdP: `POST /provision/list`

`{ "request_bundle": "<… action=list>", "endorsement": "<E>" }` → the
delegator's agent identities:

```json
{ "success": true, "identities": [
  { "email": "attestor2@mingo.place", "parent_email": "a@b.c",
    "active": true, "created_at": "2026-07-09T…Z" } ] }
```

Visibility rule: a request chain only ever sees identities delegated by its
own delegator; everything else — including human identities — is
indistinguishable from nonexistent (404 on §4.5, absent here).

### 4.5 IdP: `POST /provision/revoke`

`{ "request_bundle": "<… action=revoke, name=…>", "endorsement": "<E>" }` →
`{ "success": true }`. Disables the identity: further mints fail (403), the
name is never recycled, outstanding certificates age out within their TTL
(or die sooner where the `status` claim is deployed — core §6.4).

### 4.6 Registrar registry & key management (non-normative)

How a user creates and manages provisioning certificates is
registrar-local. The reference registrar: a signed-in user picks an
identity; the page generates the P keypair locally, signs `P_cert` with the
identity key held in registrar-origin storage (a typed-signing operation),
registers `{delegation bundle, label}` with the account (session + CSRF),
and receives the **agent credential** exactly once:

```json
{ "secret_key": "<P_priv base64url>",
  "delegation": "<U_cert~P_cert>",
  "registrar": "https://mingo.place",
  "idp": "https://mingo.place" }
```

`P_priv` is never sent to any server. The registry stores only public data;
listing shows label, delegator, creation and last-endorsed times; revocation
flips one row and starves future endorsements. Interoperability requires
only that the resulting delegation verifies per §4.1 and that the registrar
endorses per §4.2.

The registry, endorsement signer, key-management UI, and consent surface
(§6) together form the **registrar component**, intended to ship as a
reusable piece of the reference stack so any IdP can self-host it (bean
`browserid-ng-1pnf`).

## 5. Agent certificates, warrants & presentation *(new in v0.4)*

### 5.1 Agent certificate

The certificate minted in §4.3 is a core-format user certificate (core
§4.1) with two differences:

```json
{
  "typ": "browserid-agent-cert-v1",
  "iss": "mingo.place",
  "iat": 1783600000,
  "exp": 1783686400,
  "public-key": { "algorithm": "Ed25519", "publicKey": "<A_pub base64url>" },
  "principal": { "email": "attestor2@mingo.place" },
  "agent": { "parent": "a@b.c" },
  "status": { "uri": "https://mingo.place/.well-known/browserid-status", "idx": 42 }
}
```

- **`typ` (REQUIRED)**: `browserid-agent-cert-v1`. Per core §6.2, a
  verifier MUST reject any certificate bearing a `typ` it does not
  recognize — so a verifier that predates this module structurally cannot
  accept an agent certificate. There is no untyped ("invisible") agent
  certificate.
- **`agent` block (REQUIRED)**: `parent` is the delegator's identity, set
  by the IdP from the verified chain. This is the attribution claim:
  issuer-signed, verifiable with no callback. *(The agent's handle is the
  local part of `principal.email`; it is not duplicated in the block.)*
- **`status` (OPTIONAL)**: fast-revocation hook, core §6.4.
- Ordinary human certificates are unchanged and carry no `typ` and no
  `agent` block.

### 5.2 Warrant

A warrant is signed by the **delegator's identity key** (`U_priv`) — the
same key that signs `P_cert`s — and authorizes one agent identity at one
audience:

```json
{
  "typ": "browserid-agent-warrant-v1",
  "iss": "a@b.c",
  "agent": "attestor2@mingo.place",
  "aud": "https://api.mingo.place",
  "scopes": ["post", "read"],
  "parent-cert": "<U_cert JWS>",
  "iat": 1783600000,
  "exp": 1791376000
}
```

- `iss` — the delegator. MUST equal `parent-cert.principal.email` and the
  presented agent certificate's `agent.parent`.
- `agent` — the agent's full identity email. MUST equal the presented agent
  certificate's `principal.email`. *(Binding is by identity, not by
  `P_pub`: the provisioning key never appears in an RP-facing presentation,
  and identity binding survives free agent-key rotation under §4.3's
  idempotent mint.)*
- `aud` — **exactly one** RP audience: an opaque, exact-match identifier,
  same normalization as assertion `aud` (core §5). For web RPs this is the
  https origin; non-web consumers MAY use scheme-specific URIs (e.g.
  `sbo://<ledger>`) — verifiers compare the exact string and never
  interpret it. Wildcards/patterns MUST be rejected.
- `scopes` — OPTIONAL array of opaque strings. Meaningful only to the RP
  (§7.3); the IdP and registrar never interpret (or see) them.
- `parent-cert` — the delegator's `U_cert`, embedded so the presentation is
  self-contained. Signing-time semantics apply (§3): `W.iat` MUST fall
  within `parent-cert`'s validity window; `parent-cert` need not be
  currently unexpired; the warrant itself MUST be unexpired.
- Reference validity: 90 days (matching `P_cert`).

Privacy properties (by construction): one warrant names one audience, so no
artifact anywhere carries a delegator's full audience list; warrants never
transit the IdP or registrar as data (§6 issues them client-side at the
registrar origin); an RP sees only warrants addressed to it; `aud` pinning
makes a warrant useless anywhere else.

Warrants are not independently revocable: they are inert without a live
agent certificate, so revoking the agent (§4.5, or the `status` claim)
retires every warrant with it. A user who wants to withdraw a single
audience grant before its `exp` revokes and re-creates the agent (or waits
out the warrant); finer-grained warrant revocation is deliberately deferred.

### 5.3 Presentation: the warrant-backed assertion

An agent authenticates to an RP with a backed assertion whose chain embeds
the warrant between the leaf certificate and the assertion:

```
<agent_cert>~<warrant>~<assertion>
```

(With the optional host-cert intermediate of core §4.2:
`<host_cert>~<agent_cert>~<warrant>~<assertion>`.)

Verification (extends core §6.2; MUST run in this order):

1. Parse the chain. If any certificate carries `typ:
   browserid-agent-cert-v1`, agent rules apply: that certificate MUST be
   the leaf, the next segment MUST be a warrant
   (`typ: browserid-agent-warrant-v1`), and the final segment the
   assertion. Any other arrangement — agent cert without warrant, warrant
   without agent cert, unrecognized segment — MUST be rejected.
2. Verify the certificate chain to the DNSSEC root per core §6.2.
3. Verify the warrant: signature under `parent-cert`'s `public-key`;
   `parent-cert` itself verifies as a certificate chain to the **same**
   IdP root (identity-domain rule: delegator and agent share one domain and
   one `K_dns`); `W.iat` within `parent-cert` validity; `W` unexpired;
   `W.iss` == `parent-cert.principal.email` == `agent_cert.agent.parent`;
   `W.agent` == `agent_cert.principal.email`; **`W.aud` == the verifying
   RP's own audience** (the same value checked against the assertion's
   `aud`).
4. Verify the assertion under the agent certificate's subject key (`aud`,
   `exp`) as in core §6.2.
5. Result: the agent's email, plus attribution metadata the RP SHOULD
   surface to the application: `{ agent: true, parent, scopes }`.

A leaked agent certificate + key without warrants is unusable at every
conforming verifier (step 1 fails), and unusable at pre-agent verifiers
(the `typ` fails core §6.2). With warrants, it is usable exactly where and
how the delegator authorized — the delegation's defined blast radius —
until revoked.

## 6. Consent flow — just-in-time warrants *(new in v0.4)*

Warrants are **requested, not configured**: the RP names its own audience
authoritatively (§7.2), and the user approves at their registrar. The flow
follows the shape of the OAuth device authorization grant (RFC 8628).

### 6.1 Trigger

The agent contacts the RP and receives the §7.2 challenge naming
`audience` and (optionally) `scopes`. Lacking a warrant for that audience,
the agent raises a consent request.

### 6.2 Registrar: `POST /warrant/request`

Request: `{ "request_bundle": "<U_cert~P_cert~R>" }` where `R` has:

```json
{
  "typ": "browserid-provisioning-request-v1",
  "iat": …, "exp": …,
  "action": "warrant",
  "domain": "<registrar domain>",
  "name": "attestor2",
  "warrant-grants": [
    { "aud": "https://api.mingo.place", "scopes": ["post", "read"] },
    { "aud": "sbo://mingo.place",       "scopes": ["claim"] }
  ]
}
```

`warrant-grants` carries **1–8 grants**, one per audience (duplicates MUST be
rejected), each with its own scopes — an agent that needs several audiences
(e.g. a web service *and* a ledger) asks once and the principal approves
once. Each grant still yields its own **single-audience** warrant (§5.2);
batching exists only at the request/consent layer, so the privacy analysis
is unchanged.

The registrar verifies the bundle exactly as in §4.2 (registered, unrevoked,
policy), checks `name` against the constraint, then creates a **pending
consent request** and returns:

```json
{ "success": true, "code": "<high-entropy opaque>",
  "verification_uri": "https://mingo.place/consent/<code>",
  "expires_in": 900, "interval": 5 }
```

The registrar SHOULD notify the delegator (the notification channel is
registrar-local); the agent SHOULD also surface `verification_uri` to its
principal directly when it has a channel to them.

### 6.3 Consent page

Served by the registrar at `verification_uri`, to the signed-in delegator
only. It MUST display: the agent's handle and label, and — for **every**
grant in the request, each with equal prominence (no folding N grants
behind a summary line) — the **verified audience** and its requested
scopes, prefilled from the request, never user-typed. Where an RP publishes
§7.4 metadata, the page MAY enrich the display (name/logo) but MUST still
show the audience itself.

On approval, the page signs one §5.2 warrant **per grant** with the
identity key held in registrar-origin storage (the same typed-signing
operation as `P_cert` creation, §4.6) and attaches them to the pending
request; approval is all-or-nothing over the displayed set. Policy knobs
(deny, "always ask", standing per-agent preferences) are registrar-local
and non-normative. The approve action MUST be deliberate (no
default-focused approve button); consent-fatigue resistance is a design
requirement of the surface.

### 6.4 Registrar: `POST /warrant/poll`

Request: `{ "code": "<code>" }`. Responses:

| Status | Body | Meaning |
|---|---|---|
| 200 | `{ "status": "approved", "warrants": ["<W JWS>", …], "warrant": "<W JWS>\|null" }` | Done — one warrant per grant, in grant order (`warrant` is populated iff exactly one); the pending request is deleted on delivery |
| 200 | `{ "status": "pending" }` | Poll again after `interval` seconds |
| 200 | `{ "status": "denied" }` | The user declined |
| 410 | `{ "status": "expired" }` | Request expired unapproved |
| 429 | — | Polling faster than `interval` |

`code` is a short-lived, single-delivery bearer; its entropy MUST be ≥ 128
bits. On delivery the registrar MUST delete the **pending request** (the
code becomes indistinguishable from expired). The issued warrants
themselves SHOULD be retained in the registrar's **warrant registry** (§3):
per-delegator records of agent, audience, scopes, expiry, and the signed
JWS, shown only to the delegator's own authenticated session — this is what
makes an account's grants reviewable across browsers, and it is the
substrate for per-warrant revocation once certificate status lists (core
§6.4) land. Warrants signed outside the consent flow (a registrar's manual
signing surface) SHOULD be registered the same way.

MVP fallback (non-normative): the key-management UI MAY offer manual
warrant creation with a typed audience. The request flow above is the
intended UX; manual entry exists so the module is usable before RPs adopt
the challenge extension.

## 7. Grant exchange (RP side)

An RP opts in with one endpoint: exchange a verified warrant-backed
assertion for the RP's own bearer token (RFC 7521 assertion-grant shape).

### 7.1 Grant type

```
urn:x-browserid:grant-type:assertion
```

### 7.2 In-band discovery: `WWW-Authenticate` challenge

An unauthenticated request to a protected resource MUST receive `401` with:

```
WWW-Authenticate: BrowserID realm="api",
    audience="https://api.example.com",
    token_endpoint="https://api.example.com/token",
    scopes="post read"
```

`audience` (REQUIRED) — the exact audience assertions and warrants must
name; the RP is the sole authority for this value (agents and consent pages
copy it verbatim, closing the "which origin do I type" problem). Usually the
API origin, but any exact-match URI is valid (see §5.2).
`token_endpoint` (REQUIRED) — absolute URL. `scopes` (OPTIONAL, *new in
v0.4*) — space-separated scope strings the RP requests, in its own
vocabulary. `realm` OPTIONAL; unknown parameters MUST be ignored.

### 7.3 Token endpoint

`POST <token_endpoint>` with `application/x-www-form-urlencoded`:

```
grant_type=urn:x-browserid:grant-type:assertion
assertion=<warrant-backed assertion (agent_cert~warrant~assertion)>
```

The RP MUST verify the presentation per §5.3 (which subsumes audience,
expiry, signature chain, issuer trust via the core DNSSEC path, and the
warrant's audience match). Human presentations (`cert~assertion`, no agent
`typ`) verify per core §6.2 unchanged.

**Scopes:** the RP MUST NOT grant authority beyond the intersection of the
warrant's `scopes` and its own — the issued token is bounded by what the
delegator signed. A warrant without `scopes` is audience-authorized but
scope-unqualified; whether that maps to a default scope set or a minimal
one is RP policy (SHOULD be documented).

Success — `200`, OAuth-shaped:

```json
{ "access_token": "…", "token_type": "Bearer", "expires_in": 3600,
  "email": "attestor2@mingo.place",
  "agent": { "parent": "a@b.c" }, "scopes": ["post", "read"] }
```

Failure — `400` with `{ "error": "unsupported_grant_type" | "invalid_grant",
"error_description": "…" }`.

### 7.4 Out-of-band discovery: RFC 8414

RPs SHOULD serve `/.well-known/oauth-authorization-server`:

```json
{
  "issuer": "https://api.example.com",
  "token_endpoint": "https://api.example.com/token",
  "grant_types_supported": ["urn:x-browserid:grant-type:assertion"],
  "token_endpoint_auth_methods_supported": ["none"],
  "response_types_supported": [],
  "scopes_supported": ["post", "read"]
}
```

## 8. Security considerations

- **Transport:** all endpoints MUST be HTTPS in production.
- **Domain separation:** the `typ` values (§4.1, §5.1, §5.2) MUST be
  enforced; `U_priv` signing a `P_cert` or warrant must never be replayable
  as a certificate or assertion (structurally guaranteed — no
  `principal` / wrong shape — belt-and-suspenders via `typ`).
- **Fail-closed presentation:** the agent cert `typ` plus warrant-in-chain
  (§5.3) mean a leaked `A_priv` + certificate is unusable without warrants,
  and unusable at verifiers that predate this module. "Forgot to check the
  warrant" is not expressible in a conforming verifier: the chain does not
  verify without it.
- **`P_priv` leak:** the attacker can request endorsements (and consent
  requests) until the user revokes; abuse is attributable to `P_pub` in
  registrar logs (requests are signed, unlike bearer secrets). Blast radius
  stays confined to the delegator's *agent* identities — and, at RPs, to
  audiences with user-approved warrants.
- **Registrar compromise:** can endorse rogue requests but cannot fabricate
  a user authorization (mint chain) nor a warrant — both require `U_priv`.
  The IdP independently verifies the user-signed chain; RPs independently
  verify the user-signed warrant.
- **Audience pinning:** `R.domain` + `E.aud` make a bundle for one IdP
  useless at another; `E.sub` prevents endorsement reuse across requests;
  `W.aud` makes a warrant for one RP useless at another.
- **Consent surface:** the §6.3 page is the trust boundary against
  consent-phishing. It MUST render the verified target origin (not only a
  friendly name), and approval MUST be deliberate. `code` is single-use,
  short-lived, ≥ 128-bit, rate-limited on poll.
- **Warrant privacy:** warrants never transit the IdP; the registrar holds
  audience data only in the pending request and MUST delete it on delivery
  (§6.4). No party other than the addressed RP ever holds a usable record
  of where an agent is authorized.
- **Enumeration:** §4.4/§4.5 visibility rules prevent a provisioning
  credential from probing anything outside its own delegation.
- **Attribution chains:** an agent identity MUST NOT serve as a delegator
  (no unattributable agent→agent trees). The `agent.parent` claim is
  issuer-set from the verified chain; agents cannot influence it.

## 9. Conformance

An **IdP** conforms if it implements §4.3–§4.5 under §3's rules, minting §5.1
certificates. A **registrar** conforms if it additionally implements §4.2 (+
a registry) and the §6 consent flow. An **RP** conforms if it implements
§7.2–§7.3 with §5.3 verification (fail-closed on agent certificates); §7.4
is recommended. A **verifier** (RP-side library or hosted `/verify`)
conforms only if it enforces §5.3 step 1 — agent certificates are never
verifiable without their warrant.

Reference implementations in this repository and the mingo repository
*(v0.3 surface; v0.4 items are tracked in epic `browserid-ng-gsnm`)*:

| Role | Reference |
|---|---|
| Broker-rooted registrar + IdP | `browserid-broker` with `AGENT_PROVISIONING=1` |
| IdP (federated) | `mingo-idp` (mingo repo) |
| Agent | `browserid-agent` crate |
| RP | `browserid-rp` crate |
| Chain formats | `browserid-core::provisioning` |

Design rationale: `docs/plans/2026-07-10-agent-identity-v3-and-gtm-plan.md`
(v3), `docs/plans/2026-07-09-agent-delegation-chain-design.md` (v2),
`docs/plans/2026-07-08-agent-native-browserid-design.md` (v1, superseded).
