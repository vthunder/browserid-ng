# BrowserID Agent Provisioning, Warrants & Grant Exchange — API Specification

**Version:** 0.6 (draft — device-cert model)
**Date:** 2026-07-19
**Status:** Rewritten to the **device-cert model** (core spec §4–§6;
`docs/design/browserid-end-to-end-flow.md`; built types
`browserid-core/src/device.rs`). The v0.2–v0.5 **delegation chain**
(`U_cert~P_cert~R` + registrar endorsement) and the `browserid-agent-cert-v1` /
`agent_cert~warrant~assertion` presentation are **retired**.

### Changes in v0.6 (device-cert model)

1. **Agent = an `agent`-subject device cert issued directly by the IdP** (core
   §4.1) after the **user authorizes issuance** via a device-grant / pairing
   hand-off (core §7). The user-signed **delegation chain** (`U_cert~P_cert`),
   the **provisioning request** (`R`), and the **registrar endorsement** (`E`)
   are all **removed** — the IdP is the direct issuer, gated by user pairing, not
   by a `P_cert` chain.
2. **The agent mints access certs headlessly** at the IdP's **mint API** (core
   §4.2, §7): an `authentication`+`agent` device cert signs an **access request**
   naming a fresh access key; the IdP returns a short-lived **access cert**. This
   replaces `/provision/mint` returning a long-lived identity cert.
3. **Warrants are signed by a config cert** (core §4.3), **not** the delegator's
   raw identity key, and range over **(`identifier`, `subject`) → `audience`
   [+`scopes`]** (`browserid-warrant-v1`). They are **stored in the hosted-broker
   registry** and reused device-agnostically.
4. **Presentation is the four-object bundle** `access_cert ~ assertion ~ warrant
   ~ config_cert` (core §5) — the same bundle for user and agent. `§7`'s grant
   exchange swaps **this bundle** for the RP's bearer token.
5. **§6 consent** and **§7 grant exchange** keep their **RFC 8628 / RFC 7521
   shape**; only the signed artifacts change (a config-cert-signed warrant, and
   the four-object bundle as the exchanged assertion).

The v0.5 note below is retained for history; where it conflicts with v0.6, v0.6
governs.

**(Historical, superseded):** v0.5 corrected the registrar trust model (§2, §3):
the registrar is the **user's chosen broker**, never the IdP, and its endpoint is
carried in the agent certificate so a headless agent knows where to obtain
warrants (bean `browserid-ng-s75b`). v0.2 replaced v0.1's bearer API keys with a
user-signed **delegation chain** plus per-request endorsement.

### Historical (v0.4–v0.5, superseded by v0.6)

The prior versions built agents on a **delegation chain**: a user-signed
provisioning cert (`P_cert`) plus per-request **registrar endorsement** minted a
long-lived `browserid-agent-cert-v1` (carrying an `agent.parent` block and a
`registrar` claim), presented as `agent_cert~warrant~assertion` with the warrant
signed by the delegator's raw identity key. v0.6 replaces all of that with
direct IdP issuance of an `agent`-subject device cert + the mint API, and
config-cert-signed warrants in the four-object bundle. The privacy and
fail-closed goals are preserved; the mechanism changed. See the device-cert
model (`docs/design/browserid-end-to-end-flow.md`).

## 1. Purpose and scope

This document specifies the HTTP surfaces that make BrowserID usable by
software agents without a browser:

1. **Agent device-cert issuance & minting** (§4) — how the IdP issues an
   `agent`-subject **device cert** (core §4.1) after the user authorizes it via
   a device-grant, and how the agent then **mints short-lived access certs
   headlessly** at the IdP mint API (core §4.2). No browser, no delegation chain.
2. **Agent identity & warrants** (§5) — what the agent device cert asserts, and
   how a **config-cert-signed warrant** (core §4.3, §5) authorizes the agent at a
   specific RP with specific scopes.
3. **Consent flow** (§6) — how an agent obtains a warrant for a new RP
   just-in-time, with the user approving at their broker (RFC 8628 shape).
4. **Grant exchange** (§7) — how an agent authenticates to an API relying party
   by swapping the **four-object bundle** (`access_cert~assertion~warrant~config_cert`)
   for the RP's own bearer token, including in-band (`WWW-Authenticate`) and
   out-of-band (RFC 8414) discovery.

The agent's bundle verifies exactly like any user bundle (core §6.2); the only
difference is `subject: agent`, which the RP surfaces as attribution.
**Agent-ness is protocol-visible and attributable**: every agent access cert and
warrant carries `subject: agent` and the agent's own identifier, and every use is
confined to audiences the user approved.

Out of scope: browser session establishment at RPs, and escrow/stake trust
models. The registrar's key-management UI is described non-normatively
(§4.6).

## 2. Terminology

- **IdP** — a BrowserID identity provider implementing core §4/§7: device-cert
  issuance (both purposes) and the access-cert mint API. Authoritative for
  identities under its own domain.
- **Client broker** — software operating the **user's keystore on a device**:
  holds device certs, mints access certs, and signs warrants with the device's
  config cert. Runs the **device-grant** hand-off that authorizes an agent's
  device-cert issuance (§4.1), and hosts the **consent surface** (§6).
- **Hosted broker (browserid.me)** — the fallback IdP, a hosted verifier, and
  the **warrant registry / revocation UI / status endpoints**. It **records**
  warrants; it does not sign them.
- **Agent** — a headless client holding an **`agent`-subject device cert** and,
  per session, a **fresh access key** it mints an access cert for.
- **Agent device cert** — a device cert with `purpose: authentication`,
  `subject: agent`, issued by the IdP for the agent's device key, listing the
  `identities` (e.g. `dan+agent@sandmill.org` or a `dan+*@sandmill.org` glob) the
  agent may act for (core §4.1). Issued **directly by the IdP** after the user
  authorizes it — there is no `P_cert` delegation.
- **Config cert** — an `authorization`-purpose device cert (core §4.3) that signs
  warrants. Device-resident, non-extractable, issued by the identity's own IdP.
- **User / delegator** — the human whose IdP issues both the agent device cert
  (after they authorize it) and the config cert that signs the agent's warrants.
- **Access cert / access request** — the fresh-key, RP-facing cert (core §4.2)
  and the device-signed request that mints it.
- **Warrant (W)** — a config-cert-signed authorization binding one identifier +
  subject to one RP audience, optionally with scopes (§5.2, core §5).
- **Device-grant** — the pairing hand-off by which an off-browser agent's pubkey
  reaches the IdP for issuance, gated by user approval (core §7).

Key words MUST/SHOULD/MAY are RFC 2119.

## 3. Trust model (normative summary)

- **Authorization is user-signed by a config cert.** An RP MUST NOT accept an
  agent presentation without a valid **warrant** signed by a **config cert**
  (`purpose: authorization`) issued by the identity's own IdP (core §5, §6.2).
  The config-cert issuer binding (`config_cert.iss == access_cert.iss`) means no
  rogue IdP's authorization cert can vouch for another IdP's identity.
- **Agent issuance is user-authorized, IdP-signed, and direct.** An IdP MUST NOT
  issue an `agent`-subject device cert without the user's authorization via the
  device-grant (core §7). There is **no delegation chain and no registrar
  endorsement**: the IdP is the direct issuer, gated by user pairing.
- **Minting is IdP-gated online.** Each access cert is minted at the IdP mint API
  against a device-signed access request (core §4.2). The IdP verifies the device
  cert is its own issuance, unrevoked, in validity, and lists the requested
  identity; it MAY refuse. No session cookie is involved (survives ITP), and the
  agent mints headlessly.
- **Identity-domain rule.** The agent's identity is rooted at the IdP that is
  authoritative for it; the access cert and the config cert share that one IdP and
  one DNSSEC trust root (the issuer binding enforces it, core §6.2 step 2).
- **Audience confinement is user-signed and RP-enforced.** Device/access certs
  carry no audiences and no scopes. A warrant confines the agent to **one**
  audience; scopes within it are opaque to the broker and interpreted only by the
  RP (§7.3). An RP sees only warrants addressed to it. The **hosted broker**
  stores issued warrants (identifier, subject, audience, scopes, expiry, the
  signed JWS) for the user's account view and per-grant revocation — but the
  warrant is signed **client-side** by the config cert, so the broker never signs
  and the IdP never sees a warrant's audience or scopes.
- **Revocation is fail-closed and threefold** (core §6.2 step 8, §6.4): the
  **access cert** (→ IdP, per-device index), the **config cert** (→ IdP), and the
  **warrant** (→ hosted broker registry) each carry a status ref the RP checks
  fail-closed. Access certs are short-lived (reference: 24 h) and IdP-gated at
  mint, so revoking the agent's device cert stops new access certs within one TTL.
- **Scope of the agent device cert.** An agent device cert only enables minting
  access certs for the `identities` it lists — never reading account data,
  altering credentials, or acting on the user's human (login) identities. Device
  keys never transit the wire; only signatures do.
- **Quota is IdP-enforced.** The IdP SHOULD enforce a per-user quota of active
  agent device certs (reference default: 5).

## 4. Agent device-cert issuance & minting

The delegation chain (`U_cert~P_cert~R` + endorsement) of prior versions is
**removed**. An agent is bootstrapped in two steps: (a) the IdP issues an
`agent`-subject **device cert** after the user authorizes it (§4.1); (b) the
agent **mints access certs headlessly** at the IdP mint API (§4.2). Both use
core `browserid-core/src/device.rs` claim shapes; all objects are Ed25519 JWS
with an explicit `typ` (verifiers reject an unexpected `typ`).

### 4.1 Agent device-cert issuance (device-grant)

An agent's device keypair is generated **off-browser**. Because the agent cannot
authenticate to the IdP interactively, the **user authorizes** issuance and the
**IdP issues the agent device cert directly**:

1. The agent presents its device **public key** to the user's client broker (a
   pairing / device-grant hand-off).
2. The user approves the constraints — the `identities` (one email, several, or a
   single-`*` glob such as `dan+*@sandmill.org`), `subject: agent`, and validity.
3. The IdP signs a **device cert** (core §4.1):

```json
{
  "typ": "browserid-device-cert-v1",
  "iss": "mingo.place",
  "iat": 1783600000,
  "exp": 1791376000,
  "purpose": "authentication",
  "subject": "agent",
  "identities": ["attestor2@mingo.place"],
  "public-key": "<agent device key, base64url>",
  "status": { "uri": "https://mingo.place/.well-known/browserid-status", "idx": 42 }
}
```

There is **no `P_cert`, no registrar endorsement, and no `agent.parent`
block**: attribution now lives in the access cert / warrant `subject: agent`
and the `identities` list, and revocation lives in the device cert's `status`
ref. Reference validity: 90 days. The IdP SHOULD enforce a per-user quota of
active agent device certs (§3).

### 4.2 Access-cert minting: `POST <mint>` (core §4.2)

The agent mints a short-lived access cert per session by signing an **access
request** with its device key and posting it to the IdP mint endpoint (§3.1
`mint`):

```json
{
  "typ": "browserid-access-request-v1",
  "iat": 1783600000, "exp": 1783600600,
  "jti": "<single-use nonce>",
  "domain": "mingo.place",
  "identity": "attestor2@mingo.place",
  "subject": "agent",
  "access-key": "<fresh access key, base64url>"
}
```

The IdP MUST verify: the device cert is its own issuance, unrevoked, in
validity, and lists `identity`; the request signature under the device key;
`jti` unseen (replay protection); `domain` == its own domain. It returns a
short-lived **access cert** (`browserid-access-cert-v1`, core §4.2) certifying
the fresh `access-key`, with a `status` ref rooted at the issuing device's
index. The IdP MAY refuse even a valid device cert (abuse/compromise); the user
then re-authorizes the agent. No session cookie is involved — the agent mints
**headlessly**.

### 4.3 Device management (list / revoke)

An IdP SHOULD expose authenticated management surfaces (in the user's client
broker) to **list** a user's active agent device certs and **revoke** one.
Revoking flips the device cert's `status` bit, so it mints no further access
certs and its outstanding access certs are rejected fail-closed at the RP (core
§6.4) within one access-cert TTL. Names/identities are never recycled.

## 5. Agent identity, warrants & presentation *(device-cert model)*

### 5.1 Agent access cert

The RP never sees the agent **device** cert (§4.1). What it sees is the fresh,
short-lived **access cert** minted for it (§4.2, core §4.2), carrying
`subject: agent`:

```json
{
  "typ": "browserid-access-cert-v1",
  "iss": "mingo.place",
  "iat": 1783600000, "exp": 1783686400,
  "identity": "attestor2@mingo.place",
  "subject": "agent",
  "public-key": "<fresh access key, base64url>",
  "status": { "uri": "https://mingo.place/.well-known/browserid-status", "idx": 42 }
}
```

`subject: agent` **is** the attribution — issuer-signed, verifiable with no
callback. There is no separate `agent.parent` block and no untyped ("invisible")
agent credential: `subject` is part of the join the RP enforces (core §6.2).
`status` is rooted at the **issuing device's** index, so revoking the agent's
device cert kills its access certs.

### 5.2 Warrant (`browserid-warrant-v1`)

A warrant is signed by a **config cert** (core §4.3), **not** the user's raw
identity key, and authorizes one identifier + subject at one audience (core §5):

```json
{
  "typ": "browserid-warrant-v1",
  "iat": 1783600000, "exp": 1791376000,
  "identifier": "attestor2@mingo.place",
  "subject": "agent",
  "audience": "https://api.mingo.place",
  "scopes": ["post", "read"],
  "status": { "uri": "https://browserid.me/.well-known/browserid-status", "idx": 7 }
}
```

- `identifier` — the agent's email. MUST equal the access cert's `identity`.
- `subject` — MUST equal the access cert's `subject` (`agent`). The `(identifier,
  subject)` pair, not a device key, is what the warrant binds.
- `audience` — **exactly one** RP audience: opaque, exact-match, same
  normalization as assertion `aud` (core §5). For web RPs the https origin;
  non-web consumers MAY use scheme-specific URIs (e.g. `sbo://<ledger>`).
  Wildcards/patterns MUST be rejected.
- `scopes` — OPTIONAL opaque strings, meaningful only to the RP (§7.3). The IdP
  and the broker never interpret (or see) them.
- `status` — the **warrant's** revocation ref, rooted at the **hosted broker's
  warrant registry** (core §6.4) — a distinct authority from the two IdP-rooted
  status refs (access cert, config cert). The user revokes **this one grant**
  without touching the agent's others.
- Reference validity: 90 days.

The warrant is **over the identifier + subject, not bound to any key**, so it is
signed **once** by the config cert, **stored** in the hosted-broker registry, and
**reused device-agnostically**: any device that can mint an access cert for that
identity presents the stored warrant alongside it. Privacy: one warrant names one
audience; the config cert signs it **client-side** (the IdP never sees an
audience/scopes); the broker stores it but does not sign it; an RP sees only the
warrant addressed to it.

### 5.3 Presentation: the four-object bundle

An agent authenticates to an RP with the **same four-object bundle** as a human
(core §5):

```
<access_cert>~<assertion>~<warrant>~<config_cert>
```

Verification is core §6.2 verbatim (the two-path join by `(identity, subject,
audience)` with the config-cert issuer binding and three fail-closed status
checks). The agent case differs only in that `subject == agent`. In particular:

1. Parse exactly the four objects; reject any other shape, `typ`, `purpose`, or
   `subject` (fail-closed).
2. `config_cert.iss == access_cert.iss` (the identity's IdP), DNSSEC-resolved.
3. Access cert + config cert verify under that IdP key; neither expired.
4. Assertion verifies under the access cert's fresh key; `aud` == the RP.
5. Config cert is `purpose: authorization` and authorizes `access_cert.identity`;
   warrant verifies under the config cert, unexpired, with `warrant.identifier ==
   access_cert.identity`, `warrant.subject == access_cert.subject`, and
   `warrant.audience` == the RP.
6. Check the **three** status refs (access→IdP, config→IdP, warrant→hosted
   broker) **fail-closed**.
7. Result: the agent's email, `subject: agent`, and the warrant's `scopes` — the
   RP SHOULD surface these as attribution.

A leaked access cert + key without a warrant, or with a warrant for a different
audience, is unusable (steps 1/5 fail); and a leaked warrant is useless without a
matching IdP-minted access cert. The agent is usable exactly where and how the
user authorized — until any of the three authorities revokes.

## 6. Consent flow — just-in-time warrants

Warrants are **requested, not configured**: the RP names its own audience
authoritatively (§7.2), and the user approves at their broker's consent surface.
The flow keeps the shape of the OAuth device authorization grant (RFC 8628); only
the signed artifact changes — the approved object is a **config-cert-signed
warrant** (§5.2) recorded in the **hosted-broker registry**.

### 6.1 Trigger

The agent contacts the RP and receives the §7.2 challenge naming `audience` and
(optionally) `scopes`. Lacking a warrant for that audience, the agent raises a
consent request.

### 6.2 Broker: `POST /warrant/request`

The agent identifies itself with an object signed by its **agent device key** —
naming the identity and the requested grants:

```json
{
  "typ": "browserid-warrant-request-v1",
  "iat": …, "exp": …,
  "identity": "attestor2@mingo.place",
  "subject": "agent",
  "warrant-grants": [
    { "audience": "https://api.mingo.place", "scopes": ["post", "read"] },
    { "audience": "sbo://mingo.place",        "scopes": ["claim"] }
  ]
}
```

`warrant-grants` carries **1–8 grants**, one per audience (duplicates MUST be
rejected), each with its own scopes — an agent needing several audiences asks
once and the user approves once. Each grant still yields its own
**single-audience** warrant (§5.2); batching exists only at the request/consent
layer, so the privacy analysis is unchanged.

The broker verifies the request signature against the agent's device cert
(unrevoked, lists `identity`), then creates a **pending consent request** and
returns:

```json
{ "success": true, "code": "<high-entropy opaque>",
  "verification_uri": "https://browserid.me/consent/<code>",
  "expires_in": 900, "interval": 5 }
```

The broker SHOULD notify the user; the agent SHOULD also surface
`verification_uri` to its principal directly when it has a channel to them.

### 6.3 Consent page

Served by the broker at `verification_uri`, to the signed-in user only. It MUST
display: the agent's handle and label, and — for **every** grant in the request,
each with equal prominence (no folding N grants behind a summary line) — the
**verified audience** and its requested scopes, prefilled from the request, never
user-typed. Where an RP publishes §7.4 metadata, the page MAY enrich the display
(name/logo) but MUST still show the audience itself.

On approval, the page signs one §5.2 warrant **per grant** with the user's
**config cert** held device-resident in broker-origin storage (a client-side
typed-signing operation — the IdP never sees the audience/scopes) and records
each in the hosted-broker registry; approval is all-or-nothing over the displayed
set. Policy knobs (deny, "always ask", standing per-agent preferences) are
broker-local and non-normative. The approve action MUST be deliberate (no
default-focused approve button); consent-fatigue resistance is a design
requirement of the surface.

### 6.4 Broker: `POST /warrant/poll`

Request: `{ "code": "<code>" }`. Responses:

| Status | Body | Meaning |
|---|---|---|
| 200 | `{ "status": "approved", "warrants": ["<W JWS>", …], "warrant": "<W JWS>\|null" }` | Done — one warrant per grant, in grant order (`warrant` is populated iff exactly one); the pending request is deleted on delivery |
| 200 | `{ "status": "pending" }` | Poll again after `interval` seconds |
| 200 | `{ "status": "denied" }` | The user declined |
| 410 | `{ "status": "expired" }` | Request expired unapproved |
| 429 | — | Polling faster than `interval` |

`code` is a short-lived, single-delivery bearer; its entropy MUST be ≥ 128 bits.
On delivery the broker MUST delete the **pending request** (the code becomes
indistinguishable from expired). The issued warrants themselves are retained in
the **hosted-broker warrant registry** (§3): per-user records of identifier,
subject, audience, scopes, expiry, and the signed JWS, shown only to the user's
own authenticated session — this is what makes an account's grants reviewable
across devices and is the substrate for per-warrant revocation (each warrant's
`status` index, core §6.4). Warrants signed outside the consent flow (a broker's
manual signing surface) are registered the same way.

MVP fallback (non-normative): the key-management UI MAY offer manual warrant
creation with a typed audience. The request flow above is the intended UX; manual
entry exists so the module is usable before RPs adopt the challenge extension.

## 7. Grant exchange (RP side)

An RP opts in with one endpoint: exchange the verified **four-object bundle**
(`access_cert~assertion~warrant~config_cert`, core §5) for the RP's own bearer
token (RFC 7521 assertion-grant shape).

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
assertion=<four-object bundle (access_cert~assertion~warrant~config_cert)>
```

The RP MUST verify the presentation per §5.3 / core §6.2 (which subsumes
audience, expiry, the two-path join, the config-cert issuer binding, and the
three fail-closed status checks). Human presentations use the **same** bundle
shape with `subject: user`.

**Scopes:** the RP MUST NOT grant authority beyond the intersection of the
warrant's `scopes` and its own — the issued token is bounded by what the
delegator signed. A warrant without `scopes` is audience-authorized but
scope-unqualified; whether that maps to a default scope set or a minimal
one is RP policy (SHOULD be documented).

Success — `200`, OAuth-shaped:

```json
{ "access_token": "…", "token_type": "Bearer", "expires_in": 3600,
  "email": "attestor2@mingo.place",
  "subject": "agent", "scopes": ["post", "read"] }
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
- **Domain separation:** the `typ` values (device cert / access request /
  access cert / warrant, core §4–§5) MUST be enforced; a config cert signing a
  warrant must never be replayable as an access cert or assertion (different
  shape + `typ`).
- **Config-cert issuer binding:** the RP requires `config_cert.iss ==
  access_cert.iss` (core §6.2) so a warrant signed by a rogue IdP's
  authorization cert cannot vouch for another IdP's identity.
- **Fail-closed presentation:** the four-object bundle join means a leaked
  access key + cert is unusable without a matching warrant for **this** audience,
  and a leaked warrant is useless without a matching IdP-minted access cert.
  "Forgot to check the warrant" is not expressible in a conforming verifier — the
  join does not complete without it.
- **Agent device-key leak:** the attacker can mint access certs (and raise
  consent requests) until the user revokes the **device cert**; abuse is
  attributable via `subject: agent` + the identifier, and stops within one
  access-cert TTL (§4.3). Blast radius stays confined to the agent's `identities`
  — and, at RPs, to audiences with user-approved warrants.
- **Broker compromise:** the hosted broker stores warrants but does **not** sign
  them (the config cert does, client-side) and cannot mint access certs (the IdP
  does), so it can neither fabricate a user authorization nor forge a login. The
  IdP independently gates minting; RPs independently verify the config-cert-signed
  warrant.
- **Audience pinning:** the access request `domain` makes a mint for one IdP
  useless at another; `jti` prevents access-request replay; the warrant's
  `audience` makes a warrant for one RP useless at another.
- **Consent surface:** the §6.3 page is the trust boundary against
  consent-phishing. It MUST render the verified target origin (not only a
  friendly name), and approval MUST be deliberate. `code` is single-use,
  short-lived, ≥ 128-bit, rate-limited on poll.
- **Warrant privacy:** warrants are signed client-side by the config cert and
  never transit the IdP; the broker holds audience data in the pending request
  (deleted on delivery, §6.4) and the registry (user-only). No party other than
  the addressed RP ever holds a usable record of where an agent is authorized.
- **Revocation is fail-closed and threefold:** access cert (→ IdP), config cert
  (→ IdP), warrant (→ hosted broker) — all checked fail-closed (core §6.2 step 8).
- **Attribution:** `subject: agent` is issuer-set on the access cert (and the
  warrant); agents cannot influence it. An agent identity is not itself a signing
  authority for other agents.

## 9. Conformance

An **IdP** conforms if it implements agent device-cert issuance (§4.1, gated by
the user's device-grant) and the access-cert mint API (§4.2) under §3's rules. A
**broker** conforms if it additionally hosts the §6 consent flow and the warrant
registry. An **RP** conforms if it implements §7.2–§7.3 with §5.3 / core §6.2
verification (four-object bundle, config-cert issuer binding, three fail-closed
status checks); §7.4 is recommended. A **verifier** (RP-side library or hosted
`/verify`) conforms only if it accepts exactly the four-object bundle — an access
cert is never usable without its warrant and config cert.

Reference implementations in this repository and the mingo repository:

| Role | Reference |
|---|---|
| Hosted broker + fallback IdP | `browserid-broker` (device-cert issuance + mint + conformance verifier) |
| IdP (federated) | `mingo-idp` (mingo repo) |
| Agent | `browserid-agent` crate |
| RP | `browserid-rp` crate |
| Cert / bundle formats | `browserid-core::device` |

Design rationale: `docs/design/browserid-end-to-end-flow.md` (device-cert model);
migration plan `docs/plans/2026-07-18-device-cert-model-migration-plan.md`.
Superseded: `docs/plans/2026-07-10-agent-identity-v3-and-gtm-plan.md` (delegation
chain, v3), `2026-07-09-agent-delegation-chain-design.md` (v2).
