# Agent Provisioning, Warrants & Grant Exchange

> **Status: draft.** A module layered on the core protocol (see the core
> specification). It specifies how an IdP issues a device cert to a **headless
> agent** after the user authorizes it, how the agent **mints access certs** and
> obtains **warrants** without a browser, and how a relying party **exchanges** the
> agent's presentation bundle for its own bearer token. The core protocol's actors,
> artifacts, and verification apply unchanged; this module adds only the
> agent-specific issuance, consent, and grant-exchange surfaces.

## 1. Purpose and scope

An **agent** is a holder that is not a browser — a program acting for an identity,
with no interactive session at the IdP. This document specifies the HTTP surfaces
that make it a first-class holder:

1. **Agent device-cert issuance & minting (§4)** — how the IdP issues an agent an
   `authentication` **device cert** (core §4.1) after the user authorizes it via a
   device-grant, and how the agent then **mints short-lived access certs
   headlessly** at the mint (core §4.2), with no browser in the loop.
2. **Agent identity, warrants & presentation (§5)** — the agent's access cert, and
   how a **config-cert-signed warrant** (core §4.3, §5) authorizes it at a specific
   RP with specific scopes.
3. **Consent flow (§6)** — how an agent obtains a warrant for a new RP
   just-in-time, with the user approving at their broker (RFC 8628 shape).
4. **Grant exchange (§7)** — how an RP swaps the agent's **presentation bundle**
   (`access_cert~assertion~warrant~config_cert`) for its own bearer token, with
   in-band (`WWW-Authenticate`) and out-of-band (RFC 8414) discovery.

The agent's bundle verifies **exactly like any bundle** (core §6). The only thing
that makes it "an agent" is that its holder is not a browser and, for a delegated
grant, that the **grantee** (the actor) differs from the **grantor** (the identity
the action is attributed to). Both are protocol-visible: the RP learns who acted
and on whose behalf, and every use is confined to audiences the grantor approved.

Out of scope: browser session establishment at RPs, and escrow/stake trust models.

## 2. Terminology

The core protocol defines **identity**, **holder**, **grantor**, **grantee**,
**IdP**, **RP**, and the **broker** (client + hosted components). This module adds:

- **Agent** — a headless holder (in the account's `agents`/`services` namespace)
  holding an `authentication` **device cert** for one or more identities, and, per
  session, a **fresh access key** it mints an access cert for.
- **Agent device cert** — a device cert with `purpose: authentication` and an
  agent holder, issued by the IdP for the agent's device key, listing the
  `identities` it may act for (core §4.1). Issued **directly by the IdP** after the
  user authorizes it via the device-grant.
- **Device-grant** — the pairing hand-off by which an off-browser agent's public
  key reaches the IdP for issuance, gated by user approval.
- **Warrant** — a config-cert-signed authorization binding a `grantor → grantee`
  over a holder-matcher, audience, and optional scopes (§5.2, core §5).

Key words MUST/SHOULD/MAY are RFC 2119.

## 3. Trust model (normative summary)

- **Authorization is user-signed by a config cert.** An RP MUST NOT accept an agent
  presentation without a valid **warrant** signed by a **config cert**
  (`purpose: authorization`) issued by an IdP authoritative for the warrant's
  **grantor** (core §4.3, §5, §6). Because attribution lands on the grantor, an
  issuer can only ever authorize a grant for an identity it vouches for.
- **Agent issuance is user-authorized, IdP-signed, and direct.** An IdP MUST NOT
  issue an agent device cert without the user's authorization via the device-grant
  (core §7). The IdP is the direct issuer, gated by user pairing.
- **Minting is IdP-gated online.** Each access cert is minted at the IdP against a
  device-signed access request (core §4.2). The IdP verifies the device cert is its
  own issuance, unrevoked, in validity, and lists the requested identity **exactly**
  (subaddressing does not widen the auth path, core §4.6); it MAY refuse. No session
  cookie is involved; the agent mints headlessly.
- **Audience confinement is user-signed and RP-enforced.** Device and access certs
  carry no audiences and no scopes. A warrant confines the agent to **one** audience;
  scopes within it are opaque to the broker and interpreted only by the RP (§7.3).
  An RP sees only warrants addressed to it. The hosted broker stores issued warrants
  for the account's own view and per-grant revocation, but the warrant is signed
  **client-side** by the config cert — the broker never signs, and the IdP never
  sees a warrant's audience or scopes.
- **Revocation is fail-closed and threefold** (core §6): the **access cert**
  (→ IdP, per-device index), the **config cert** (→ IdP), and the **warrant**
  (→ hosted broker registry) each carry a status ref the RP checks fail-closed.
  Access certs are short-lived and IdP-gated at mint, so revoking the agent's device
  cert stops new access certs within one TTL.
- **Scope of the agent device cert.** It only enables minting access certs for the
  `identities` it lists — never reading account data, altering credentials, or
  acting on the user's other identities. Device keys never transit the wire; only
  signatures do.
- **Quota is IdP-enforced.** The IdP SHOULD enforce a per-user quota of active agent
  device certs (reference default: 5).

## 4. Agent device-cert issuance & minting

An agent is bootstrapped in two steps: (a) the IdP issues it an `authentication`
device cert after the user authorizes it (§4.1); (b) the agent mints access certs
headlessly (§4.2). All objects are Ed25519 JWS with an explicit `typ`; verifiers
reject an unexpected `typ`.

### 4.1 Agent device-cert issuance (device-grant)

An agent's device keypair is generated **off-browser**. Because the agent cannot
authenticate to the IdP interactively, the **user authorizes** issuance and the IdP
issues the device cert directly:

1. The agent presents its device **public key** to the user's client broker (a
   pairing / device-grant hand-off).
2. The user approves the constraints — the `identities` (one email, several, or an
   explicit `user+*@domain` glob), the **holder** (assigned by the broker in the
   account's `agents`/`services` namespace; the agent cannot choose it), and the
   validity.
3. The IdP signs a **device cert** (core §4.1):

```json
{
  "typ": "browserid-device-cert-v1",
  "iss": "mingo.place",
  "iat": 1783600000,
  "exp": 1791376000,
  "purpose": "authentication",
  "holder": "agents.k3n9x2",
  "identities": ["attestor2@mingo.place"],
  "public-key": "<agent device key, base64url>",
  "status": { "uri": "https://mingo.place/.well-known/browserid-status", "idx": 42 }
}
```

Attribution lives in the identities the agent acts as and, at presentation, in the
grantor/grantee of its warrant; revocation lives in the device cert's `status` ref.
Reference validity: 90 days. The IdP SHOULD enforce a per-user quota (§3).

### 4.2 Access-cert minting

The agent mints a short-lived access cert per session by signing an **access
request** with its device key and posting it to the IdP mint endpoint (support
document `access-cert`):

```json
{
  "typ": "browserid-access-request-v1",
  "iat": 1783600000, "exp": 1783600600,
  "jti": "<single-use nonce>",
  "domain": "mingo.place",
  "identity": "attestor2@mingo.place",
  "holder": "agents.k3n9x2",
  "access-key": "<fresh access key, base64url>"
}
```

The IdP MUST verify: the device cert is its own issuance, unrevoked, in validity,
and lists `identity` exactly (core §4.6); the request signature under the device
key; `holder` equals the device cert's holder; `jti` unseen (replay protection);
`domain` equals its own domain. It returns a short-lived **access cert** (core §4.2)
certifying the fresh `access-key`, carrying the device's holder verbatim and a
`status` ref rooted at the issuing device's index. The IdP MAY refuse even a valid
device cert (abuse/compromise); the user then re-authorizes the agent.

### 4.3 Device management (list / revoke)

An IdP SHOULD expose authenticated surfaces (in the user's client broker) to
**list** a user's active agent device certs and **revoke** one. Revoking flips the
device cert's `status` bit, so it mints no further access certs and its outstanding
access certs are rejected fail-closed at the RP within one access-cert TTL (core
§6.3). Holders and identities are never recycled.

## 5. Agent identity, warrants & presentation

### 5.1 Agent access cert

The RP never sees the agent **device** cert (§4.1). It sees the fresh, short-lived
**access cert** minted for it (§4.2, core §4.2):

```json
{
  "typ": "browserid-access-cert-v1",
  "iss": "mingo.place",
  "iat": 1783600000, "exp": 1783686400,
  "identity": "attestor2@mingo.place",
  "holder": "agents.k3n9x2",
  "public-key": "<fresh access key, base64url>",
  "status": { "uri": "https://mingo.place/.well-known/browserid-status", "idx": 42 }
}
```

The access cert names **the actor** (the grantee identity) and its holder; the
issuer signs both, verifiable with no callback. `status` is rooted at the issuing
device's index, so revoking the agent's device cert kills its access certs.

### 5.2 Warrant

A warrant is signed by a **config cert** (core §4.3), **not** the user's raw
identity key, and authorizes one `grantor → grantee` over a holder-matcher and one
audience (core §5):

```json
{
  "typ": "browserid-warrant-v1",
  "iat": 1783600000, "exp": 1791376000,
  "grantor": "dan@sandmill.org",
  "grantee": "attestor2@mingo.place",
  "holder": "agents.*",
  "audience": "https://api.mingo.place",
  "scopes": ["post", "read"],
  "status": { "uri": "https://browserid.me/.well-known/browserid-status", "idx": 7 }
}
```

- `grantor` — the identity the action is **attributed** to. The signing config
  cert MUST be authoritative for it (with subaddressing, core §4.6). For an
  "as-you" grant `grantor == grantee`.
- `grantee` — the identity that **acts**; MUST equal the presented access cert's
  `identity`.
- `holder` — a **matcher** (`*`, `<ns>.*`, or `<id>`) checked against the grantee's
  access-cert holder.
- `audience` — **exactly one** RP audience: opaque, exact-match, same normalization
  as assertion `aud` (core §5). For web RPs the https origin; non-web consumers MAY
  use scheme-specific URIs. Wildcards/patterns MUST be rejected.
- `scopes` — OPTIONAL opaque strings, meaningful only to the RP (§7.3). The IdP and
  broker never interpret (or see) them.
- `status` — the **warrant's** revocation ref, rooted at the hosted broker's
  warrant registry (core §6.3) — a distinct authority from the two IdP-rooted refs.
  The user revokes **this one grant** without touching the others.
- Reference validity: 90 days.

The warrant is **over the grantor/grantee + holder-matcher, not bound to any key**,
so it is signed **once**, **stored** in the hosted-broker registry, and **reused
device-agnostically**: any device whose holder the matcher covers, that can mint an
access cert for the grantee, presents the stored warrant alongside it. One warrant
names one audience; the config cert signs it client-side (the IdP never sees an
audience or scopes); the broker stores but does not sign it; an RP sees only the
warrant addressed to it.

### 5.3 Presentation: the four-object bundle

An agent authenticates to an RP with the **same bundle** as any holder (core §5):

```
<access_cert>~<assertion>~<warrant>~<config_cert>
```

Verification is core §6 verbatim — the two independent DNSSEC-rooted paths joined by
`(grantee = access-cert identity, holder ∈ matcher, audience)`, attributed to the
grantor, with per-identity issuer authority and three fail-closed status checks. A
leaked access cert + key without a warrant, or with a warrant for a different
audience, is unusable; a leaked warrant is useless without a matching IdP-minted
access cert. The agent is usable exactly where and how the user authorized — until
any of the three authorities revokes.

## 6. Consent flow — just-in-time warrants

Warrants are **requested, not configured**: the RP names its own audience
authoritatively (§7.2), and the user approves at their broker's consent surface. The
flow keeps the shape of the OAuth device authorization grant (RFC 8628); the
approved object is a **config-cert-signed warrant** (§5.2) recorded in the hosted
broker registry.

### 6.1 Trigger

The agent contacts the RP and receives the §7.2 challenge naming `audience` and
(optionally) `scopes`. Lacking a warrant for that audience, the agent raises a
consent request.

### 6.2 Broker: request a warrant

The agent identifies itself with an object signed by its **agent device key**,
naming its identity (the prospective grantee) and the requested grants:

```json
{
  "typ": "browserid-warrant-request-v1",
  "iat": …, "exp": …,
  "identity": "attestor2@mingo.place",
  "warrant-grants": [
    { "audience": "https://api.mingo.place", "scopes": ["post", "read"] },
    { "audience": "sbo+raw://avail:turing:506/", "scopes": ["claim"] }
  ]
}
```

`warrant-grants` carries **1–8 grants**, one per audience (duplicates MUST be
rejected), each with its own scopes — an agent needing several audiences asks once
and the user approves once. Each grant still yields its own **single-audience**
warrant (§5.2); batching exists only at the request/consent layer.

Two optional fields shape the consent surface:

- **`grantor`** — a pin on whom the warrants attribute to. Absent (or `*`): the
  approver chooses — the consent page offers the agent itself or any identity the
  account owns. `self` (or the agent's own email): pinned to the agent
  (`grantor == grantee`). A concrete email: pinned to that identity. A pinned
  request renders the grantor as text and offers only approve/deny — a pin is
  **never silently substituted**, and an unsatisfiable pin (an identity not on the
  routed account) MUST fail the request immediately rather than expiring.
- **`message`** — the agent's own account of why it wants the grants (≤500 chars),
  displayed quoted and explicitly marked unverified; its absence is stated rather
  than hidden.

The broker verifies the request signature against the agent's device cert
(unrevoked, lists `identity`), creates a **pending consent request**, and returns:

```json
{ "success": true, "code": "<high-entropy opaque>",
  "verification_uri": "https://browserid.me/consent/<code>",
  "expires_in": 900, "interval": 5 }
```

The broker SHOULD notify the user; the agent SHOULD also surface `verification_uri`
to its principal directly when it has a channel to them.

### 6.3 Consent page

Served by the broker at `verification_uri`, to the signed-in user only. It MUST
display: the agent's identity and its **user-chosen display name** (set when the
identity was created — the trustworthy "who" the card opens with; the requester's
label is only ever shown marked unverified), and — for **every** grant in the
request, each with equal prominence (no folding N grants behind a summary) — the
**verified audience** and its requested scopes, prefilled from the request, never
user-typed.

A request from an agent the account has **never met** (no identity on the account,
no recorded device cert or service entry) MUST NOT offer consent: the page renders a
deny-only card, and the requester's poll learns the machine reason
(`unknown_agent`) so a legitimate agent knows to request an identity first. Where an
RP publishes §7.4 metadata, the page MAY enrich the display (name/logo) but MUST
still show the audience itself.

On approval, the page signs one §5.2 warrant **per grant** with the user's **config
cert** held device-resident in broker-origin storage (a client-side typed-signing
operation — the IdP never sees the audience or scopes) and records each in the
hosted broker registry; approval is all-or-nothing over the displayed set. Policy
knobs (deny, "always ask", standing per-agent preferences) are broker-local and
non-normative. The approve action MUST be deliberate (no default-focused approve
button); consent-fatigue resistance is a design requirement of the surface.

### 6.4 Broker: poll for the result

Request: `{ "code": "<code>" }`. Responses:

| Status | Body | Meaning |
|---|---|---|
| 200 | `{ "status": "approved", "warrants": ["<W JWS>", …], "warrant": "<W JWS>\|null" }` | Done — one warrant per grant, in grant order (`warrant` is populated iff exactly one); the pending request is deleted on delivery |
| 200 | `{ "status": "pending" }` | Poll again after `interval` seconds |
| 200 | `{ "status": "denied", "reason": "…"? }` | The user declined; `reason` (optional) carries a machine cause, e.g. `unknown_agent` — request an identity first |
| 410 | `{ "status": "expired" }` | Request expired unapproved |
| 429 | — | Polling faster than `interval` |

`code` is a short-lived, single-delivery bearer; its entropy MUST be ≥ 128 bits. On
delivery the broker MUST delete the **pending request** (the code becomes
indistinguishable from expired). The issued warrants are retained in the hosted
broker **warrant registry** (§3): per-user records of grantor, grantee, audience,
scopes, expiry, and the signed JWS, shown only to the user's own authenticated
session — this is what makes an account's grants reviewable across devices and is
the substrate for per-warrant revocation (each warrant's `status` index, core §6.3).
Warrants signed outside the consent flow (a broker's manual signing surface) are
registered the same way.

MVP fallback (non-normative): the key-management UI MAY offer manual warrant
creation with a typed audience. The request flow above is the intended UX; manual
entry exists so the module is usable before RPs adopt the challenge extension.

### 6.5 Two-stage provisioning approval

A merged provisioning request (issue the agent device cert **and** grant warrants in
one hand-off) is approved in **two stages under one code**: the **identity stage**
verifies the pairing fingerprint and mints the agent device cert — the word
"permission" never appears — and the **grants stage** then presents the permission
question exactly as §6.3 does for a known agent, with the identity fixed and stated.
The broker's approval endpoint takes `stage: "identity"` then `stage: "grants"`; the
agent's poll keeps reading `pending` until the whole request resolves and still
receives one single-delivery pickup. Declining the grants stage is honest, not
fatal: the identity exists, and the pickup delivers the credential with no warrants
and a `grants_denied` reason. Abandonment after the identity stage leaves an
identity with no permissions — exactly what the screens said existed. Identity-only
requests (no grants) complete at the identity stage; warrant-only requests are §6.2.
The user-chosen **display name** confirmed at the identity stage is stored on the
agent identity and is what every later §6.3 card opens with.

## 7. Grant exchange (RP side)

An RP opts in with one endpoint: exchange the verified **presentation bundle**
(`access_cert~assertion~warrant~config_cert`, core §5) for the RP's own bearer token
(RFC 7521 assertion-grant shape).

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

`audience` (REQUIRED) — the exact audience assertions and warrants must name; the RP
is the sole authority for this value (agents and consent pages copy it verbatim,
closing the "which origin do I type" problem). Usually the API origin, but any
exact-match URI is valid (see §5.2). `token_endpoint` (REQUIRED) — absolute URL.
`scopes` (OPTIONAL) — space-separated scope strings the RP requests, in its own
vocabulary. `realm` OPTIONAL; unknown parameters MUST be ignored.

### 7.3 Token endpoint

`POST <token_endpoint>` with `application/x-www-form-urlencoded`:

```
grant_type=urn:x-browserid:grant-type:assertion
assertion=<presentation bundle (access_cert~assertion~warrant~config_cert)>
```

The RP MUST verify the presentation per §5.3 / core §6 (which subsumes audience,
expiry, the two-path join, per-identity issuer authority, and the three fail-closed
status checks). A self-login uses the **same** bundle shape with `grantor == grantee`.

**Scopes:** the RP MUST NOT grant authority beyond the intersection of the warrant's
`scopes` and its own — the issued token is bounded by what the grantor signed. A
warrant without `scopes` is audience-authorized but scope-unqualified; whether that
maps to a default or a minimal scope set is RP policy (SHOULD be documented).

Success — `200`, OAuth-shaped:

```json
{ "access_token": "…", "token_type": "Bearer", "expires_in": 3600,
  "email": "dan@sandmill.org",
  "grantee": "attestor2@mingo.place",
  "scopes": ["post", "read"] }
```

`email` is the grantor (whom the action is attributed to); `grantee` is the actor of
record. For a self-login they are equal. Failure — `400` with
`{ "error": "unsupported_grant_type" | "invalid_grant", "error_description": "…" }`.

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
- **Domain separation:** the `typ` values (device cert / access request / access
  cert / warrant) MUST be enforced; a config cert signing a warrant must never be
  replayable as an access cert or assertion (different shape + `typ`).
- **Per-identity issuer authority:** the RP requires each of the two issuers to be
  authoritative for its own identity — the access-cert issuer for the grantee, the
  config-cert issuer for the grantor (core §6) — so a warrant signed by an IdP that
  is not authoritative for the grantor cannot attribute a write to it.
- **Fail-closed presentation:** the bundle join means a leaked access key + cert is
  unusable without a matching warrant for **this** audience, and a leaked warrant is
  useless without a matching IdP-minted access cert. "Forgot to check the warrant"
  is not expressible in a conforming verifier — the join does not complete without it.
- **Agent device-key leak:** the attacker can mint access certs (and raise consent
  requests) until the user revokes the **device cert**; abuse is attributable via
  the grantee identity + holder, and stops within one access-cert TTL (§4.3). Blast
  radius stays confined to the agent's `identities` — and, at RPs, to audiences with
  user-approved warrants.
- **Broker compromise:** the hosted broker stores warrants but does **not** sign
  them (the config cert does, client-side) and cannot mint access certs (the IdP
  does), so it can neither fabricate a user authorization nor forge a login.
- **Audience pinning:** the access request `domain` makes a mint for one IdP useless
  at another; `jti` prevents access-request replay; the warrant's `audience` makes a
  warrant for one RP useless at another.
- **Consent surface:** the §6.3 page is the trust boundary against consent-phishing.
  It MUST render the verified target origin (not only a friendly name), and approval
  MUST be deliberate. `code` is single-use, short-lived, ≥ 128-bit, rate-limited on
  poll.
- **Warrant privacy:** warrants are signed client-side by the config cert and never
  transit the IdP; the broker holds audience data in the pending request (deleted on
  delivery, §6.4) and the registry (user-only). No party other than the addressed RP
  ever holds a usable record of where an agent is authorized.
- **Revocation is fail-closed and threefold:** access cert (→ IdP), config cert
  (→ IdP), warrant (→ hosted broker) — all checked fail-closed (core §6).

## 9. Conformance

- An **IdP** conforms if it implements agent device-cert issuance (§4.1, gated by
  the user's device-grant) and the access-cert mint (§4.2) under §3's rules.
- A **broker** conforms if it additionally hosts the §6 consent flow and the warrant
  registry.
- An **RP** conforms if it implements §7.2–§7.3 with §5.3 / core §6 verification
  (four-object bundle, per-identity issuer authority, three fail-closed status
  checks); §7.4 is recommended.
- A **verifier** conforms only if it accepts exactly the four-object bundle — an
  access cert is never usable without its warrant and config cert.
