<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# browserid-ng — Protocol Specification (core)

> **Status: draft.** This is the standalone specification of the browserid-ng
> protocol: the actors, the credential artifacts they exchange, and how a relying
> party verifies a presentation. Two capabilities are layered as separate modules:
> agent provisioning & grant exchange, and SBO on-chain attribution (built on the
> offline verification of §6.3). A plain relying party needs neither.

## 1. Overview

browserid-ng is a decentralized identity protocol: a party proves control of an
**email identity** to a **relying party (RP)** by presenting a short-lived,
cryptographically signed **presentation bundle**, with no password and no central
login provider. The trust root is **DNSSEC** (§3): an IdP's signing key is
authenticated through the DNS hierarchy the domain already controls, not the Web
PKI. This makes discovery results **offline-verifiable** (RFC 9102 proofs), which
is what lets identities be attributed in trustless contexts (the attribution
module).

### 1.1 Actors

- **Identity** — an email address, `user@domain`; *who*, not who is acting.
- **Identity Provider (IdP)** — issues **device certs** to a holder it has
  authenticated and runs the **mint** that exchanges a device-signed request for a
  fresh-key **access cert** (§4). A domain that publishes the §3 discovery records
  is its own **primary IdP**; an email whose domain does not is served by a
  **fallback IdP** (§8). Every IdP MUST implement device-cert issuance (both
  purposes) and the mint (§7, §9).
- **Relying Party (RP)** — a site or service that accepts an identity by
  **verifying** a presentation bundle (§6).

### 1.2 Holders and roles

A cert acts for an **(identity, holder)** pair, not an identity alone. A **holder**
is an opaque handle for one credential-bearing party — a browser, an agent, a
service. Authorization attaches to the pair: the same identity, held by two
holders, can carry different permissions. A holder is opaque to verifiers; only a
warrant's holder-matcher reads it (§4.5). A warrant names two roles:

- **Grantor** — the (identity, holder) that **authorizes**, signing a warrant with
  a config cert; the write is attributed to the grantor's identity.
- **Grantee** — the (identity, holder) that **acts**, holding the access cert and
  signing the assertion. In a self-login grantor and grantee coincide; in a
  delegation they differ, and may belong to different IdPs (§5, §6).

### 1.3 Infrastructure: the broker

The **broker** is the user's agent (in the user-agent sense), not a party to any
identity claim. Its **client** component holds the user's keys on the device and
mediates the web login exchange (§7.3); its **hosted** component (browserid.me is
the reference) keeps the warrant registry and the revocation/status endpoints. A
hosted broker MAY additionally serve as a **fallback IdP** that an RP chooses to
accept or not (§8.1) — but that is a separate role; as a broker it verifies
nothing.

## 2. Cryptography & key formats

- All signatures are **Ed25519 (EdDSA)**. JWTs use `"alg": "EdDSA"`.
- Public keys are the raw 32-byte Ed25519 point. Two text encodings appear:
  - **base64url** (unpadded) — in JWT `public-key` claims and the `_browserid`
    DNS record.
  - **`ed25519:<hex>`** — the on-chain form (attribution module).
- A public key is a bare 32-byte value, **not a JWK** `{kty, crv, x}` object: with
  the algorithm fixed at Ed25519 protocol-wide, a JWK would only add redundant
  constants and an attacker-controllable `alg`/`crv`.

## 3. Discovery & the trust root

**The authenticated `_browserid` DNSSEC record is the required, sole trust root
for an IdP's identity key.**

- **`_browserid.<domain>` TXT**, DNSSEC-signed, carries the IdP's key:

  ```
  v=browserid1; public-key-algorithm=Ed25519; public-key=<base64url>; host=<optional>
  ```

  It MUST be fetched over an authenticated channel — **DNS-over-TLS**, EDNS `DO`
  bit set — and accepted only when the resolver's **AD** flag is set. `SERVFAIL`
  is treated as **Bogus → hard reject** (a broken DNSSEC chain is an attack
  signal, not a fall-through). An **insecure** (AD-unset) result means the
  domain is not a primary → the identity is handled via the broker (§8). The
  fallback broker's *own* key is likewise DNSSEC-resolved; a fallback without
  DNSSEC is a hard error.

- **`.well-known/browserid`** carries an IdP's **endpoints** (§3.1) and an optional
  host certificate (§4.4) — never a key. An IdP's identity key comes only from the
  DNSSEC record above.

### 3.1 Support document

`GET https://<domain>/.well-known/browserid` returns JSON:

| Field | Meaning |
|---|---|
| `authentication` | Path to the interactive authentication page (§7). |
| `provisioning` | Path to the provisioning page (§7). |
| `device-cert` | Path to the **batch device-cert issuance API** (session/interactive-authed): issues the user (`authentication`) + config (`authorization`) device certs. REQUIRED for conformance (§9). |
| `access-cert` | Path to the **headless access-cert mint API** (§7): device-signed access request → short-lived access cert. The device cert is the credential, so agents mint with no browser. REQUIRED for conformance (§9). |
| `device-authorization` | Path to the browser-facing device-authorization page — the login popup hand-off that gets a device its certs first-party. |
| `agent-device-authorization` | Optional. The device-authorization page's agent mode (merged provisioning): issues a **named-agent** device cert (an identity differing from the session's, e.g. a `+tag` sub-address). Absent ⇒ named agents unsupported here; "as-you" agents need no support. |
| `device-revoke` | Optional. Browser-facing device-**revocation** page so the **user** (never a registrar on its own authority) can revoke certs this IdP issued. Absent ⇒ no remote-initiated revocation (certs run to expiry). |
| `authority` | Optional delegation pointer to another domain's IdP. |

A domain opts out simply by publishing no records. The document carries no key —
the mint endpoint is published as `access-cert`, not `mint`.

## 4. Certificates

Every credential is an Ed25519 JWS whose `typ` domain-separates it. A verifier
MUST reject a token whose `typ` it does not recognize.

There is one certificate type — the **device cert** — factored along a
**`purpose` axis** plus an opaque **`holder`** id, both carried in the cert:

- **`purpose`** ∈ { `authentication` (mints access certs), `authorization`
  (signs warrants) } — the least-privilege axis: logging in ≠ authorizing.
- **`holder`** — an opaque id naming *which credential-bearing party* this cert
  acts as (a browser, an agent, a service), organized into holder namespaces via a
  `<ns>.<rand>` prefix (§4.5). A holder is opaque to verifiers; only a warrant's
  holder-matcher interprets it.

Both purposes share **one cert shape**; the two are named by shorthand:

| Shorthand | is a | purpose | signs | RP sees? |
|---|---|---|---|---|
| **auth cert** | device cert | authentication | access request → access cert | no |
| **config cert** | device cert | authorization | warrant | **yes** |

A verifier MUST reject an unknown `purpose` value and a missing/malformed
`holder` — fail-closed.

### 4.1 Device certificate (`browserid-device-cert-v1`)

An IdP-signed JWS certifying a **device key** for one or more identities. It is
**durable** (reference validity 90 days) and **never presented to an RP** — it
is the "logged-in device" credential; revoking it logs that device (or agent)
out.

| Claim | Meaning |
|---|---|
| `typ` | `browserid-device-cert-v1`. |
| `iss` | Issuing IdP domain (the identity's primary, or `browserid.me` fallback). |
| `iat`, `exp` | Validity window (reference: 90 days). |
| `purpose` | `authentication` \| `authorization`. |
| `holder` | Opaque broker-assigned id (§4.5) — which of the account's things this cert acts as. Copied into the access cert at mint. |
| `identities` | Array of emails (or single-`*` globs, e.g. `*`) this device may act for — all rooted at this IdP. MUST be non-empty. A bare `user@domain` entry also authorizes `user+tag@domain` sub-addresses (RFC 5233 subaddressing is a protocol rule, §4.6). |
| `public-key` | The certified device key (base64url Ed25519). |
| `status` | Optional revocation ref `{ "uri", "idx" }` (§6.3); revoking it logs the device/agent out. |

A single issuance request MAY return **several** device certs at once — e.g. an
`authentication` device cert for login together with a **config cert** for
authorizing warrants (§4.3). All carry the same holder for a browser device; an
agent gets its own holder in the `agents`/`services` namespace (§4.5).

### 4.2 Access certificate (`browserid-access-cert-v1`)

A short-lived (reference: 24 hours), **RP-facing** IdP-signed cert certifying a
**fresh** key — the key the assertion (§5) chains from. It is produced by the
**mint API** (§7): the device signs an **access request** with its
`authentication` device key and posts it; the IdP verifies the device cert
(own signature, unrevoked, in validity, identity in its list) and returns the
access cert. Because the certified key is fresh, the device cert never leaves
the device↔IdP channel; because every access cert is IdP-gated online, short
access certs stay meaningful, no session cookie is needed (survives ITP), and
agents mint headlessly.

**Access request (`browserid-access-request-v1`)** — device-signed:

| Claim | Meaning |
|---|---|
| `typ` | `browserid-access-request-v1`. |
| `iat`, `exp` | Short window (reference: 10 min). |
| `jti` | Single-use nonce (replay protection at the mint). |
| `domain` | Target IdP domain (audience pinning). |
| `identity` | Which identity to mint for (∈ the device cert's `identities`). |
| `holder` | The holder the minted access cert must carry — MUST equal the device cert's holder; the mint MUST NOT let the requester choose a different value. |
| `access-key` | The fresh key to certify (never the device key). |

**Access cert claims:**

| Claim | Meaning |
|---|---|
| `typ` | `browserid-access-cert-v1`. |
| `iss` | Issuing IdP (MUST equal the identity's IdP; conformance-checked at §6). |
| `iat`, `exp` | Short window (reference: 24 h). |
| `identity` | The certified email. |
| `holder` | Copied verbatim from the issuing device cert at mint (the isolation guarantee: the requester cannot choose or forge it). |
| `public-key` | The certified **fresh** access key. |
| `status` | Optional revocation ref, rooted at the **issuing device's** status index (revoking one device kills its access certs, not the whole identity). |

### 4.3 Config certificate (`browserid-device-cert-v1`, `purpose: authorization`)

A **config cert** is a device cert whose `purpose` is `authorization`; it signs
**warrants** (§5). It is **device-resident and non-extractable** (like the access
key), issued by the identity's IdP **alongside the auth cert at login** (one batch
request yields both). Unlike the auth cert, the config cert **is presented to the
RP** (it is the object the warrant's signature verifies against).

**A config cert MUST be issued by an IdP authoritative for the identities it may
grant for.** The config cert can sign a warrant only for a `grantor` its
`identities` cover (with subaddressing, §4.6), and at verification (§6) the RP
requires `config_cert.iss` to be authoritative for that grantor's domain. This
confines a warrant to identities its issuer vouches for.

### 4.4 Host certificate (optional intermediate)

> **Planned extension — not yet implemented.** The design is settled; this
> section specifies the target.

A **host certificate** carries `principal = { "host": "<domain>" }` and asserts
that a key `K_host` is authoritative to issue certs for `<domain>`. A host cert
**MUST be signed by the DNSSEC-published key `K_dns`** (not self-signed).

This yields an optional chain on either issuer-signed object (the access cert or
the config cert):

```
K_dns  →  (optional) host cert (K_host)  →  access cert  →  assertion
```

Use it to separate the **DNS admin** (holds `K_dns`, rarely used) from the
**IdP operator** (holds `K_host`, signs certs), and to rotate the operational
key by issuing a new host cert **without a DNS change**. Simple deployments omit
it and sign directly with `K_dns`. Host certs carry **no endpoints** (endpoints
stay in the support document, §3.1).

### 4.5 Holders

A **holder** is an opaque, high-entropy id — carried by every device cert and
copied verbatim into the access cert at mint — naming which credential-bearing
party a cert acts as. Holders sit in user-private namespaces (`browsers` /
`agents` / `services`) via a randomized `<ns>.<rand>` prefix, assigned by the
client broker and passed through by IdPs verbatim. One browser gets one holder,
reused across every identity on that device; a non-browser party (agent, service)
gets a holder it **cannot choose**, so separate parties cannot name each other's.
A warrant ranges over a holder through a **matcher** (§5) — the only thing that
reads holder structure. A holder is at most 128 bytes.

### 4.6 Subaddressing (authorization only)

Owning `user@domain` implies owning `user+tag@domain` for any `tag` (RFC 5233
sub-addressing). This applies to **authorization only**: a config cert
authoritative for `user@domain` may sign a warrant whose **grantor** is
`user+tag@domain`, with no per-tag cert.

It does **not** apply to **authentication**: an auth cert for `user@domain` mints
access certs for `user@domain` *exactly*. Acting as `user+tag@domain` requires an
auth cert issued for that sub-identity (e.g. an agent provisioned at
`user+agent@domain`). So a user delegates to a named sub-identity by having one
issued — not by an existing device silently speaking as it.

## 5. Assertions, warrants & the presentation bundle

- **Assertion** — a short-lived JWT signed by the **fresh access key** (the key
  certified by the access cert, §4.2), claims:

  | Claim | Meaning |
  |---|---|
  | `aud` | The RP origin the assertion is for. |
  | `exp` | Expiry (short). |

- **Warrant (`browserid-warrant-v1`)** — the authorization object, signed by a
  **config cert** (§4.3). It authorizes a **`grantor` → `grantee`** delegation
  over a **`holder`-matcher → `audience` [+ `scopes`]** — e.g. "`user@sandmill.org`
  (grantor) authorizes `poster@mingo.place` (grantee), holder matching `*`, to act
  at `https://api.mingo.place/` with scopes `post read`". A warrant is **always**
  present at the RP (self-logins carry one too, where grantor == grantee).

  | Claim | Meaning |
  |---|---|
  | `typ` | `browserid-warrant-v1`. |
  | `iat`, `exp` | Validity window (reference: 90 days). |
  | `grantor` | The identity the write is **attributed** to (the effective author). The signing config cert MUST be authoritative for it (§4.3). |
  | `grantee` | The identity that **acts** — mints the access cert and signs. MUST equal the presented access cert's identity. Equals `grantor` for an "as-you" grant; differs for delegated on-behalf grants. |
  | `holder` | A **matcher** — `*` (any holder), `<ns>.*` (a namespace), or `<id>` (one holder) — checked against the **grantee's** access-cert holder (anti-fungibility). |
  | `audience` | **Exactly one** RP audience (exact string match, same normalization as assertion `aud`). |
  | `scopes` | OPTIONAL array of opaque strings, interpreted only by the RP. |
  | `status` | Optional revocation ref, rooted at the **hosted broker's warrant registry** (§6.3). |

  A warrant is **over the grantor/grantee + holder-matcher, not bound to any
  device/access key**, so it is signed **once** by a config cert, **stored** in
  the hosted broker registry, and **reused device-agnostically**: any device whose
  holder the matcher covers, that can mint an access cert for the grantee, presents
  the stored warrant alongside it. A warrant is long-lived and **not a secret** — a
  leaked warrant is useless without a matching IdP-minted access cert, so a user
  may publish an individual warrant (the on-chain attribution module publishes it
  as part of the verification bundle). The only concern is **bulk**
  publication/enumeration, which in aggregate discloses which sites and services a
  user uses.

  **Grantor and grantee are independent identities.** In a self-login they
  coincide. In a delegation they differ — and may belong to **different IdPs**: an
  agent at `agent@a.example` (grantee, with its own access cert from `a.example`)
  can act on behalf of `owner@b.example` (grantor, whose config cert is from
  `b.example`). The write is attributed to the grantor; the grantee is the actor
  of record. This is safe because each of the two objects is rooted independently
  in an IdP authoritative for **its own** identity (grantor↔config cert,
  grantee↔access cert; §6), so an IdP can never authorize a grant for an identity
  it does not vouch for.

- **Presentation bundle** — the tilde-joined **four objects** presented to an
  RP, uniform for self and delegated logins:

  ```
  access_cert ~ assertion ~ warrant ~ config_cert
  ```

  The auth cert is **never** presented. A verifier MUST reject
  a bundle that is not exactly these four objects, in this order — the parse is
  fail-closed.

## 6. Verification

A verifier is given a presentation bundle and an expected **audience**, and either
rejects it or returns the identity it establishes. Verification joins **two
independent DNSSEC-rooted paths** — one through the access cert (the grantee's
actor credential) and one through the config cert (the grantor's authorization) —
and attributes the result to the grantor. (The `browserid.me` broker offers a
hosted HTTP verifier for RP convenience; that endpoint is a service, not part of
this protocol.)

### 6.1 Verification algorithm

The join is **(grantee = access-cert identity, holder ∈ matcher, audience)**, with
the result attributed to the **grantor**: the access cert says this fresh key
speaks for the grantee at this audience, and the warrant says the grantor
authorizes the grantee for this audience + scopes, signed by an `authorization`
config cert an IdP issued for the grantor. The two issuers (access-cert / grantee,
config-cert / grantor) may differ.

1. Parse the bundle into exactly `access_cert ~ assertion ~ warrant ~
   config_cert` (§5). Reject any other shape, and any object bearing an
   unrecognized `typ` or `purpose`, or a missing/malformed `holder` — fail-closed.
2. **Per-identity issuer authority.** Resolve `access_cert.iss` and
   `config_cert.iss` **via the authenticated DNSSEC record** (§3) — one resolution
   if they are equal, otherwise two. The verifier MUST require each issuer to be
   **authoritative for its own identity**: `access_cert.iss` for the grantee's
   domain and `config_cert.iss` for the grantor's domain (the domain's DNSSEC
   primary, or an RP-accepted fallback for a no-primary domain; §8.1). This is what
   makes cross-issuer delegation safe: an issuer can only ever vouch for an identity
   in a domain it is authoritative for. Keys come only from DNSSEC (§3).
   *(The optional host-cert intermediate (§4.4) hooks in here when implemented.)*
3. Verify the **access cert** and the **config cert** under their respective IdP
   keys; reject if either is expired.
4. Verify the **assertion** under the access cert's fresh `public-key`; check
   `aud` == the RP audience and not expired.
5. Verify the **config cert authorizes the grantor**: `purpose == authorization`
   and its `identities` match `warrant.grantor`.
6. Verify the **warrant** under the config cert's `public-key`; check it is
   unexpired and that the join holds: `warrant.grantee == access_cert.identity`,
   `warrant.holder` (matcher) covers `access_cert.holder`, and `warrant.audience`
   == the RP audience.
7. **Three fail-closed status authorities.** Check the revocation ref on each of
   the three objects that carries one — the **access cert** (→ its IdP, per-device
   index), the **config cert** (→ its IdP), and the **warrant** (→ hosted broker
   registry). All three checks are **fail-closed** (§6.3).
8. Return the attributed identity (grantor), the grantee (actor of record), the
   grantor and grantee issuers, the `holder`, and the scopes.

### 6.2 Offline verification with detached DNSSEC proofs

Because the trust root is DNSSEC (§3), a certificate or backed assertion can be
verified **with no live network fetch** when accompanied by a **detached DNSSEC
proof**: an RFC 9102 proof of the issuer's `_browserid` record, carrying the
published key and its RRSIG validity window. The verifier validates the proof
against the IANA root, extracts the issuer key, and proceeds as in §6.1. This
enables verification in archives, audits, and ledger/trustless contexts where the
IdP is not reachable at verification time — something a live `.well-known` TLS
fetch cannot provide.

The proof is self-contained; how a consumer transports, caches, or refreshes it,
and roots identities in its own trust model, is out of scope here. The on-chain
consumer is the **attribution module**.

### 6.3 Certificate status (fast revocation)

There are **three revocation authorities**, one per RP-facing object that
carries a `status` ref, and the verifier checks **all three fail-closed** (§6.1
step 7):

- the **access cert** → its **IdP**, rooted at the **issuing device's** status
  index (revoking one device kills its access certs, not the whole identity);
- the **config cert** → its **IdP**;
- the **warrant** → the **hosted broker's warrant registry** (per-grant index,
  so the user revokes one audience grant without touching the others).

Because every access cert is **IdP-gated online at mint** (§4.2), the
authentication path is already fresh at issuance; the status refs give sub-TTL
revocation of live sessions. A ref carries:

```json
"status": { "uri": "https://<authority>/.well-known/browserid-status", "idx": 42 }
```

- `uri` names a **signed status list** published by the authority; `idx` is the
  credential's position in it. Issuers allocate **one index per device** for
  access certs (stable across re-mints, so one bit kills a device's outstanding
  access certs) and the hosted broker allocates **one per warrant grant**
  (stable across reissues). The list format follows the
  **IETF OAuth Token Status List** mechanism in shape — 1 bit per entry,
  LSB-first, zlib-compressed, base64url — carried in this protocol's usual
  claim-level-`typ` JWS (`browserid-status-list-v1`, claims `iss`/`sub` (the
  list URI)/`iat`/`ttl`/`status_list{bits,lst}`).
- Verifiers SHOULD fetch and cache the list (reference cache: 5 minutes) and
  treat a set bit as **revoked → reject**. Fetching the whole list reveals
  nothing about which subject is being checked (no OCSP-style privacy leak).
- All three checks are **fail-closed**: if a status list is unreachable the
  verifier MUST reject rather than honor the object until `exp`. (This is
  stricter than a general-purpose cache: the three authorities are the
  revocation backbone of the model, so an unreachable authority is treated as
  "cannot prove unrevoked → reject.")
- Detached-proof consumers (§6.3) can pair a bundle with a **status-list
  snapshot**, giving offline verification a defined freshness window ("valid
  as of T").

Layered with short TTLs and IdP-gated online minting (§4.2), this yields:
instant revocation at the mint (a revoked device cert mints no new access cert),
≤ cache-window for live sessions at status-checking RPs, and fail-closed
rejection if any of the three authorities is unreachable.

## 7. IdP operations

An IdP produces the credentials the rest of the protocol consumes. Every IdP MUST
implement two operations (§9); a holder — a browser, an agent, a service — is just
a client of them.

### 7.1 Device-cert issuance

The IdP authenticates the holder, then signs one or more **device certs** (§4.1)
for keys the holder generated locally (ideally non-extractable, so a private key
never leaves the holder). A single authenticated request MAY return a batch — an
`authentication` device cert together with a `authorization` config cert — so a
login yields both the ability to mint and the ability to authorize in one step.
How the holder authenticates is the IdP's choice (an interactive login for a
browser; the **agent device-grant** below for an agent).

**Agent device-grant.** An agent generates its keypair off-device and cannot
authenticate to the IdP itself. Instead the **user authorizes** the issuance: the
agent's public key reaches the IdP through the user's session, the user approves
the constraints (which identities, the holder — assigned in the user's
`agents`/`services` namespace, which the agent cannot choose — and the validity),
and the IdP signs the agent's device cert. (Detailed in the agent-provisioning
module.)

### 7.2 The access-cert mint

The holder signs an **access request** (§4.2) with its `authentication` device
key and posts it to the mint endpoint. The IdP verifies the device cert online —
own signature, unrevoked, in validity, identity in its list — and returns a
short-lived **access cert** certifying the request's fresh key. The IdP MAY refuse
even a nominally-valid device cert (abuse or compromise), in which case the holder
re-authenticates.

Minting online on a fresh key each time is what lets a credential be **cookie-free**
(no session cookie to lose to browser storage policies) and lets an **agent mint
headlessly**, with no browser and no user present.

### 7.3 The web login exchange

For a browser RP, obtaining a presentation is an interactive exchange, kept
**first-party** so signing keys never leave the origin that holds them:

1. The RP invokes a **login mediator** — today a small script it includes; a
   native browser federated-login API could serve the same role. The invocation
   carries an optional **`acceptedFallbacks`** list (§8.1): the fallback IdPs the
   RP will accept for a no-primary email. It is a call argument, not fetched from
   the RP.
2. The mediator opens the identity flow in a **first-party popup**. There the
   holder authenticates to its IdP, obtains its device certs (§7.1), mints an
   access cert (§7.2), and signs the assertion and warrant — each signing step
   performed in the origin that holds the corresponding key.
3. The mediator returns the **presentation bundle** (§5) to the RP, which verifies
   it (§6).

`acceptedFallbacks` only routes the exchange and lets it fail fast; it grants
nothing, because the RP's verifier independently enforces its trusted-issuer set
(§8.1).

## 8. Fallback IdPs

An email whose domain has no primary IdP (§7) is vouched for by a **fallback
IdP** — a party that verifies control of the email (by an SMTP challenge, or
another supported proof of control where applicable) and then issues **device
certs** (both purposes) and runs the **mint API** for it,
all under its own `iss`, published under its own `_browserid` DNSSEC key, so
every object verifies through the same DNSSEC-rooted path (§3) as any primary.
`browserid.me` is the reference fallback and the **hosted broker** — it also
hosts the **warrant registry / revocation UI / status endpoints** (§6.3). It is a
convenience, **not a mandatory party**: any DNSSEC-publishing domain can run a
fallback, and an RP chooses which fallbacks it accepts (§8.1).

**Conformance boundary.** A fallback serves **only no-primary domains**. A
fallback-issued device/access/config cert for a domain that **has** a primary
**fails verification** — the primary is DNSSEC-authoritative for its own
identities. So the per-identity issuer authority check (§6.1 step 2) and the
accepted-set enforcement (§6.1) together prevent a fallback from vouching over a
primary's head — applied independently to the grantee (access cert) and the
grantor (config cert).

### 8.1 RP-selected fallbacks

A fallback IdP that can verify an email can issue a login-capable cert for it,
so accepting a fallback is a trust decision — and it is **the RP's** to make,
not one browserid.me imposes:

- An RP declares the set of **fallback IdPs it accepts** (by issuer domain).
  A cert on the no-primary path is acceptable to that RP only if its `iss` is
  in the set. This is what lets an RP adopt browserid-ng **without being forced
  to trust `browserid.me`** as an identity authority.
- **Primaries are always accepted.** A domain's primary is DNSSEC-authoritative
  for its own users (§3, §7); the accepted-fallbacks set governs only the
  no-primary path. (v1 has no knob to restrict primaries.)
- **Declaration is a call argument, not discovery.** The RP passes
  `acceptedFallbacks: [<issuer-domain>, …]` when it invokes the login flow
  (§7) — the same shape a browser's native federated-login API consumes, so
  the mediator/polyfill and a future native implementation read one argument.
  It is **not** fetched from an RP `.well-known`.
- **The argument is advisory; enforcement is at verify (§6.1).** Its purpose is
  to route the user to a fallback the RP will accept and to fail fast otherwise
  (rather than verify-then-reject). A wrong or spoofed argument can only cause a
  *failed* login — never an accepted one — because the RP's verifier
  independently rejects any `iss` outside its trusted set. The RP MUST derive
  the client argument and the verifier's trusted-issuer set from one config so
  they cannot drift.
- **Default.** Absent the argument, the accepted set is `{browserid.me}` (the
  reference fallback). An explicit empty set means primaries only. An RP that
  wants other fallbacks but not browserid.me passes a list without it.
- **Cross-RP cert reuse is issuer-gated.** A cached fallback cert is reused only
  at RPs that accept its `iss`; otherwise the mediator re-verifies the email
  through an accepted fallback (cached per `(email, iss)`). Primaries reuse
  freely.

`browserid.me` remains a pinned **broker trust anchor** for on-chain
attribution (see the attribution module; `/sys/trust/brokers`) independent of
any RP's accepted-fallbacks choice.

> **v1 scope.** Only `browserid.me` is deployed as a fallback today, so v1's
> concrete effect is that an RP may *decline* it (leaving only primary logins
> there) while the protocol — accepted-set argument, verifier enforcement,
> issuer-carried certs, reuse gating — lets anyone stand up another fallback
> with no further protocol change.

## 9. Conformance

Every IdP **MUST** implement **device-cert issuance for both purposes**
(`authentication` and `authorization`) and the **access-cert mint API** (§7).
No-primary domains are served by the fallback IdP (browserid.me); a domain
**with** a primary MUST have that primary implement the full API — the fallback
cannot issue on its behalf (§8). So login and agents ride one required API.

A **verifier** conforms only if it (a) accepts exactly the four-object bundle,
(b) enforces **per-identity issuer authority** — the access-cert issuer
authoritative for the grantee's identity and the config-cert issuer for the
grantor's identity (§6.1 step 2) — and (c) checks all **three status authorities
fail-closed** (§6.1).

## 10. Layered modules

- **[Agent provisioning, warrants & grant exchange](./agent-provisioning-and-grant-api.md)** —
  how the IdP issues an agent device cert (with a broker-assigned holder in the
  `agents`/`services` namespace) after the user authorizes it (device-grant), how
  the agent **mints access certs headlessly**, and how a config-cert-signed
  **warrant** confines it to the audiences and scopes its principal approved.
  Defines the consent + grant-exchange surfaces that produce and consume the
  `access_cert~assertion~warrant~config_cert` bundle §5/§6 verify.
- **On-chain attribution** — attributing an email identity to an `ed25519:` key on
  a ledger, built on the offline-verification primitive (§6.3). Specified
  separately as the attribution module: its concepts are ledger-specific, and it
  depends on this core protocol, not the reverse.

## Appendix A — Lineage

browserid-ng descends from Mozilla's BrowserID/Persona and keeps its familiar
building blocks — **JWT + Ed25519** signatures and the **tilde-joined**
presentation (§2, §5). It departs in the parts that matter for a decentralized,
agent-capable, offline-verifiable system: **DNSSEC** replaces Web-PKI as the trust
root (§3); the RP-facing credential is a **four-object presentation bundle** minted
on a **fresh key online**, rather than a long-lived identity certificate (§4–§5);
authorization is carried by **holder-scoped warrants** with grantor/grantee
delegation (§5); and there is no reliance on a browser-native identity API — the
web login exchange is a first-party mediator (§7.3). This appendix is background;
every normative rule lives in the sections above.

