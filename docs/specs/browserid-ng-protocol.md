<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# browserid-ng — Protocol Specification (core)

> **STATUS: DRAFT.** Canonical spec for the browserid-ng protocol, authored per
> bean `browserid-ng-v9rz`. Derived from Mozilla's BrowserID/Persona
> (`mozilla/id-specs`, archived 2022) with deliberate departures — see
> [`browserid-ng-divergence-analysis.md`](./browserid-ng-divergence-analysis.md).
>
> This spec describes the **device-cert model** (see
> `docs/design/browserid-end-to-end-flow.md`): durable IdP-signed **device
> certs** (never seen by the RP) that mint short-lived, fresh-key **access
> certs**, plus **config certs** that sign **warrants**. The built types are in
> `browserid-core/src/device.rs`; the frozen wire vectors in
> `test-vectors/device-cert-v1.json`. The optional **§4.4 host certificate**
> intermediate remains a planned extension (bean `browserid-ng-dff5`).
>
> Layered on this core: [agent provisioning & grant exchange](./agent-provisioning-and-grant-api.md)
> (this repo), and SBO on-chain attribution (in the **sbo** repo, built on §6.3).
> A plain relying party needs neither.

## 1. Overview

browserid-ng is a decentralized identity protocol: a person (or an agent acting
for one) proves control of an **email identity** to a **relying party (RP)** by
presenting a short-lived, cryptographically signed **assertion**, with no
password and no central login provider.

The actors:

- **Identity** — an email address, `user@domain`.
- **Identity Provider (IdP)** — issues **device certs** for a device it has
  authenticated, and runs the **mint API** that exchanges a device-signed
  request for a fresh-key **access cert** (§4). A domain that publishes the
  discovery records below is its own **primary IdP** for its users. Domains that
  don't are served by a **broker** (§8). **Every IdP MUST implement device-cert
  issuance (both purposes) and the access-cert mint API** (§7, §9).
- **Relying Party (RP)** — a site/app that accepts an identity by **verifying**
  an assertion (§6).

The trust root is **DNSSEC** (§3): an IdP's signing key is authenticated through
the DNS hierarchy the domain already controls, not the Web PKI. This makes
discovery results **offline-verifiable** (RFC 9102 proofs), which is what lets
identities be attributed in trustless contexts (see the attribution module).

### Inheritance from BrowserID

The **JWT + Ed25519 building blocks** and the **tilde-joined** presentation are
kept from Mozilla BrowserID, so the wire encoding is familiar. But the credential
**structure** is deliberately re-shaped into the device-cert model: instead of one
`certificate~assertion` chain rooted on a long-lived identity cert, an RP receives
a **four-object bundle** — `access_cert~assertion~warrant~config_cert` (§5) — and
the long-lived credential (the **device cert**) never leaves the device/IdP
channel. The **trust root** (DNSSEC vs Web PKI), the **crypto** (Ed25519 vs RSA),
the **browser integration** (first-party pages + postMessage vs the shimmed
`navigator.id`), and the **fresh-key online mint** (no long-lived RP-facing
identity cert) are deliberate departures.

## 2. Cryptography & key formats

- All signatures are **Ed25519 (EdDSA)**. JWTs use `"alg": "EdDSA"`.
  *(Departure from BrowserID's RSA/RS256.)*
- Public keys are the raw 32-byte Ed25519 point. Two text encodings appear:
  - **base64url** (unpadded) — in JWT `public-key` claims and the `_browserid`
    DNS record.
  - **`ed25519:<hex>`** — the SBO/on-chain form (attribution module).
- We deliberately **do not use JWK**. A key is a 32-byte value, not a
  `{kty,crv,x}` object.

Reference: `browserid-core/src/keys.rs`.

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
  broker's *own* key is likewise DNSSEC-resolved, so **no path — primary or
  fallback — trusts a `.well-known` key**; a broker without DNSSEC is a hard
  error. Reference: `browserid-core/src/dns.rs`, `browserid-broker/src/dns_fetcher.rs`,
  `browserid-broker/src/fallback_fetcher.rs`.

- **A key presented only via `.well-known/browserid` is NOT trusted.** There is
  no dual path: accepting either DNSSEC or Web-PKI trust would reduce security
  to the weaker link (a single mis-issued TLS certificate would forge an
  identity). This closes that downgrade.

- **`.well-known/browserid` is retained for *endpoint discovery*** (§3.1), and
  to deliver an optional host certificate (§4.4). It is not a trust root; every
  key it references chains back to the DNSSEC record.

### 3.1 Support document

`GET https://<domain>/.well-known/browserid` returns JSON:

| Field | Meaning |
|---|---|
| `public-key` | The IdP key. **Advisory only** — MUST match the DNSSEC record; the DNSSEC value is authoritative. |
| `authentication` | Path to the interactive authentication page where a device obtains its device cert(s) (§7). |
| `provisioning` | Path to the device-cert issuance endpoint (§7) — including the agent device-grant hand-off. |
| `mint` | Path to the **access-cert mint API** (§7): device-signed access request → short-lived access cert. REQUIRED for conformance (§9). |
| `authority` | Optional delegation pointer to another domain's IdP. |

*(Departures from BrowserID: the former `disabled` field is **removed** — a
domain opts out by publishing no records; and `public-key` here is no longer a
trust source.)* Reference: `browserid-core/src/discovery.rs`,
`browserid-broker/src/routes/well_known.rs`.

## 4. Certificates

Every credential is an Ed25519 JWS whose `typ` domain-separates it. A verifier
MUST reject a token whose `typ` it does not recognize. Reference:
`browserid-core/src/device.rs`; frozen wire vectors `test-vectors/device-cert-v1.json`.

The model factors a credential along **two orthogonal axes carried in the cert**:

- **`purpose`** ∈ { `authentication` (mints access certs), `authorization`
  (signs warrants) } — the least-privilege axis: logging in ≠ authorizing.
- **`subject`** ∈ { `user`, `agent` } — which *kind* of identity it acts for,
  the same axis a warrant ranges over.

Verifiers reject unknown `purpose`/`subject` values (serde rejects unknown
variants — fail-closed).

| Shorthand | purpose | subject | signs | RP sees? |
|---|---|---|---|---|
| **user cert** | authentication | user | access request → access cert | no |
| **agent cert** | authentication | agent | access request → access cert | no |
| **config cert** | authorization | user \| agent | warrant | **yes** |

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
| `subject` | `user` \| `agent`. |
| `identities` | Array of emails (or single-`*` globs, e.g. `dan+*@sandmill.org`, `*`) this device may act for — all rooted at this IdP. MUST be non-empty. |
| `public-key` | The certified device key (base64url Ed25519). |
| `status` | Optional revocation ref `{ "uri", "idx" }` (§6.4); revoking it logs the device/agent out. |

A single issuance request MAY return **several** device certs at once — e.g. a
**user cert** (authentication+user) for login together with one or more **agent
certs** (authentication+agent). A **config cert** is a device cert with
`purpose: authorization` (§4.3).

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
| `subject` | `user` \| `agent`. |
| `access-key` | The fresh key to certify (never the device key). |

**Access cert claims:**

| Claim | Meaning |
|---|---|
| `typ` | `browserid-access-cert-v1`. |
| `iss` | Issuing IdP (MUST equal the identity's IdP; conformance-checked at §6). |
| `iat`, `exp` | Short window (reference: 24 h). |
| `identity` | The certified email. |
| `subject` | `user` \| `agent`. |
| `public-key` | The certified **fresh** access key. |
| `status` | Optional revocation ref, rooted at the **issuing device's** status index (revoking one device kills its access certs, not the whole identity). |

### 4.3 Config certificate (`browserid-device-cert-v1`, `purpose: authorization`)

A **config cert** is a device cert whose `purpose` is `authorization`; it signs
**warrants** (§5). It is **device-resident and non-extractable** (like the
access key), issued by the identity's IdP **alongside the user cert at login**
(one batch request yields both). Unlike the authentication device cert, the
config cert **is presented to the RP** (it is the object the warrant's signature
verifies against).

`subject: user` is a self-scoped config cert (authors warrants only for the
user's own logins); `subject: agent` authorizes only agents.

**A config cert MUST be issued by the identity's own IdP.** At verification
(§6) the RP checks `config_cert.iss == access_cert.iss`, i.e. both are the
identity's IdP, DNSSEC-rooted and subject to the same primary/fallback
conformance. Without this binding an RP would accept a warrant signed by *any*
`authorization` cert from *any* IdP — a privilege-escalation hole.

### 4.4 Host certificate (optional intermediate)

> **Planned extension — not yet implemented** (bean `browserid-ng-dff5`). The
> design is settled; this section specifies the target.

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

## 5. Assertions, warrants & the presentation bundle

- **Assertion** — a short-lived JWT signed by the **fresh access key** (the key
  certified by the access cert, §4.2), claims:

  | Claim | Meaning |
  |---|---|
  | `aud` | The RP origin the assertion is for. |
  | `exp` | Expiry (short). |

- **Warrant (`browserid-warrant-v1`)** — the authorization object, signed by a
  **config cert** (§4.3). It authorizes an **(`identifier`, `subject`) →
  `audience` [+ `scopes`]** — e.g. "`dan+agent@sandmill.org`, subject `agent`,
  may act at `https://api.mingo.place/` with scopes `post read`". A warrant is
  **always** present at the RP (user logins carry one too, not just agents).

  | Claim | Meaning |
  |---|---|
  | `typ` | `browserid-warrant-v1`. |
  | `iat`, `exp` | Validity window (reference: 90 days). |
  | `identifier` | The email the warrant authorizes. |
  | `subject` | `user` \| `agent`. |
  | `audience` | **Exactly one** RP audience (exact-match, same normalization as assertion `aud`). |
  | `scopes` | OPTIONAL array of opaque strings, interpreted only by the RP. |
  | `status` | Optional revocation ref, rooted at the **hosted broker's warrant registry** (§6.4). |

  A warrant is **over the identifier + subject, not bound to any device/access
  key**, so it is signed **once** by a config cert, **stored** in the hosted
  broker registry, and **reused device-agnostically**: any device that can mint
  an access cert for that identity presents the stored warrant alongside it.
  A warrant is long-lived and **not a secret** — a leaked warrant is useless
  without a matching IdP-minted access cert — but warrants SHOULD NOT be
  intentionally published (in aggregate they disclose which sites a user uses).

- **Presentation bundle** — the tilde-joined **four objects** presented to an
  RP, uniform for user and agent logins:

  ```
  access_cert ~ assertion ~ warrant ~ config_cert
  ```

  The authentication device cert is **never** presented. A verifier MUST reject
  a bundle that is not exactly these four objects, in this order — the join is
  fail-closed. `AccessPresentation::parse` rejects anything but four
  `~`-separated segments.

Reference: `browserid-core/src/device.rs`
(`AccessPresentation`), `browserid-core/src/assertion.rs`.

## 6. Verification

### 6.1 Verifier API

`POST /verify` with `{ "assertion": <presentation-bundle>, "audience": <origin> }`
returns the verified identity (email), subject, and scopes on success. The
`assertion` field carries the **four-object bundle**
`access_cert~assertion~warrant~config_cert` (§5); the field name is retained for
compatibility. Reference: `browserid-broker/src/routes/verify.rs`.

An RP's verifier holds a **trusted-issuer set** — the primaries and fallback
IdPs (§8.1) it accepts — and MUST reject an assertion whose `iss` is not in it
(the reference `Verifier` does this: `trust_issuer` /
`trust_issuer_from_well_known`, rejecting an untrusted issuer). This is the
authoritative enforcement of an RP's accepted-fallbacks policy; the client-side
`acceptedFallbacks` argument (§8.1) is only a routing hint and grants nothing.

### 6.2 Verification algorithm

Verification is a **two independent DNSSEC-rooted paths, joined by
(identity, subject, audience)** — the access cert (→ this fresh key speaks for
identity X, subject S, at this audience) and the warrant (→ X, subject S,
authorized for this audience + scopes, signed by an IdP-issued `authorization`
config cert for X). Reference: `AccessPresentation::verify` in `device.rs`.

1. Parse the bundle into exactly `access_cert ~ assertion ~ warrant ~
   config_cert` (§5). Reject any other shape, and any object bearing an
   unrecognized `typ`, `purpose`, or `subject` — fail-closed.
2. **Config-cert issuer binding.** Require `config_cert.iss == access_cert.iss`.
   Both MUST be the **identity's own IdP** — otherwise an RP would trust a
   warrant signed by any authorization cert from any IdP (privilege escalation).
3. Resolve that IdP's key **via the authenticated DNSSEC record** (§3) — one
   resolution, since the two issuers are now equal. No `.well-known` key trust;
   no dual path. The resolver decides which issuers it trusts (DNSSEC primary,
   or an accepted fallback for a no-primary domain; §8.1). *(The optional
   host-cert intermediate (§4.4) hooks in here when implemented.)*
4. Verify the **access cert** and the **config cert** under that IdP key; reject
   if either is expired.
5. Verify the **assertion** under the access cert's fresh `public-key`; check
   `aud` == the RP audience and not expired.
6. Verify the **config cert authorizes this login**: `purpose == authorization`
   and its `identities` match `access_cert.identity`.
7. Verify the **warrant** under the config cert's `public-key`; check it is
   unexpired and that the join holds: `warrant.identifier == access_cert.identity`,
   `warrant.subject == access_cert.subject`, and `warrant.audience` == the RP
   audience.
8. **Three fail-closed status authorities.** Check the revocation ref on each of
   the three objects that carries one — the **access cert** (→ its IdP, per-device
   index), the **config cert** (→ its IdP), and the **warrant** (→ hosted broker
   registry). All three checks are **fail-closed** (§6.4). (`device.rs` surfaces
   the three refs on `VerifiedAccess`; the network check lives in the RP-side
   verifier.)
9. Return the certified email, subject, scopes, and issuer.

This collapses the former well-known-vs-DNSSEC branching into one path
(`verifier.rs`), now joining two DNSSEC-rooted objects rather than following one
embedded chain.

### 6.3 Offline verification with detached DNSSEC proofs

Because the trust root is DNSSEC (§3), a certificate or backed assertion can be
verified **with no live network fetch** when it is accompanied by a **detached
DNSSEC proof**: an RFC 9102 proof for the issuer's `_browserid` record, carrying
the published key and its RRSIG validity window. The verifier validates the
proof against the IANA root, extracts the issuer key, and proceeds as in §6.2
using that key in place of a live DNS lookup.

This is the capability Web-PKI discovery cannot provide — a `.well-known` fetch
is a live TLS transaction, not a portable artifact — and it is the reason
browserid-ng roots trust in DNSSEC. It enables verification in archives, audits,
and ledger/trustless contexts where the IdP is not reachable at verification
time.

The proof is a self-contained blob; how a consumer transports, caches, or
refreshes it, and how it roots identities in its own trust model, is out of
scope for the core protocol. The on-chain consumer is specified separately — see
**SBO Attribution Specification** in the sbo repo, which layers ledger-specific
identity rooting and trust anchors on this primitive.

### 6.4 Certificate status (fast revocation)

> **Implemented** (bean `browserid-ng-egr7`): the broker allocates indices,
> publishes `/.well-known/browserid-status`, and checks its own credentials
> authoritatively at `/verify`; `browserid-rp` ships a cached checker
> (`StatusCache`). Federated IdPs adopt it by allocating indices at issuance
> and publishing their own list.

There are **three revocation authorities**, one per RP-facing object that
carries a `status` ref, and the RP-side verifier checks **all three
fail-closed** (§6.2 step 8):

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

## 7. Primary IdP & browser integration

**Every IdP MUST implement device-cert issuance (both `authentication` and
`authorization` purposes) and the access-cert mint API** (§9). Login and agents
ride one required API — the browser is just one device among many.

browserid-ng does **not** use the shimmed `navigator.id` API. Instead:

- First-party **`/auth`** (authentication) and **`/provision`** pages, with
  `authentication_api.js` / `provisioning_api.js` shims. On login the device
  generates a device keypair (ideally non-extractable) and the IdP issues one or
  more **device certs** (§4.1) — a **user cert** for login plus a device-resident
  **config cert** (§4.3) in one batch, and optionally **agent certs**. The
  interactive step uses the existing first-party **WinChan popup** channel, not
  a hidden cross-origin iframe.
- A **mint endpoint** (§3.1 `mint`): a device signs an **access request** (§4.2)
  with its `authentication` device key and posts it; the IdP verifies the device
  cert online and returns a short-lived **access cert**. This is what makes
  minting **cookie-free (survives ITP)** and lets **agents mint headlessly**,
  with no browser or user in the loop. The IdP MAY refuse even a nominally-valid
  device cert (abuse/compromise); the user then re-logs-in.
- **Agent device-grant.** An agent's device keypair is generated off-browser;
  the agent cannot authenticate to the IdP, so the **user authorizes** issuance
  and the **IdP issues the agent device cert directly** — the agent's pubkey
  flows to the IdP via the client broker (a device-grant / pairing hand-off),
  the user approves the constraints (identities, `subject: agent`, validity), and
  the IdP signs it. The agent then mints access certs headlessly via the mint API.
- A first-party **signer popup** (`/sign`) that holds device/config keys and
  signs access requests, warrants, and assertions on request via `postMessage`,
  so keys never leave their origin.
- `wsapi/*` endpoints for account/session/cert operations.
- `include.js` + `communication_iframe` retained only for RP compatibility.

The RP's login invocation carries an optional **`acceptedFallbacks`** argument
(§8.1) — the fallback IdPs the RP will accept for no-primary emails — which the
mediator uses to route email verification and to fail fast when it can't. This
is a call argument (mirroring a browser federated-login API), not an RP
`.well-known`.

Reference: `browserid-broker/src/routes/mod.rs`.

## 8. Fallback IdPs

An email whose domain has no primary IdP (§7) is vouched for by a **fallback
IdP** — a party that verifies control of the email (e.g. by SMTP challenge) and
then issues **device certs** (both purposes) and runs the **mint API** for it,
all under its own `iss`, published under its own `_browserid` DNSSEC key, so
every object verifies through the same DNSSEC-rooted path (§3) as any primary.
`browserid.me` is the reference fallback and the **hosted broker** — it also
hosts the **warrant registry / revocation UI / status endpoints** (§6.4). It
occupies the role BrowserID's central `login.persona.org` once did — but it is
**not a mandatory party.**

**Conformance boundary.** A fallback serves **only no-primary domains**. A
fallback-issued device/access/config cert for a domain that **has** a primary
**fails verification** — the primary is DNSSEC-authoritative for its own
identities. So the config-cert issuer binding (§6.2 step 2) and the accepted-set
enforcement (§6.1) together prevent a fallback from vouching over a primary's head.

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
- **Default.** Absent the argument, the accepted set is `{browserid.me}` —
  today's behavior, and no new trust (an RP invoking browserid.me's `include.js`
  already trusts it). An explicit empty set means primaries only. An RP that
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
(b) enforces the config-cert issuer binding, and (c) checks all **three status
authorities fail-closed** (§6.2).

## 10. Layered modules

- **[Agent provisioning, warrants & grant exchange](./agent-provisioning-and-grant-api.md)** —
  how the IdP issues an `agent`-subject device cert after the user authorizes it
  (device-grant), how the agent **mints access certs headlessly**, and how a
  config-cert-signed **warrant** confines it to the audiences and scopes its
  principal approved. Defines the consent + grant-exchange surfaces that produce
  and consume the `access_cert~assertion~warrant~config_cert` bundle §5/§6 verify.
- **SBO on-chain attribution** — attributing an email identity to an `ed25519:`
  key on a ledger, built on the offline-verification primitive (§6.3). Specified
  in the **sbo** repo (`specs/SBO Attribution Specification.md`), not here:
  its concepts (`/sys/dnssec` objects, controller rooting, `/sys/trust/brokers`)
  are ledger-specific, and sbo depends on browserid-ng, not the reverse.

