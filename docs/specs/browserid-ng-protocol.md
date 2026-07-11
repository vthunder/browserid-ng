<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# browserid-ng — Protocol Specification (core)

> **STATUS: DRAFT.** Canonical spec for the browserid-ng protocol, authored per
> bean `browserid-ng-v9rz`. Derived from Mozilla's BrowserID/Persona
> (`mozilla/id-specs`, archived 2022) with deliberate departures — see
> [`browserid-ng-divergence-analysis.md`](./browserid-ng-divergence-analysis.md).
>
> Everything described here is implemented and deployed, except **§4.2 (optional
> host certificates)**, a planned extension (bean `browserid-ng-dff5`).
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
- **Identity Provider (IdP)** — issues **certificates** binding a public key to
  an email it vouches for. A domain that publishes the discovery records below
  is its own **primary IdP** for its users. Domains that don't are served by a
  **broker** (§8).
- **Relying Party (RP)** — a site/app that accepts an identity by **verifying**
  an assertion (§6).

The trust root is **DNSSEC** (§3): an IdP's signing key is authenticated through
the DNS hierarchy the domain already controls, not the Web PKI. This makes
discovery results **offline-verifiable** (RFC 9102 proofs), which is what lets
identities be attributed in trustless contexts (see the attribution module).

### Inheritance from BrowserID

The **wire formats** — the JWT certificate/assertion shapes and the tilde-joined
**backed assertion** — are kept faithful to Mozilla BrowserID (§4, §5), so the
model is familiar and the assertion chain is unchanged. The **trust root**
(DNSSEC vs Web PKI), the **crypto** (Ed25519 vs RSA), and the **browser
integration** (first-party pages + postMessage vs the shimmed `navigator.id`)
are deliberate departures.

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
  to deliver an optional host certificate (§4.2). It is not a trust root; every
  key it references chains back to the DNSSEC record.

### 3.1 Support document

`GET https://<domain>/.well-known/browserid` returns JSON:

| Field | Meaning |
|---|---|
| `public-key` | The IdP key. **Advisory only** — MUST match the DNSSEC record; the DNSSEC value is authoritative. |
| `authentication` | Path to the interactive authentication page (§7). |
| `provisioning` | Path to the provisioning page/endpoint (§7). |
| `authority` | Optional delegation pointer to another domain's IdP. |

*(Departures from BrowserID: the former `disabled` field is **removed** — a
domain opts out by publishing no records; and `public-key` here is no longer a
trust source.)* Reference: `browserid-core/src/discovery.rs`,
`browserid-broker/src/routes/well_known.rs`.

## 4. Certificates

### 4.1 User certificate

A certificate is a JWT signed by an IdP key, binding a subject key to an
identity:

| Claim | Meaning |
|---|---|
| `iss` | Issuing IdP (domain, or `browserid.me` for the broker). |
| `iat`, `exp` | Validity window. |
| `public-key` | The certified subject key (base64url Ed25519). |
| `principal` | `{ "email": "user@domain" }`. |
| `typ` | Absent on a plain user certificate. Modules may define **typed certificate variants** (e.g. the agent module's `browserid-agent-cert-v1`); a verifier MUST reject any certificate bearing a `typ` it does not recognize. This makes module credentials fail-closed at verifiers that predate the module. |
| `status` | Optional fast-revocation hook: `{ "uri", "idx" }` pointing into a signed status list (§6.4). |

Reference: `browserid-core/src/certificate.rs`.

### 4.2 Host certificate (optional intermediate)

> **Planned extension — not yet implemented** (bean `browserid-ng-dff5`). The
> design is settled; this section specifies the target.

A **host certificate** carries `principal = { "host": "<domain>" }` and asserts
that a key `K_host` is authoritative to issue user certs for `<domain>`. A host
cert **MUST be signed by the DNSSEC-published key `K_dns`** (not self-signed).

This yields an optional chain:

```
K_dns  →  (optional) host cert (K_host)  →  user cert  →  assertion
```

Use it to separate the **DNS admin** (holds `K_dns`, rarely used) from the
**IdP operator** (holds `K_host`, signs user certs), and to rotate the
operational key by issuing a new host cert **without a DNS change**. Simple
deployments omit it and sign user certs directly with `K_dns`. Host certs carry
**no endpoints** (endpoints stay in the support document, §3.1).

## 5. Assertions & backed assertions

- **Assertion** — a short-lived JWT signed by the *subject* key from a
  certificate, claims:

  | Claim | Meaning |
  |---|---|
  | `aud` | The RP origin the assertion is for. |
  | `exp` | Expiry (short). |

- **Backed assertion** — the tilde-joined chain presented to an RP, **identical
  in shape to BrowserID**:

  ```
  <cert-1>~…~<cert-n>~<assertion>
  ```

  The certificate chain roots at the IdP key (§3); the trailing assertion is
  signed by the leaf certificate's subject key. Only the signature algorithm
  (EdDSA) differs from BrowserID.

  Modules may define chains with additional, typed segments (e.g. the agent
  module's warrant, `agent_cert~warrant~assertion`). A verifier MUST reject a
  backed assertion containing a segment it does not recognize — chains are
  fail-closed, never skip-what-you-don't-understand.

Reference: `browserid-core/src/assertion.rs`.

## 6. Verification

### 6.1 Verifier API

`POST /verify` with `{ "assertion": <backed-assertion>, "audience": <origin> }`
returns the verified identity (email) on success, mirroring the BrowserID
verifier contract. Reference: `browserid-broker/src/routes/verify.rs`.

An RP's verifier holds a **trusted-issuer set** — the primaries and fallback
IdPs (§8.1) it accepts — and MUST reject an assertion whose `iss` is not in it
(the reference `Verifier` does this: `trust_issuer` /
`trust_issuer_from_well_known`, rejecting an untrusted issuer). This is the
authoritative enforcement of an RP's accepted-fallbacks policy; the client-side
`acceptedFallbacks` argument (§8.1) is only a routing hint and grants nothing.

### 6.2 Verification algorithm

1. Parse the backed assertion into its cert chain + assertion. Reject any
   segment of unrecognized type (§5) and any certificate bearing an
   unrecognized `typ` (§4.1). A certificate `typ` a verifier *does* recognize
   activates that module's presentation rules (e.g. the agent module's
   warrant requirement) **before** step 5.
2. Resolve the issuer (`iss`) IdP key **via the authenticated DNSSEC record**
   (§3). No `.well-known` key trust; no dual path.
3. Verify the cert chain: each cert signed by the previous key; the root cert
   signed by `K_dns` directly. *(The optional host-cert intermediate (§4.2) is
   not yet implemented; when added it hooks in at this step.)*
4. Verify the assertion signature against the leaf certificate's subject key,
   and that `aud` matches the RP and nothing is expired. Where a certificate
   carries a `status` claim, the verifier SHOULD check it (§6.4).
5. Return the certified email (plus any module metadata, e.g. agent
   attribution).

This collapses the former well-known-vs-DNSSEC branching into one path
(`verifier.rs`).

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

Certificates are offline, self-contained credentials, so absent anything else
a certificate is valid until `exp` — revocation latency equals the TTL. For
sub-TTL revocation, a certificate MAY carry:

```json
"status": { "uri": "https://<idp>/.well-known/browserid-status", "idx": 42 }
```

- `uri` names a **signed status list** published by the issuing IdP; `idx` is
  the credential's position in it. Issuers allocate **one index per
  identity** (stable across re-mints, so one bit kills every outstanding
  certificate for that identity) and, for the agent module, **one per
  warrant grant** (stable across reissues). The list format follows the
  **IETF OAuth Token Status List** mechanism in shape — 1 bit per entry,
  LSB-first, zlib-compressed, base64url — carried in this protocol's usual
  claim-level-`typ` JWS (`browserid-status-list-v1`, claims `iss`/`sub` (the
  list URI)/`iat`/`ttl`/`status_list{bits,lst}`).
- Verifiers SHOULD fetch and cache the list (reference cache: 5 minutes) and
  treat a set bit as **revoked → reject**. Fetching the whole list reveals
  nothing about which subject is being checked (no OCSP-style privacy leak).
- The dependency is soft: if the list is unreachable, behavior degrades to
  TTL-only semantics. Whether that failure is open (honor the cert until
  `exp`) or closed is RP policy; libraries SHOULD default to a short
  fail-open grace, then fail closed.
- Detached-proof consumers (§6.3) can pair a certificate with a **status-list
  snapshot**, giving offline verification a defined freshness window ("valid
  as of T").

Layered with short TTLs and the agent module's delegation-root revocation,
this yields: instant revocation for new sign-ins at status-checking RPs,
≤ cache-window for live sessions there, ≤ TTL at RPs that skip the check.

## 7. Primary IdP & browser integration

browserid-ng does **not** use the shimmed `navigator.id` API. Instead:

- First-party **`/auth`** (authentication) and **`/provision`** pages, with
  `authentication_api.js` / `provisioning_api.js` shims.
- A first-party **signer popup** (`/sign`) that holds the user's key and signs
  assertions/typed writes on request via `postMessage`, so the key never leaves
  its origin.
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
IdP** — a party that verifies control of the email (e.g. by SMTP challenge)
and issues a cert with its own `iss`, published under its own `_browserid`
DNSSEC key, so the cert verifies through the same DNSSEC-rooted path (§3) as
any primary. `browserid.me` is the reference fallback and occupies the role
BrowserID's central `login.persona.org` once did — but it is **not a mandatory
party.**

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

## 9. Layered modules

- **[Agent provisioning, warrants & grant exchange](./agent-provisioning-and-grant-api.md)** —
  how an agent obtains its own delegated identity from a principal's
  (registrar-endorsed provisioning chain), and how user-signed **warrants**
  confine it to the audiences and scopes its principal authorized. Defines the
  `browserid-agent-cert-v1` certificate `typ` and the
  `agent_cert~warrant~assertion` chain that §4.1/§5/§6.2's fail-closed rules
  exist for.
- **SBO on-chain attribution** — attributing an email identity to an `ed25519:`
  key on a ledger, built on the offline-verification primitive (§6.3). Specified
  in the **sbo** repo (`specs/SBO Attribution Specification.md`), not here:
  its concepts (`/sys/dnssec` objects, controller rooting, `/sys/trust/brokers`)
  are ledger-specific, and sbo depends on browserid-ng, not the reverse.

