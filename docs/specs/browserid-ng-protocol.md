<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# browserid-ng — Protocol Specification (core)

> **STATUS: DRAFT.** Canonical spec for the browserid-ng protocol, authored per
> bean `browserid-ng-v9rz`. Derived from Mozilla's BrowserID/Persona
> (`mozilla/id-specs`, archived 2022) with deliberate departures — see
> [`browserid-ng-divergence-analysis.md`](./browserid-ng-divergence-analysis.md).
>
> Section status is marked inline: **[SETTLED]** sections describe shipped,
> stable behavior. The DNSSEC trust root and unified verifier (§3, §6.2) shipped
> on branch `feat/dnssec-required` (bean `browserid-ng-28uc` Phase 1). The one
> remaining **[PENDING]** item is the optional host certificate (§4.2), awaiting
> 28uc Phase 2.
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

## 2. Cryptography & key formats  **[SETTLED]**

- All signatures are **Ed25519 (EdDSA)**. JWTs use `"alg": "EdDSA"`.
  *(Departure from BrowserID's RSA/RS256.)*
- Public keys are the raw 32-byte Ed25519 point. Two text encodings appear:
  - **base64url** (unpadded) — in JWT `public-key` claims and the `_browserid`
    DNS record.
  - **`ed25519:<hex>`** — the SBO/on-chain form (attribution module).
- We deliberately **do not use JWK**. A key is a 32-byte value, not a
  `{kty,crv,x}` object.

Reference: `browserid-core/src/keys.rs`.

## 3. Discovery & the trust root  **[SETTLED]**

> Implemented on `feat/dnssec-required` (28uc Phase 1): a single DNSSEC-rooted
> verifier path.

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

### 3.1 Support document  **[SETTLED, minus trust role]**

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

### 4.1 User certificate  **[SETTLED format; trust per §3]**

A certificate is a JWT signed by an IdP key, binding a subject key to an
identity:

| Claim | Meaning |
|---|---|
| `iss` | Issuing IdP (domain, or `browserid.me` for the broker). |
| `iat`, `exp` | Validity window. |
| `public-key` | The certified subject key (base64url Ed25519). |
| `principal` | `{ "email": "user@domain" }`. |

Reference: `browserid-core/src/certificate.rs`.

### 4.2 Host certificate (optional intermediate)  **[PENDING — 28uc Phase 2]**

> Decided design (host principal reinstated; not yet implemented):

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

## 5. Assertions & backed assertions  **[SETTLED]**

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

Reference: `browserid-core/src/assertion.rs`.

## 6. Verification

### 6.1 Verifier API  **[SETTLED shape; trust resolution per §3]**

`POST /verify` with `{ "assertion": <backed-assertion>, "audience": <origin> }`
returns the verified identity (email) on success, mirroring the BrowserID
verifier contract. Reference: `browserid-broker/src/routes/verify.rs`.

### 6.2 Verification algorithm  **[SETTLED]**

> Implemented on `feat/dnssec-required` (28uc Phase 1). The verifier is generic
> over a `Discoverer` (native RPITIT), so it is unit-testable with a mock;
> production discovery resolves the key via DNSSEC (`FallbackFetcher`).

1. Parse the backed assertion into its cert chain + assertion.
2. Resolve the issuer (`iss`) IdP key **via the authenticated DNSSEC record**
   (§3). No `.well-known` key trust; no dual path.
3. Verify the cert chain: each cert signed by the previous key; the root cert
   signed by `K_dns` directly. *(The optional host-cert intermediate — §4.2,
   Phase 2 — is not yet in the verifier; when added it hooks in at this step.)*
4. Verify the assertion signature against the leaf certificate's subject key,
   and that `aud` matches the RP and nothing is expired.
5. Return the certified email.

This collapses the former well-known-vs-DNSSEC branching into one path
(`verifier.rs`).

### 6.3 Offline verification with detached DNSSEC proofs  **[SETTLED]**

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

## 7. Primary IdP & browser integration  **[SETTLED overview]**

browserid-ng does **not** use the shimmed `navigator.id` API. Instead:

- First-party **`/auth`** (authentication) and **`/provision`** pages, with
  `authentication_api.js` / `provisioning_api.js` shims.
- A first-party **signer popup** (`/sign`) that holds the user's key and signs
  assertions/typed writes on request via `postMessage`, so the key never leaves
  its origin.
- `wsapi/*` endpoints for account/session/cert operations.
- `include.js` + `communication_iframe` retained only for RP compatibility.

Reference: `browserid-broker/src/routes/mod.rs`.

## 8. Fallback broker  **[SETTLED]**

Domains (and their users) without a primary IdP are served by the **broker**,
`browserid.me`:

- SMTP-verifies control of an email, then issues certs with `iss=browserid.me`.
- **Publishes its own `_browserid` DNSSEC key**, so broker-issued certs verify
  through the same DNSSEC-rooted path (§3) as any primary.
- Is a pinned **broker trust anchor** for on-chain attribution (see the
  attribution module; `/sys/trust/brokers`).

This replaces BrowserID's central `login.persona.org` with a DNSSEC-rooted,
attribution-aware broker occupying the same role.

## 9. Layered modules

- **[Agent provisioning & grant exchange](./agent-provisioning-and-grant-api.md)** —
  how an agent obtains its own delegated identity from a principal's, with a
  broker-endorsed provisioning chain.
- **SBO on-chain attribution** — attributing an email identity to an `ed25519:`
  key on a ledger, built on the offline-verification primitive (§6.3). Specified
  in the **sbo** repo (`specs/SBO Attribution Specification.md`), not here:
  its concepts (`/sys/dnssec` objects, controller rooting, `/sys/trust/brokers`)
  are ledger-specific, and sbo depends on browserid-ng, not the reverse.

---

*Open drafting notes:* §3 and §6.2 are finalized against the shipped verifier
(`feat/dnssec-required`, commit `85021d2`). §4.2 (optional host certificates)
remains the only PENDING section, awaiting 28uc Phase 2.
