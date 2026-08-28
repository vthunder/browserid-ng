<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# browserid-ng — Protocol Specification

> **Status: draft.** This is the standalone, complete specification of the
> browserid-ng protocol: the actors, the credential artifacts they exchange, how a
> holder obtains and presents them, and how a relying party verifies a presentation.
> An agent is simply a holder and is covered throughout — there is no separate
> "agent protocol." One capability lives outside this spec: **on-chain attribution**
> (§10), whose trust anchors and dependency direction are genuinely distinct.

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
  **fallback IdP** (§8). Its required operations are specified in §7.
- **Relying Party (RP)** — a site or service that accepts an identity by
  **verifying** a presentation bundle (§6).

### 1.2 Holders and roles

A cert acts for an **(identity, holder)** pair, not an identity alone. A **holder**
is an opaque handle for one credential-bearing party — a browser, an agent, a
service. Authorization attaches to the pair: the same identity, held by two
holders, can carry different permissions. A holder is opaque to verifiers; only a
warrant's holder-matcher reads it (§4.5) — one kind of warrant **binding**
(§5), the instance qualifier. A warrant names two roles:

- **Grantor** — the identity that **authorizes**, signing a warrant with a
  config cert; the action is attributed to the grantor.
- **Grantee** — the identity that **acts**. The warrant's binding (§5) pins
  *which instance* of the grantee and how it is authenticated: a
  holder-bound record by key possession — the grantee's device holding the
  access cert and signing the assertion — and a connection-bound record
  (§5) by the custody channel's own dance, with no grantee key in the
  picture. In a self-login grantor and grantee coincide; in a delegation
  they differ, and may belong to different IdPs (§5, §6).

### 1.3 Infrastructure: the broker

The **broker** is the user's agent (in the user-agent sense), not a party to any
identity claim. Its **client** component holds the user's keys on the device and
mediates the web login exchange (§7.3); the warrant registry and the
revocation/status endpoints are the **registry** role — a service specified by
its own API (registry-api-v1) that any party can operate; browserid.me runs the
reference deployment. A registry operator MAY additionally serve as a
**fallback IdP** that an RP chooses to accept or not (§8.1) — but that is a
separate role, chosen independently; as a registry it verifies nothing.

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
  domain is not a primary → the identity is issued by the wallet's configured
  fallback IdP (§8). The fallback IdP's *own* key is likewise DNSSEC-resolved;
  a fallback without DNSSEC is a hard error.

- **`.well-known/browserid`** carries an IdP's **endpoints** (§3.1) and an optional
  host certificate (§4.4) — never a key. An IdP's identity key comes only from the
  DNSSEC record above.

### 3.1 Support document

`GET https://<domain>/.well-known/browserid` returns JSON:

| Field | Meaning |
|---|---|
| `authentication` | Path to the interactive authentication page (§7). |
| `provisioning` | Path to the provisioning page (§7). |
| `device-cert` | Path to the **batch device-cert issuance API** (session/interactive-authed): issues the user (`authentication`) + config (`authorization`) device certs. REQUIRED for primary IdPs (§7). A **fallback IdP** (§8) MAY omit it and satisfy issuance entirely through its `device-authorization` page (the ceremony contract, fallback-IdP spec) plus `access-cert`. |
| `access-cert` | Path to the **headless access-cert mint API** (§7): device-signed access request → short-lived access cert. The device cert is the credential, so agents mint with no browser. REQUIRED — every IdP MUST implement it (§7). |
| `device-authorization` | Path to the browser-facing device-authorization page — the login popup hand-off that gets a device its certs first-party. |
| `agent-device-authorization` | Optional. The device-authorization page's agent mode (merged provisioning): issues a **named-agent** device cert (an identity differing from the session's, e.g. a `+tag` sub-address). Absent ⇒ named agents unsupported here; "as-you" agents need no support. |
| `device-revoke` | Optional. Browser-facing device-**revocation** page so the **user** (never a registrar on its own authority) can revoke certs this IdP issued. Absent ⇒ no remote-initiated revocation (certs run to expiry). |
| `authority` | Optional delegation pointer to another domain's IdP. |
| `terms` | Optional. URL of a human-readable policy page for a domain issuing **managed identities** (§4.7). UAs SHOULD link it alongside — never instead of — the claims-derived constraint disclosure. |

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
| `managed` | OPTIONAL boolean. Marks every device cert of a **managed identity** (§4.7). An IdP MUST set it on an identity's device certs before it ever stamps `constraints` into that identity's presented certs or requires a mint `audience` (§4.2) — the durable, issuance-time signal that drives UA disclosure. |
| `constraints` | OPTIONAL restriction object (§4.7) — meaningful only on a **config cert** (presented to RPs; binds warrants at §6.1 step 7), where it is the org's one lever over delegation to grantees at *other* IdPs. An auth cert is never presented and MUST NOT carry it: the `managed` marker is its whole signal. |

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
| `audience` | OPTIONAL — **managed identities only** (§4.7). A client MUST NOT send it unless its device cert carries `managed: true`, and an IdP MUST NOT require or honor it otherwise — the mint stays **RP-blind for unmanaged identities**, enforced structurally by the user's own agent. A managing IdP MAY require it and scope the minted cert to that audience (a single-entry `aud` constraint, §4.7); this is the used-set-visibility posture (§4.7 Privacy). |

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
| `constraints` | OPTIONAL managed-identity restriction object (§4.7), enforced at verification (§6.1 step 7). |

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

### 4.7 Constraints & managed identities

> **Planned extension — not yet implemented.** The design is settled; this
> section specifies the target.

A **managed identity** is declared by its IdP at issuance: every device cert of
a managed identity carries `managed: true` (§4.1). The marker — not the
presence of constraints — is the signal, because policy itself lives in
short-lived presented certs and can change at every mint; the durable device
cert is what tells the UA, once, at issuance time, that this identity answers
to its domain. An IdP MUST mark an identity managed before (or when) it first
stamps `constraints` or requires a mint `audience` (§4.2) for it.

`constraints` — restrictions on the presentations a certificate may
participate in — MAY appear on the **presented** certs only: the **access
cert**, stamped at mint (the normal case — audience and scope policy applied
fresh every ~24 h), and the **config cert**, the grantor-side object (the org's
one lever over delegations to grantees at *other* IdPs, where the org signs
nothing else in the bundle). An auth cert is never presented and MUST NOT carry
`constraints`. Constraints restrict only identities their issuer is
authoritative for; a user's identities from other issuers are untouched. The
role split is fixed: constraints are **authored by IdPs, enforced by
verifiers, and disclosed by user agents** — a broker/UA is never an
enforcement point.

| Key | Meaning |
|---|---|
| `aud` | `{ "salt": "<base64url>", "hashes": ["<base64url>", …] }` — allowlist of permitted audiences. An audience satisfies it iff `b64url(SHA-256(salt ‖ audience))` ∈ `hashes`, with the audience normalized exactly as assertion `aud` (§5). Hashed because certs are presented to every RP the holder visits — a cleartext list would enumerate the domain's application roster ecosystem-wide. Hashing protects the domain from RPs, not the user from the IdP. |
| `scopes` | Array of strings: the presented warrant MUST NOT carry a scope outside this set. |
| `max-ttl` | Seconds: the presented warrant's `exp − iat` MUST NOT exceed this. |

**Constraints bind the presentation, as presented.** A presentation satisfies a
cert's constraints iff the RP audience (== assertion `aud` == `warrant.audience`,
§6.1) satisfies `aud`, and the warrant satisfies `scopes` and `max-ttl`.
Constraints are evaluated at verification time against the certificate copies
**in the bundle** — so policy freshness is set by the TTL of the presented
certs, which is the issuing IdP's knob. The reference TTLs (§4.1–4.2) are
consumer defaults; a managing domain is expected to deviate. The natural
policy point is a **mint**, and both operations have one. For presentation,
the **access-cert mint** (§7.2): every presented bundle — human login or
delegated agent, each minting through the identity's IdP — embeds a fresh
(reference ~24 h) access cert, so constraints stamped there govern the whole
presentation path on a short policy loop, with no new endpoint or object.
Connection-bound admission (§6.4) never mints an access cert: there the
**config cert is the sole constraint carrier**, checked at record validation
(§6.4 step 1d), so a managing domain that wants its policy to reach members'
connections MUST stamp constraints on config certs, not only at the
access-cert mint. Admission's short loop is the **freshness-backed bearer
mint** (§6.4): to change what a member's standing connections may do, the org
rotates the member's config cert — revoke the old, reissue under the new
constraints — and the flipped status bit fails every affected record's next
bearer mint within one bearer TTL; reconnecting re-runs consent under the new
cert. Blunter than per-mint stamping (rotation is per member, not per
connection), but the loop is the same short one.

**Fail closed on unknown keys.** A verifier that encounters a `constraints` key
it does not implement MUST reject the presentation. Constraints are
restrictions; ignoring one is escaping it. (This is also what keeps future
vocabulary additions safe: verifiers predating a key reject rather than
silently waive it.)

**User-agent duties.** A UA/broker encountering `managed: true` SHOULD:
disclose, before storing the certs, that the identity is managed — its domain
controls issuance and may restrict, and see, where it is used (**no expectation
of privacy from the issuer**, categorically; the domain's `terms` page (§3.1)
linked alongside); present managed identities distinctly wherever identities
are chosen; and re-disclose when an identity *transitions* to managed at
reissue. Per-mint variation in access-cert constraints is live policy and needs
no re-prompt. If an issuer stamps `constraints` or demands a mint `audience`
for an identity whose device certs are **not** marked, the UA SHOULD treat the
identity as managed anyway — disclose, and surface the issuer's inconsistency.
The UA MUST NOT enforce constraints; its role is disclosure.

**Privacy.** For an unmanaged identity the access request carries no RP
audience and the mint stays RP-blind (§4.2, §7.2) — constraints change nothing
for consumers. A managing domain chooses its **visibility posture**: stamp a
broad uniform allowlist and learn only the *allowed* set (its mint stays
RP-blind too), or require per-audience minting (§4.2 `audience`) and see each
audience as it is first used. Both postures are the domain's dial over
identities it issues — consistent with the no-expectation-of-privacy doctrine
above — and the UA's disclosure SHOULD say which applies.

**Deployment.** A constraint binds only at verifiers that enforce this section;
earlier verifiers ignore unknown cert claims. A domain SHOULD NOT rely on
constraints until the verifiers it cares about conform.

## 5. Assertions, warrants & the presentation bundle

- **Assertion** — a short-lived JWT signed by the **fresh access key** (the key
  certified by the access cert, §4.2), claims:

  | Claim | Meaning |
  |---|---|
  | `aud` | The RP origin the assertion is for. |
  | `exp` | Expiry (short). |
  | `req_origin` | OPTIONAL. The **requesting channel**: the authenticated origin the signing request arrived from, stamped by the wallet at dispatch. Present iff the presented warrant carries a `requester` binding entry (§5); matched by verifiers fail-closed (§6.6 invariant 13). |

- **Warrant (`browserid-warrant-v2`)** — the **authorization record**, signed by
  a **config cert** (§4.3). It records that a **`grantor`** authorizes a
  **`grantee`** at one **`audience`** [+ `scopes`], and carries exactly one
  **`binding`** claim, holding a **set of channel entries** (a singular
  object is shorthand for a one-entry set) — the instance qualifiers that pin
  *the circumstances under which the grant operates*: which instance of the
  grantee acts and, on self-grants, which channel may initiate. Identities (`grantor`, `grantee`) are
  **always email strings**; bindings are warrant-local qualifiers, are **not
  identities**, and never appear where identities live. A warrant is **always**
  present at the RP (self-logins carry one too, where grantor == grantee).

  One record format serves **two operations** (§6): **presentation**
  (operation P, §6.1), in which the grantee proves possession of its key in
  the four-object bundle below — the word "presentation" is reserved in this
  spec for that operation — and **admission** (operation A, §6.4), in which a
  resource *holds* the record and matches an independently authenticated
  subject against it, like a signed row in `/etc/passwd`. Which operations a
  record can serve is governed by its binding.

  | Claim | Meaning |
  |---|---|
  | `typ` | `browserid-warrant-v2`. |
  | `iat`, `exp` | Validity window (reference: 90 days). |
  | `grantor` | The identity the action is **attributed** to (the effective author). Always an **exact** email — never a matcher. The signing config cert MUST be authoritative for it (§4.3). |
  | `grantee` | The identity that **acts**. An exact email — or, on admission-consumed records only, a **grantee matcher** (below). Equals `grantor` for an "as-you" grant; differs for delegated on-behalf grants. |
  | `binding` | **A set of channel entries** — a JSON array, or a single object as shorthand for a one-entry set (the only form pre-amendment records use). Each entry: mandatory `kind`, kind-specific fields (table below); entries are **conjunctive**. A missing or empty `binding`, or an entry with an unimplemented `kind`, ⇒ reject — fail-closed. |
  | `audience` | **Exactly one** audience (exact string match, same normalization as assertion `aud`) — an RP origin, or a non-web destination such as an SBO database ref on a `sign:`-scoped record. |
  | `scopes` | OPTIONAL array of **scope entries**: a bare string `s` (shorthand for `{"scope": s}`) or an object carrying the scope string plus **parameters** (below). Resource scopes are opaque to this protocol and interpreted only by the RP; the `sign:` namespace (below) is interpreted by wallets. |
  | `status` | **REQUIRED** revocation ref, rooted at the **user's warrant registry** (§6.3, registry-api-v1) — the ref's `uri` names the allocating registry. |

  ```json
  { "typ": "browserid-warrant-v2",
    "iat": 1755100000, "exp": 1762876000,
    "grantor": "friend@example.com",
    "grantee": "friend@example.com",
    "binding": { "kind": "connection", "protocol": "oauth", "id": "cn_8f3a…",
                 "client_host": "claude.ai", "client_name": "Claude" },
    "audience": "https://gate.dan.dev/notes",
    "scopes": ["tool:read_file", "tool:search_files"],
    "status": { "uri": "https://browserid.me/.well-known/browserid-status", "idx": 168 } }
  ```

  **Bindings.** The structural rule is *exactly one `binding` claim, holding
  a set* (amended 2026-08-25 from "exactly one binding object"; the singular
  shorthand keeps every previously issued record valid, and pre-amendment
  verifiers reject the array shape — fail-closed, the intended versioning
  behavior, §6.6 invariant 14). Future kinds never add new *top-level*
  claims: an unknown claim tends to be ignored by verifiers, while an unknown
  `kind` inside the mandatory slot is fail-closed by rule. Each entry is a
  rule from the grantor about the circumstances under which the grant
  operates — which device signs, who may ask — and **all entries must check
  out**: each kind defines how it evaluates in each operation, and an
  *unsatisfiable* cell fails that operation.

  | `kind` | Fields | Pins | Subject authenticated by |
  |---|---|---|---|
  | `holder` | `matcher` — `*` (any holder), `<ns>.*` (a namespace), or `<id>` (one holder) | which **device holders** of the grantee (v1 semantics verbatim), checked against the grantee's access-cert holder (anti-fungibility) or login holder | key possession — access cert + assertion (§6.1) — or a browserid login carrying a holder (§6.4) |
  | `connection` | `protocol`, `id`, `client_host`, `client_name` | which **custody channel** of the grantee | per `protocol` — for `"oauth"`: authorization codes released only to the registered redirect URI, PKCE binding the exchange to the authorize initiator |
  | `requester` | `origin` — one web origin, exact | which **requesting channel** may ask the grantor's **wallet** to sign under the grant (prose below) | the wallet authenticates the request's source itself — for a website, the browser-verified message origin, unforgeable by page JS — and stamps it into the assertion (`req_origin`) for downstream re-checking |

  How each entry evaluates, per operation — an unsatisfiable cell fails that
  operation:

  | `kind` | op P (presentation, §6.1) | op A (admission, §6.4) | evaluated by |
  |---|---|---|---|
  | `holder` | access cert's holder covered by the matcher | login's holder covered by the matcher | verifier / resource |
  | `connection` | *unsatisfiable* | the custody dance bound to `binding.id` | resource |
  | `requester` | `req_origin` stamped in the assertion equals `origin` | *unsatisfiable* | wallet at dispatch; verifiers re-check the stamp |

  This table subsumes rules previously stated as standalone prohibitions: a
  `connection`-bound record cannot verify in a presentation, and a
  `requester` entry can admit no one — both are unsatisfiable cells, not
  special cases. A record whose set satisfies no operation at all is dead
  paper — fail-closed and harmless — but signing surfaces MUST refuse to mint
  one (mint-side lint).

  Within `connection`, an unimplemented `protocol` ⇒ reject. Both extension
  doors are explicit and fail-closed: a future custody channel with different
  mechanics is a new `protocol`; a different qualifier axis entirely is a new
  `kind`.

  A `holder` matcher and a connection `id` are the same concept at different
  layers: not just *who*, but *which instance of who* — which device of the
  identity, or which custody channel of the identity. The instance MUST be
  pinned in the signed record: a record naming only `client_host` would be
  satisfiable by **any** connection from that host to this audience —
  including someone else's, whose agent would then act attributed to the
  grantor, within the grantor's scopes. Resource-internal state must never be
  the only thing standing between "my connection" and "any connection" (a
  buggy rebind or a restore-from-backup is not an attack, and must still be
  unable to cross grants). `id` is broker-minted at consent (§7.5), opaque and
  exact — no wildcard — and is **1:1 with its record** (§6.6). `client_host`
  is the enforceable client datum (the registered redirect-URI host);
  `client_name` is display-only and MUST be marked unverified everywhere it
  appears. For `protocol: "oauth"` the enforcement is normative at the
  resource: it MUST register exactly one exact-match redirect URI per
  connection (no wildcard or pattern URIs; a post-consent registration
  change to a different host invalidates the connection), MUST require PKCE
  (S256), and MUST verify at each authorization-code release and token
  exchange that the registered redirect URI's host equals
  `binding.client_host` — fail-closed. Without these checks the consented
  custody host would be display-only.

  **`connection` implies a self-grant:** a `connection`-bound record MUST have
  `grantor == grantee`. This is derived, not stipulated: the grantee names the
  identity that *acts*; a connection's actor is its *establisher* — the only
  identity the custody mechanics tie to the channel; the establisher is the
  consent ceremony's signer, because consent is the only moment `binding.id`
  can be minted and bound; and the signer is the grantor (§6.1 step 5). A
  connection record is the grantor's own grant to themselves, narrowed to one
  custody channel — the exact shape self-logins already have, plus the
  qualifier.

  **The `requester` kind: who may ask.** Some grants are exercised not by the
  grantee's own key possession alone but *through the grantor's* **wallet** —
  the party holding the user's keys and signing on the user's behalf (in the
  reference deployment, the broker-origin signer surface backed by the
  browser keystore; equally a hosted or CLI wallet). A `requester` entry
  says: only honor requests that arrive from this source. The wallet MUST
  authenticate the source to its own satisfaction before honoring a request —
  for a website, the browser-verified origin of the request message, which
  page JS cannot forge; a web origin is the only requester source specced.
  Only the wallet witnesses the ask, so the wallet is the enforcement point
  (§6.6 invariant 9); it additionally stamps the origin into each fresh
  assertion (`req_origin`) so conforming verifiers re-check the same fact
  downstream (invariant 13). The rule lives in the signed record rather than
  wallet-local storage so a wallet bookkeeping bug cannot cross grants — each
  record carries its own answer to "may this site ask?" — and so the user's
  account ledger shows exactly what was authorized.

  *Honesty tier, stated plainly.* The stamp is as honest as the stamper.
  WebAuthn's stamper is the browser itself; a JS wallet's is code on the
  wallet origin — strong against page JS, but a compromised wallet origin
  could lie. No new trust is introduced (that origin already holds the keys);
  the gain is that honest-but-buggy dispatch becomes downstream-detectable
  and every signature carries a signed audit trail of who asked. Stronger
  wallet honesty is a certification / hardware-attestation matter, open to a
  future hardware-backed wallet, out of reach for a JS one.

  **Multi-entry sets are self-grant-only.** On a delegated record (grantor ≠
  grantee) the binding set MUST be exactly one `holder` entry — v1 channel
  semantics verbatim. Nothing is *incoherent* about richer sets on delegated
  records; each known combination is one specific unsolved problem, so each
  stays a labeled door: **(1)** a `requester` entry on a delegated grant
  inverts the enforcement point — the rule would be enforced by the
  *grantee's* wallet, the constrained party policing itself and
  self-attesting the stamp (same syntax, much weaker meaning); **(2)** a
  `connection` entry on a grantor-signed record is unconstructible in one
  ceremony — `binding.id` is minted at the grantee's consent, after the
  grantor signed; a host *matcher* ("via claude.ai, any connection") avoids
  the id problem and is enforceable by the resource, and this field is its
  natural home when that is designed; **(3)** the composition rules (§6.5) do
  not yet say how channel entries on a policy record conjoin with the
  connection record's own set. All three are design work, not prohibitions;
  until done, fail closed.

  **Grantee matchers (admission only).** An admission-consumed record MAY
  carry a grantee matcher: `*@<domain>` (anyone at the domain) or `*` (any
  authenticated email) — policy rows such as "everyone at my company gets the
  read tools", or a public-but-attributed mount. Three guardrails: **(1)**
  matchers are **admission-only** — operation P requires an exact grantee (a
  glob in P would let any matching agent act *attributed to the grantor*:
  attribution transfer to unknown actors); **(2)** a matcher grants
  **permission, never attribution** — the acting identity always comes from
  the subject's own credential (login or self-signed connection record), never
  from the glob row; **(3)** `*` means any *authenticated* email, never
  anonymous — subjects still log in or connect as themselves; the glob only
  widens who matches. `grantor` is never a matcher — it is attribution, exact
  and signed-for.

  **Identity comparison.** Wherever this spec matches identities "exactly"
  (§6.1 step 6, §6.4 step 3), the comparison is: domain part lowercased and
  in A-label (punycode) form, local part byte-exact, no other normalization.
  Issuers and signing surfaces MUST emit identity strings already in this
  form. A `*@<domain>` matcher compares `<domain>` under the same rule
  against the subject's entire domain part — subdomains do not match — and
  covers any local part, subaddressed (§4.6) ones included.

  **Scope entries & parameters.** Three rules: **(1)** everywhere the system
  treats scopes as identifiers — constraint checks (§4.7, §6.1 step 7), scope
  intersection (§6.5's S ∩ S′) — an entry's identity is its scope *string*;
  parameters ride along. **(2)** Parameters are **attenuations** with a
  defined stricter-wins order; a consumer MUST refuse an entry carrying a
  parameter it does not implement (§6.6 invariant 14). **(3)** `mode` is the
  first parameter, defined on `sign:` scopes: `"prompt"` makes the wallet
  render the object to be signed in its own UI and wait for approval before
  signing; absent ⇒ `"auto"` — the grant's baseline is standing silent
  authority, prompt is the explicit tightening (`prompt` > `auto`).
  Wallet-local overrides may only tighten, never loosen. Future parameters
  (counts, rate caps — stateful, wallet-enforced) enter as new object keys,
  never new claims. Mode's threat model, flatly: it constrains a bad
  *requester*, not a bad *wallet* — a dishonest wallet holds the keys and no
  mode bit binds it, the same position as WebAuthn's user-presence flag,
  where verifiers trust the authenticator's word (see the honesty tier
  above).

  **The `sign:` scope namespace.** `sign:<kind>` scopes — disjoint from
  resource scopes — name **what a wallet may be asked to sign**: the scope
  determines what the wallet will sign, the consent-card verb, and the
  payload discipline — a typed object destined for the warrant's audience,
  never a bare hash or arbitrary blob. The current vocabulary is
  `sign:sbo:<action>` (typed SBO envelopes by action, e.g. `sign:sbo:post`,
  `sign:sbo:delete`); extending it is deferred until another instance is
  real.

  **Signing grants.** A **signing grant** is the record type the two
  generalizations above exist for: a self-grant with an exact grantee, the
  channel set {`holder`, `requester`}, one exact audience, and `sign:` scopes
  — "*this website* may submit objects of *this kind* to be signed as me,
  for *this audience*." It is authored only in a consent ceremony (§6.6
  invariant 11, ceremony in §7.5), registered like any other warrant (status
  index, account ledger row), and **stored at the wallet**, which is the
  enforcement point: every incoming request either matches a stored record —
  channel set, `grantee`, `audience`, and `sign:` scope, honoring the scope
  entry's parameters — or is refused (invariant 9). Per use the wallet mints
  a fresh access cert and assertion (with `req_origin` stamped) and presents
  them with the *stored* warrant — by the kind × operation table a signing
  grant operates in op P only. One record per (requester, audience) pair
  keeps revocation per-site and per-audience. Auto-mode scopes are standing
  authority — the site submits objects of that kind silently and repeatedly;
  the consent card MUST say so in its verb, counterweighted by the scope
  constraint, the pinned audience, the ledger row, the revocation bit, and
  prompt mode for scopes that warrant it.

  ```json
  { "typ": "browserid-warrant-v2",
    "iat": 1756100000, "exp": 1763876000,
    "grantor": "dan@example.com",
    "grantee": "dan@example.com",
    "binding": [ { "kind": "holder",    "matcher": "<this device's holder>" },
                 { "kind": "requester", "origin": "https://mingo.example" } ],
    "audience": "sbo+raw://avail:turing:506/",
    "scopes": ["sign:sbo:post", { "scope": "sign:sbo:delete", "mode": "prompt" }],
    "status": { "uri": "https://browserid.me/.well-known/browserid-status", "idx": 171 } }
  ```

  **`status` is REQUIRED** on v2 records. In v1 it is optional because a
  leaked warrant is inert without the grantee's key; a connection-bound record
  authorizes with no grantee key in the picture, so the registrar bit is the
  kill switch and a record without one is malformed. (Requiring it on all v2
  records also makes the registry's revocation ledger complete by
  construction.)

  A holder-bound warrant is **over the grantor/grantee + holder-matcher, not
  bound to any device/access key**, so it is signed **once** by a config cert,
  **stored** in the user's warrant registry, and **reused device-agnostically**:
  any device whose holder the matcher covers, that can mint an access cert for
  the grantee, presents the stored warrant alongside it. A warrant is
  long-lived and **not a secret** — a leaked holder-bound record is useless
  without a matching IdP-minted access cert, and a leaked connection-bound
  record is attributed paper, redeemable only by the genuine audience inside
  the custody dance bound to its `id` — so a user may publish an individual
  warrant (the on-chain attribution module publishes it as part of the
  verification bundle). The only concern is **bulk** publication/enumeration,
  which in aggregate discloses which sites and services a user uses — and,
  via the v2 client descriptor, which hosts a user connects through: the same
  class of metadata.

  **v1 compatibility.** `browserid-warrant-v1` — the same claims with a
  top-level `holder` matcher in place of `binding`, and `status` OPTIONAL —
  remains valid indefinitely and is interpreted as a v2 record with
  `binding: { "kind": "holder", "matcher": <holder claim> }`. New signing
  surfaces SHOULD emit v2; verifiers accept both. Conforming v1 verifiers
  already reject v2 objects (unknown `typ` ⇒ reject, §6.1 step 1), so
  downgrade protection at every deployed verifier holds by existing rule
  (§6.6).

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
  fail-closed. Only a warrant whose channel set is satisfiable
  in operation P — a `holder` entry, no `connection` entry, any `requester`
  entry matched by the assertion's `req_origin` stamp — **and** whose grantee
  is exact (non-matcher) can ever verify in a bundle (§6.1, §6.6 invariants 1
  and 13); a `connection`-bound record is admission-only and never presents.

## 6. Verification

A warrant is consumed by one of **two operations**, per its binding (§5):

- **Operation P — presentation verification** (§6.1): the verifier is given a
  four-object bundle and an expected **audience**, and either rejects it or
  returns the identity it establishes. The grantee proves possession of its
  key; authority travels with the actor.
- **Operation A — record validation + subject matching** ("admission", §6.4):
  the resource **holds** the record; nothing presents it. An independently
  authenticated subject is matched against the record; authority sits at the
  resource.

Presentation verification joins **two independent DNSSEC-rooted paths** — one
through the access cert (the grantee's actor credential) and one through the
config cert (the grantor's authorization) — and attributes the result to the
grantor. (The `browserid.me` broker offers a hosted HTTP verifier for RP
convenience — `/verify` for bundles and a two-object record-validation call
for admission (§6.4); those endpoints are a service, not part of this
protocol.)

### 6.1 Verification algorithm

The join is **(grantee = access-cert identity, holder ∈ matcher, audience)**, with
the result attributed to the **grantor**: the access cert says this fresh key
speaks for the grantee at this audience, and the warrant says the grantor
authorizes the grantee for this audience + scopes, signed by an `authorization`
config cert an IdP issued for the grantor. The two issuers (access-cert / grantee,
config-cert / grantor) may differ.

1. Parse the bundle into exactly `access_cert ~ assertion ~ warrant ~
   config_cert` (§5). Reject any other shape, and any object bearing an
   unrecognized `typ` or `purpose` — fail-closed. The warrant is
   `browserid-warrant-v2`, or v1 interpreted as its holder-binding sugar (§5).
   A v2 warrant missing `binding` or `status`, with an empty binding set, or
   with any binding entry whose `kind` is unimplemented, ⇒ reject (§5).
   **Presentation requires a channel set satisfiable in op P and an exact
   grantee:** the set MUST contain a `holder` entry and MUST NOT contain a
   `connection` entry (unsatisfiable in P, §5's kind × operation table); a
   matcher-grantee record MUST NOT verify in a bundle — mechanically it
   carries no exact join for step 6, and the verifier MUST also reject it
   explicitly here.
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
   unexpired and that the join holds: `warrant.grantee == access_cert.identity`
   (exact, per §5's identity comparison — a grantee matcher never satisfies
   this join), **every** binding entry evaluates satisfied per §5's kind ×
   operation table — the holder matcher (the v2 `holder` entry; v1 `holder`
   claim) covers `access_cert.holder`; a `requester` entry requires the
   assertion's `req_origin` to be present and equal to its `origin`
   (invariant 13) — and `warrant.audience` == the RP audience.
7. **Enforce constraints** (§4.7). For each presented cert carrying a
   `constraints` claim (access cert, config cert), check the presentation
   satisfies it: the RP audience against `aud` (by salted hash), the warrant
   against `scopes` and `max-ttl`. A constraint key the verifier does not
   implement ⇒ reject — fail-closed.
8. **Three fail-closed status authorities.** Check the revocation ref on each of
   the three objects that carries one — the **access cert** (→ its IdP, per-device
   index), the **config cert** (→ its IdP), and the **warrant** (→ the warrant
   registry its own `status.uri` names). All three checks are **fail-closed** (§6.3).
9. Return the attributed identity (grantor), the grantee (actor of record), the
   grantor and grantee issuers, the `holder`, and the scopes.

A conforming verifier performs **every** step. In particular, accepting anything
but exactly the four-object bundle (step 1), skipping the per-identity issuer
authority check (step 2), waiving a constraint (step 7), or honoring any object
without its fail-closed status check (step 8) is non-conforming.

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
step 8):

- the **access cert** → its **IdP**, rooted at the **issuing device's** status
  index (revoking one device kills its access certs, not the whole identity);
- the **config cert** → its **IdP**;
- the **warrant** → the **warrant registry that allocated its ref** (per-grant
  index, so the user revokes one audience grant without touching the others;
  registry-api-v1 — the ref's `uri` names the authority).

Because every access cert is **IdP-gated online at mint** (§4.2), the
authentication path is already fresh at issuance; the status refs give sub-TTL
revocation of live sessions. A ref carries:

```json
"status": { "uri": "https://<authority>/.well-known/browserid-status", "idx": 42 }
```

- `uri` names a **signed status list** published by the authority; `idx` is the
  credential's position in it. Issuers allocate **one index per device** for
  access certs (stable across re-mints, so one bit kills a device's outstanding
  access certs) and the warrant registry allocates **one per warrant grant**
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

**Distribution to web RPs.** The broker exposes two convenience endpoints so
RPs can consume status without implementing list verification:

- `POST /status/check` (`{refs: [{uri, idx}, …]}`) — the fail-closed re-check
  an RP backend runs on session activity, using the `status_refs` returned by
  `/verify`. An `ok: false` (any ref uncheckable) MUST be treated as
  revoked.
- `GET /status/proxy?uri=…` — serves the **verified** list token at `uri`
  from the broker's cache (its own list by redirect). This exists for the RP
  *page*: a browser fetching a primary IdP's list directly would send the
  page's `Origin` and the user's IP to that IdP, disclosing the RP↔user
  association the protocol otherwise avoids. Routing the poll through the
  broker adds no information anywhere: the broker already participated in the
  login, and the primary IdP sees only the broker's aggregate cache-refresh
  fetches. Because every proxied response must parse and verify as an
  issuer-signed status list, the endpoint cannot be used as a general fetch
  proxy.

### 6.4 Admission: record validation + subject matching (operation A)

In operation A the resource **holds** the record (obtained per §7.5); nothing
presents the warrant — it is the row an independently authenticated subject is
matched against. Three steps, each fail-closed:

1. **Validate the record** (on acquisition; status re-checked per use, below):
   a. parse; `typ` is `browserid-warrant-v2` (or v1, as a holder-binding
      record, §5); a non-empty `binding` set, every entry of an implemented
      kind (and, for `connection`, an implemented `protocol`); `status`
      present (v2);
   b. resolve `config_cert.iss` **via the authenticated DNSSEC record** (§3);
      require it authoritative for the grantor's domain (§8.1 fallbacks apply
      as in §6.1 step 2); verify the config cert (unexpired, `purpose ==
      authorization`, `identities` cover `warrant.grantor`);
   c. verify the warrant under the config cert's `public-key`; unexpired;
      `audience` == this resource (exact); if the binding set contains a
      `connection` entry, or has more than one entry, `grantor == grantee`
      (§5, §6.6 invariants 4 and 10);
   d. enforce config-cert constraints (§4.7) in full, exactly as §6.1
      step 7: this resource's audience (== `warrant.audience`, step 1c)
      against `aud` (by salted hash), and the warrant against `scopes` and
      `max-ttl`; a constraint key the verifier does not implement ⇒ reject;
   e. check the revocation ref on each chain object that carries one, each
      check **fail-closed** (§6.3): the config cert (→ its IdP) and the
      warrant (→ its warrant registry, per its `status.uri`; the warrant's
      ref is always present on v2, optional on v1).
2. **Authenticate the subject** by the binding's method: the custody
   protocol's dance (`connection` — e.g. the OAuth redirect-URI + PKCE
   mechanics, §5), or a browserid login (`holder`). The authenticated
   artifact is the subject's **own** credential — it may itself be a
   presentation (a §7.3 login bundle) — never the held record.
3. **Match** the subject against grantee + every binding entry (per §5's
   kind × operation table — entries are conjunctive):
   - `connection`: the authenticated dance is the one bound to `binding.id`
     (the 1:1 rule, §6.6 invariant 5) and satisfies the `protocol`'s
     normative checks (§5 — for `"oauth"`: exact-match registered redirect
     URI whose host equals `binding.client_host`, PKCE S256);
   - `holder`: the login's identity matches `grantee` (exact per §5's
     identity comparison, or per a grantee matcher — permission only, never
     attribution, §5) AND the holder matcher covers the login's holder;
   - `requester`: unsatisfiable in operation A (§5's table) — a set
     containing one fails the match.

   A matching step that cannot be evaluated (an unknown binding; a non-`*`
   matcher against a holder-less authentication) MUST fail closed; `*`
   imposes nothing.

**Record validation authenticates no one** — it establishes only that the
record is authentic and unrevoked. Redemption authority is custody plus
subject matching, both of which happen at the resource; anyone else holding
the record holds attributed paper (a warrant is not a secret, §5) — readable,
spendable nowhere. The hosted verifier therefore exposes record validation as
a two-object call (`warrant ~ config_cert`, steps 1b–1e) beside
`/verify`, requiring no caller authentication.

Validation MAY be split: the signature, resolution, and constraint checks of
steps 1a–1d — **excluding their validity-window clauses** — are immutable and
MAY be checked once at acquisition. Per use, the verifier MUST re-check
fail-closed both the status refs (1e, within the §6.3 cache window) and that
the warrant and config cert are unexpired (the validity clauses of 1b–1c): a
held record authorizes until its `exp` or its revocation, whichever comes
first — expiry is a live bound, not an acquisition-time fact.

**Freshness-backed minting.** Presentation fails closed by construction — the
actor must return to an online, IdP-gated mint every access-cert TTL — while
a held record's live checks are things the resource must remember to run.
Where a resource mints derived credentials (bearers) from a held record (the
OAuth lane's embedded AS), admission MUST get the same forced online loop, at
the one periodic transaction its topology already has — the bearer mint:

- Bearers minted from a held record MUST be short-lived (reference: ≤ 1 h,
  always ≪ the record's remaining life).
- A mint or refresh MUST be backed by evidence **no older than the bearer it
  produces**: status-list tokens (§6.3) covering the record's and the config
  cert's refs, plus the validity-window checks of 1b–1c. No fresh evidence ⇒
  no mint — refresh fails, and the connection goes dark within one bearer
  TTL.
- The AS SHOULD retain, per mint, the snapshot it relied on: a disputed
  admission then audits as record + config cert + the signed status snapshot
  backing the bearer — §6.2's "valid as of T" pairing, applied to admission.

This converts the failure mode of an honest-but-lazy resource from "honors
silently until `exp`" into "connections die within one bearer TTL", bounds
worst-case revocation latency at bearer TTL rather than record life, and
shrinks the diligence surface from every per-call path to the one mint
chokepoint the reference lane ships. It cannot make a willfully non-checking
resource check — nothing can; the resource fronts the tools — but
non-compliance becomes auditable rather than invisible.

The same record may serve **both** operations when its binding allows: "G
authorizes `alice@gmail.com` (holder `*`) at `/notes`" can be held by the
resource and satisfied by Alice's login (A), or presented by Alice's agent
with her access cert (P). The authority is identical and P is the stronger
proof; nothing is gained by forbidding either.

*Design note — why both operations exist.* The two operations are the
capabilities/ACL duality: P is authority that **travels with the actor** —
self-contained, verifiable by anyone, anywhere, later; A is authority that
**sits at the resource** — a signed row, right for anonymous-client rails
where the resource is the enforcement point anyway. Neither subsumes the
other: admitting an email subject means authenticating a browserid login,
which *is* a presentation — the regress bottoms out at P, and A is a
composition pattern over it for subjects that cannot present. Conversely,
dropping delegated P would lose stateless first contact (a presenting agent
verified cold, no registry), third-party/offline verifiability (§6.2 — an
admission decision is only a local yes in the resource's logs), the actor as
an independently accountable principal (its own certs and revocation axis:
two kill switches on orthogonal authorities, where an admission has exactly
one), and non-interactive actorhood (§7.4 → §7.2).

### 6.5 Composition: policy records × connection records

The shared-resource scenario — admin G grants member E access to resource R;
E later connects via an anonymous host — is a **two-record chain**, each
record signed by the party who knows its contents at signing time; no signed
object is ever amended or late-bound:

1. **Policy record** (G-signed, at grant-authoring time, §7.5):
   `{grantor: G, grantee: E, binding: {kind: "holder", matcher: "*"},
   audience: R, scopes: S}`. G knows E, R, S — and nothing about future
   connections.
2. **Connection record** (E-signed, at connection time, §7.5):
   `{grantor: E, grantee: E, binding: {kind: "connection", id: C, …},
   audience: R, scopes: S′}`. Born when the connection C is born, at E's own
   consent card.

Admission at R conjoins them: authenticate the dance bound to C (§6.4 step
2); C's record is signed by E; E matches a policy record's grantee (exact or
matcher); **effective scopes = S ∩ S′**. Rules:

- **Attribution vs. permission.** The connection record's signer (E) is the
  *attributed* identity — E acted. The policy record's grantor (G) is the
  *permitter* — the reason it was allowed, never the author. Audit rendering:
  "E, via <client> (<host>), under G's grant." The self-serve case G = E is
  the degenerate one where the distinction is invisible.
- **Two-sided revocation.** E revokes the connection record at E's account
  (kills E's own connection, touches nothing else); G revokes the policy
  record (kills E's access through every connection). Each side holds its own
  registrar bit (§6.3).
- **Joined on the email, deliberately NOT by cryptographic cross-reference.**
  Both records are independently signature-verified, so the join is as strong
  as its parts — the email is the protocol's join key. Embedding a
  policy-record hash in the connection record would freeze policy at
  connection time; policy must evolve independently (G edits E's scopes;
  every existing connection of E's picks up the change at its next check, no
  re-consent; either side revokes without touching the other).
- **The chain is exactly two layers, fail-closed.** Policy records (who may
  enter) and connection records (which custody channel, attributed to whom)
  conjoin at admission; records MUST NOT confer the authority to mint further
  records. (General delegation chains are deliberately out of scope.)
- **The resource is the custodian and conjunction point.** It holds both row
  sets, binds any bearer/refresh state to the (binding.id, connection record)
  pair, and evaluates the conjunction per call — status and validity-window
  re-checks fail-closed on both records (§6.4), then S ∩ S′. The connecting user NEVER holds the policy
  record — it is not a ticket they carry; it travels G → broker → resource
  and stays there. Admission records are never "presented later"; for audit,
  both records are independently verifiable artifacts the resource can hand
  over.

A resource MAY keep its policy layer as unsigned local configuration (a roles
table) instead of policy records; the conjunction semantics are the same —
config-row policy and record policy answer the same admission question.

### 6.6 Warrant-v2 invariants

A conforming implementation MUST uphold all of these:

1. Operation P requires a `holder` entry, no `connection` entry (§5's kind ×
   operation table), AND an exact (non-matcher) grantee; a
   `connection`-bound or matcher-grantee record MUST NOT verify in a
   four-object bundle. (Mechanically guaranteed — no holder matcher ⇒ §6.1
   step 6 cannot pass — and stated explicitly at §6.1 step 1.)
2. Conforming v1 verifiers already reject v2 objects (unknown `typ` ⇒ reject,
   §6.1 step 1): downgrade protection at every deployed verifier is by
   explicit rule.
3. A v2 record without `status`, without a non-empty `binding` set, or with
   any binding entry of an unimplemented `kind` (or connection `protocol`)
   MUST be rejected. Signing surfaces MUST refuse to mint such records, and
   likewise any record whose channel set satisfies no operation (§5, dead
   paper).
4. A `connection`-bound record MUST be a self-grant (`grantor == grantee`).
5. **`binding.id` is 1:1 with its record:** the id is minted by the broker in
   one consent flow and bound to the record signed in that same flow; the
   resource MUST bind bearers/refresh to that (id, record) pair, and any
   other record naming the same id is invalid. The registry stores the
   pairing, making conflicts detectable.
6. Grantee matchers (`*`, `*@<domain>`) are permission, never attribution: a
   matcher-grantee record MUST NOT be the source of the attributed identity,
   and its subjects MUST still be authenticated (no anonymous admission).
   `grantor` MUST always be exact.
7. In operation A, a subject-matching step that cannot be evaluated MUST fail
   closed.
8. Record validation authenticates no one. Only presentation (P) or the
   binding's subject authentication (A step 2) establishes an acting party.
   Bindings are never identities and appear nowhere identities live.
9. A **wallet** (§5) MUST NOT sign for an external request except under a
   stored, valid, unrevoked record whose channel set, `grantee`, `audience`,
   and `sign:` scope all cover the request, honoring the scope entry's
   parameters. No covering record, an unevaluable check, an unclassifiable
   object, or a prompt-mode scope on a wallet with no interactive surface ⇒
   refuse.
10. A signing grant is a self-grant (`grantor == grantee`) with an exact
    grantee and the channel set {`holder`, `requester`} — by §5's kind ×
    operation table it operates in op P only. A delegated record (grantor ≠
    grantee) MUST carry exactly one `holder` entry: multi-entry sets are
    self-grant-only (the labeled doors, §5).
11. Wallets MUST NOT author warrants without a **consent ceremony** — the
    standing grant card and a per-request approval are both ceremonies;
    signing on the say-so of a message alone is never one. A request can
    only match an existing record or trigger a ceremony.
12. A `sign:`-scoped record is never reusable as any other grant type, and
    vice versa. (Often also blocked mechanically — an SBO grant's audience
    is a ref no login verifier accepts — but the rule is stated, not
    inferred.)
13. A presentation under a record carrying a `requester` entry MUST have the
    requesting channel stamped in its assertion (`req_origin`); conforming
    verifiers MUST match the stamp against the entry, fail-closed.
14. **Unknown means reject.** A consumer of set-form records — any record
    whose `binding` is an array or whose `scopes` carry object entries —
    MUST reject one carrying a claim, channel kind, or scope parameter it
    does not implement. Adding one is therefore a versioned change — a new
    `typ`, a new shape old parsers reject (the binding array itself), or a
    capability the consumer explicitly advertises — never a silent addition.
    Consequence: a restriction the signer believes in can never be ignored
    by a deployed consumer. (For these records this deliberately supersedes
    the working assumption that verifiers ignore unknown claims — §5
    "Bindings".)

## 7. Issuance & obtaining credentials

This section is what an **IdP** and a **client broker** implement; a plain **RP**
(which only verifies, §6) can skip it. It covers how a holder — a browser, an
agent, a service — gets its device certs, mints access certs, and obtains warrants.
The holder type never changes the machinery; only *how the holder authenticates*
differs (interactive login §7.3, or device-grant §7.4).

### 7.1 Device-cert issuance

**Every IdP MUST implement device-cert issuance for both purposes**
(`authentication` and `authorization`). The IdP authenticates the holder, then
signs one or more **device certs** (§4.1) for keys the holder generated locally
(ideally non-extractable, so a private key never leaves the holder). A single
authenticated request MAY return a batch — an `authentication` device cert together
with a `authorization` config cert — so a login yields both the ability to mint and
the ability to authorize in one step; it MAY also return an auth cert alone, for a
holder that should be able to log in but not create warrants (§7.5). How the holder
authenticates is the IdP's choice: an **interactive login** for a browser (§7.3),
or the **device-grant** for a headless holder (§7.4).

### 7.2 The access-cert mint

**Every IdP MUST implement the access-cert mint.** The holder signs an **access
request** (§4.2) with its `authentication` device key and posts it to the mint
endpoint. The IdP verifies the device cert online —
own signature, unrevoked, in validity, and the requested identity in its list
(exact-match; subaddressing does not widen the mint, §4.6) — and returns a
short-lived **access cert** certifying the request's fresh key, carrying the
device's holder verbatim. The IdP MAY refuse even a nominally-valid device cert
(abuse or compromise), in which case the holder re-authenticates.

The mint is where a managing domain applies **current policy**: constraints in
the minted access cert (§4.7) are decided fresh at every mint — there is no
standing vocabulary anywhere durable. The device cert contributes only the
`managed` marker (§4.1), which MUST already be set for any identity whose mints
the IdP constrains.

If the access request names an `audience` (§4.2 — managed identities only, and
only from a client whose device cert is marked), the IdP MAY scope the minted
cert to exactly that audience, and a holder MAY hold **several concurrent
access certs** for one identity — one per audience — with the client minting
more as needed. A refusal then surfaces policy at login time ("this identity is
not permitted at this site") rather than as an opaque verifier reject. Absent
the marker, a client MUST NOT send `audience` and an IdP MUST NOT require or
honor it: for unmanaged identities the mint stays RP-blind.

Minting online on a fresh key each time is what lets a credential be **cookie-free**
(no session cookie to lose to browser storage policies) and lets a headless holder
**mint with no browser and no user present**.

### 7.3 Interactive login: the web exchange

For a browser RP, obtaining a presentation is an interactive exchange, kept
**first-party** so signing keys never leave the origin that holds them:

1. The RP invokes a **login mediator** — today a small script it includes; a
   native browser federated-login API could serve the same role. The invocation
   carries an optional **`acceptedFallbacks`** list (§8.1): the fallback IdPs the
   RP will accept for a no-primary email. It is a call argument, not fetched from
   the RP.
2. The mediator opens the identity flow in a **first-party popup**. There the
   holder authenticates to its IdP, obtains its device cert(s) (§7.1), mints an
   access cert (§7.2), and assembles the bundle — signing the assertion, and, **if
   it holds a config cert**, a fresh login **warrant** for this audience. A holder
   issued only an auth cert instead presents a **preexisting** warrant whose
   holder-matcher covers it (§7.5). Each signing step happens in the origin that
   holds the key.
3. The mediator returns the **presentation bundle** (§5) to the RP, which verifies
   it (§6).

`acceptedFallbacks` only routes the exchange and lets it fail fast; it grants
nothing, because the RP's verifier independently enforces its trusted-issuer set
(§8.1).

**Session signals.** The mediator exposes an observer contract to the RP page
(in the reference shim: `navigator.id.watch()`); every presentation, whatever
path it arrived by, is delivered through the same login observer. Three rules
govern it:

- **No silent minting.** A presentation is only produced by an explicit
  user-triggered exchange (steps 1–3 above), with one exception: a
  **browser-mediated** auto-reauthentication API (FedCM), which is opt-in per
  user, shows the browser's own UI, and is invisible to the RP — the RP
  neither requests nor observes the mechanism. There is no hidden-iframe or
  storage-probing reconciliation; a page load without one of these paths
  fires only a *ready* signal ("the automatic phase has settled").
- **Logout is symmetric with login.** The RP's logout call routes through the
  logout observer (in every same-origin tab, via a same-origin broadcast) and
  tells the identity layer to disable auto-reauthentication, so a logged-out
  user is not silently signed back in.
- **Revocation is observable (UX), enforced server-side (security).** At
  login the mediator MAY retain the presentation's status refs (§6.3) — 
  pointers, not credentials — and poll them through the broker's status proxy
  (§6.3) to deliver a logout signal to open tabs when the issuing device is
  revoked. This signal is advisory; the RP's backend re-checks the same refs
  (fail-closed) on session activity.

### 7.4 Headless issuance: the device-grant

A headless holder (an agent or service) generates its keypair off-browser and
cannot authenticate to the IdP interactively. Instead the **user authorizes** the
issuance:

1. The holder presents its device **public key** to the user's client broker (a
   pairing / device-grant hand-off).
2. The user approves the constraints — the `identities` (one email, several, or an
   explicit `user+*@domain` glob), the **holder** (assigned by the broker in the
   account's `agents`/`services` namespace; the holder cannot choose it), and the
   validity.
3. The IdP signs the device cert directly (§4.1) — it is the direct issuer, gated
   only by the user's approval.

An **IdP that issues to headless holders MUST support the device-grant.** It SHOULD
enforce a per-user quota of active headless device certs (reference default: 25),
and MAY refuse issuance. The holder then mints access certs headlessly (§7.2).
Attribution lives in the identities the holder acts as and, at presentation, in the
warrant's grantor/grantee (§5).

### 7.5 Obtaining warrants

A warrant (§5) authorizes a `grantor → grantee` at one audience, signed by the
grantor's **config cert** client-side — so only a party holding a config cert can
create one. The IdP never sees an audience or scopes; the signed warrant is stored
in the user's warrant registry (registry-api-v1) for device-agnostic reuse
(§5) and per-grant revocation (§6.3).

Presentation-consumed warrants reach their grantee's holders as below;
admission-consumed records (§6.4) instead reach the **resource** that will
hold them, through two further flows at the end of this section —
**connection grant requests** (audience-initiated) and the **grant-authoring
ceremony** (grantor-initiated).

How a holder comes to present a warrant depends on what it was issued:

- **A holder with a config cert** signs its own warrants — at an interactive login
  the browser signs a fresh login warrant in the popup (§7.3), and it can author
  warrants for other holders it grants to.
- **A holder with only an auth cert** (least privilege — a login on a shared
  machine, or a headless holder not trusted to authorize) cannot create warrants. It
  presents a **preexisting** warrant whose holder-matcher covers it (e.g. a standing
  grant to the `browsers` category), and obtains new ones through the just-in-time
  consent flow below, where a party holding the config cert (the user, at their
  broker) signs on its behalf.

The **just-in-time consent flow** lets a holder obtain a warrant with the user
approving out of band. A **registry that serves such holders MUST host this
flow alongside the warrant registry** (registry-api-v1). It keeps the shape of
the OAuth device authorization grant (RFC 8628):

1. **Request.** The holder posts an object signed by its device key, naming its
   identity (the prospective grantee) and **1–8 grants**, each a
   `{ audience, scopes }` (duplicate audiences MUST be rejected). Two optional
   fields shape the consent: **`grantor`** pins whom the warrants attribute to
   (absent or `*`: the approver chooses; `self`: the holder itself; a concrete
   email: that identity — a pin is **never silently substituted**, and an
   unsatisfiable pin fails the request immediately); **`message`** is the holder's
   own ≤500-char rationale, shown quoted and marked unverified. The broker verifies
   the signature against the holder's device cert and returns a `code`,
   `verification_uri`, `expires_in`, and `interval`.
2. **Consent.** The broker serves the consent page at `verification_uri` to the
   signed-in user only. It MUST show the holder's identity and **user-chosen
   display name** (the requester's own label only ever shown marked unverified),
   and — for **every** grant, each with equal prominence — the **verified audience**
   and its requested scopes, prefilled from the request, never user-typed. A
   request from a holder the account has never met MUST render a deny-only card
   (the poll learns a machine reason, e.g. `unknown_agent`). Approval MUST be
   deliberate (no default-focused button) and is all-or-nothing over the displayed
   set; on approval the page signs one warrant per grant with the config cert and
   records each in the registry.
3. **Poll.** The holder polls with `{ code }`: `pending` → retry after `interval`;
   `approved` → the warrants (one per grant, in order); `denied` (optionally with a
   machine reason); `expired`; or `429` if polling faster than `interval`. `code`
   is single-use, ≥ 128-bit, short-lived; the pending request is deleted on
   delivery, while the issued warrants persist in the registry.

**Two-stage provisioning.** A single hand-off MAY both issue the device cert
(§7.4) and grant warrants, approved in two stages under one code: an **identity
stage** (verify the pairing, mint the device cert — no "permission" language) then
a **grants stage** (the consent question above, identity fixed). Declining the
grants stage is honest, not fatal: the identity exists, and the pickup delivers the
credential with no warrants and a `grants_denied` reason.

**Connection grant requests.** The signed-request gate above assumes a
requester holding a device key. A `connection`-bound record (§5) has no such
requester — the host is anonymous — so the request is raised by the
**audience** (the resource) itself and authenticated by **proof of audience
control**:

1. **Request.** The resource POSTs `{ type: "connection", audience, scopes,
   client: { client_host, client_name }, message? }`. Exactly **one** audience
   per request (this flow is per-connection; the 1–8 batching above does not
   apply). The broker replies with `request_id`, a `challenge` nonce,
   `consent_uri` (the page the connecting user must visit), `expires_in`, and
   `interval` — the same pending-request machinery as the JIT flow, keyed by
   `request_id` in place of `code`.
2. **Audience proof.** The resource publishes the nonce at
   `https://<audience-origin>/.well-known/browserid-audience-proof/<request_id>`;
   the broker fetches it over TLS — redirects refused, connections only to
   public unicast addresses (loopback, private, and link-local ranges
   refused at resolution time), short timeout, fail-closed — before the
   consent page will render. The document body is the challenge nonce
   verbatim (`Content-Type` SHOULD be `text/plain` and is otherwise
   ignored); the broker compares it byte-for-byte after stripping trailing
   ASCII whitespace, and the resource MUST keep it published until the
   request resolves or expires. The proof establishes origin control, rooted
   in WebPKI — the same root the audience string itself relies on. For
   **path audiences** the proof is at origin scope — the same scope at
   which WebPKI names the audience; a path tenant that does not control its
   origin has no independent identity in this model. The card always
   renders the **full audience**, path included.
3. **Consent (connection variant).** The card names the **connection**, not a
   requester: "Connect <client_name> (<client_host>) to <audience>. It will
   be able to use: <scopes> — attributed to you. Revocable here." The
   verified audience is rendered with the same anti-phishing prominence as
   above; `client_name` MUST be marked as reported by the site — the broker
   cannot verify the host's involvement and the card MUST NOT imply it did
   (the client binding is enforced by the audience's redirect-URI + PKCE
   mechanics, §5). Approval mints `binding.id`, signs the **self-grant**
   record with the approver's config cert, and stores the registry row — the
   `id ↔ record` pairing (§6.6 invariant 5) plus the status index.
4. **Delivery.** The resource sends the connecting user's browser to
   `consent_uri` (in the OAuth lane, as a step of its own authorize
   redirect) and polls with `{ request_id }` under the JIT flow's state
   machine: `pending` → retry after `interval`; `approved`; `denied`
   (optionally with a machine reason); `expired` (after `expires_in`); `429`
   if polling faster than `interval`. `approved` delivers the signed record
   **together with the grantor's signing config cert** — exactly the
   two-object `warrant ~ config_cert` input §6.4 validates — to the
   resource, which is the record's custodian (§6.5).

The stakes of a forged request are bounded: an attacker-raised record is
redeemable only by the genuine audience, inside a custody dance that audience
initiates — the attack is annoyance-phishing, not authority theft. The proof
keeps the consent surface clean; it is not guarding a vault. The broker
SHOULD rate-limit connection requests per audience origin.

**Grant-authoring ceremony (grantor-initiated).** Policy records (§6.5) are
authored the other way around: the grantor initiates, and the resource —
which holds no config cert and MUST never sign — compiles its access policy
(e.g. a role edit in its console) into flat per-(grantee, audience) grants.
The wire shape mirrors the connection flow:

1. **Request.** The resource POSTs `{ type: "authoring", grants:
   [{ grantee, audience, scopes }, …] }`. All grant audiences MUST share one
   origin (the proof below is origin-scoped); duplicate (grantee, audience)
   pairs MUST be rejected. The broker replies with `request_id`, a
   `challenge` nonce, `consent_uri`, `expires_in`, and `interval`.
2. **Audience proof.** As the connection flow's step 2 — same URL scheme,
   fetch rules, and document format, keyed by this `request_id`, at the
   grants' shared origin. Same bounded stakes; the proof keeps the consent
   surface clean.
3. **Consent.** The resource sends the grantor to `consent_uri`. The broker
   renders the compiled set under the **just-in-time flow's** consent rules
   above (verified audience per grant with equal prominence, prefilled and
   never user-typed, deliberate all-or-nothing approval) — and, because rows
   here name other people, the card MUST render each row's **grantee** with
   the same prominence as its audience and scopes. Approval signs each
   record with the grantor's config cert; each gets its registrar status
   index and lands in the registry (the grantor's account ledger).
4. **Delivery.** The resource polls with `{ request_id }` under the same
   state machine as the connection flow; `approved` delivers each record
   with the grantor's signing config cert — the `warrant ~ config_cert`
   pairs §6.4 validates — and the resource stores the set as its policy
   backing store (§6.5).

A policy edit is revoke-old + sign-new in one ceremony; roles remain a
resource-side abstraction — the protocol sees only flat records.

**Signing grants (wallet ceremony).** A signing grant (§5) is authored where
the wallet is: the requesting site opens the user's wallet surface (in the
reference deployment, the broker login dialog) declaring the audience(s) and
`sign:` scopes it asks for, and after sign-in the wallet renders the standard
consent card — verified requesting origin, identity, audience, and a verb
per scope, prompt-mode scopes called out. Approval signs one record per
(requester, audience) with the config cert, registers it (status index,
account ledger row), and stores it at the wallet; the `requester` origin in
the record is the one the wallet itself authenticated, never a declared
value. No audience proof is required (contrast the connection flow): the
request arrives through a surface the requesting site itself opened, so the
browser-verified origin authenticates the requester, and the record is a
self-grant — a forged request buys only consent spam, the same bounded
stakes as above. Where config keys are device-resident, each device signs
its own record on first use — one card per device, the posture holder
channels already impose.

The consent page is the trust boundary against consent-phishing: it MUST render the
verified target origin (not only a friendly name), and approval MUST be deliberate.

### 7.6 Managing issued certs

An IdP SHOULD expose authenticated surfaces (in the user's client broker) to
**list** a user's active device certs and **revoke** one. Revoking flips the cert's
`status` bit (§6.3), so it mints no further access certs and its outstanding access
certs are rejected fail-closed within one access-cert TTL. Holders and identities
are never recycled.

## 8. Fallback IdPs

An email whose domain has no primary IdP (§7) is vouched for by a **fallback
IdP** — a party that verifies control of the email (by an SMTP challenge, or
another supported proof of control where applicable) and then issues **device
certs** (both purposes) and runs the **mint API** for it,
all under its own `iss`, published under its own `_browserid` DNSSEC key, so
every object verifies through the same DNSSEC-rooted path (§3) as any primary.
`browserid.me` is the reference fallback; it also operates the reference
**registry** (warrant registry / revocation UI / status endpoints — §6.3,
registry-api-v1). Those are two independent roles it happens to co-host: either
can be replaced without the other, and neither is a mandatory party — any
DNSSEC-publishing domain can run a fallback, and an RP chooses which fallbacks
it accepts (§8.1).

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

## 9. Grant exchange (optional)

> **Optional, and served by the RP.** These endpoints live on the **relying
> party**, not on any IdP or broker — so there is nothing here for a broker to
> implement. An RP that verifies a presentation (§6) and mints its own session
> however it likes needs none of this; it is a convenience for **API relying
> parties** that want a standard OAuth-shaped token swap, and it applies equally to
> any holder.

An RP MAY opt in with one endpoint that exchanges the presentation bundle (§5) for
the RP's own token (RFC 7521 assertion-grant shape). Grant type:
`urn:x-browserid:grant-type:assertion`.

- **In-band discovery.** An unauthenticated request to a protected resource returns
  `401` with a `WWW-Authenticate: BrowserID` challenge carrying `audience`
  (REQUIRED — the exact audience assertions and warrants must name; the RP is the
  sole authority for it), `token_endpoint` (REQUIRED, absolute URL), and optional
  `scopes` and `realm`. Unknown parameters MUST be ignored.
- **Token endpoint.** `POST <token_endpoint>` (`application/x-www-form-urlencoded`)
  with `grant_type=urn:x-browserid:grant-type:assertion` and `assertion=<bundle>`.
  The RP MUST verify the bundle per §6 before issuing a token, and MUST NOT grant
  authority beyond the intersection of the warrant's `scopes` and its own. Success
  is an OAuth-shaped `{ access_token, token_type, expires_in, email (=grantor),
  grantee, scopes }`; failure a `400` with `invalid_grant` /
  `unsupported_grant_type`.
- **Out-of-band discovery.** RPs SHOULD serve
  `/.well-known/oauth-authorization-server` (RFC 8414) advertising the
  `token_endpoint`, the grant type, and `scopes_supported`.

## 10. On-chain attribution (external module)

Attributing an email identity to an `ed25519:` key on a ledger is built on the
offline-verification primitive (§6.2) and specified **separately** as the
attribution module: its concepts are ledger-specific, and it depends on this
protocol, not the reverse. This is the one capability that lives outside this spec,
because its trust anchors and dependency direction are genuinely distinct.

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

