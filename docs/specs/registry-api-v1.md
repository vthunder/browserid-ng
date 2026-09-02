<!-- This Source Code Form is subject to the terms of the Mozilla Public
     License, v. 2.0. If a copy of the MPL was not distributed with this
     file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Registry API v1

> **Status: draft.** The wire API of the **registry** role: the service
> that records a user's devices, holders, and warrants, carries pending
> consent requests, and operates their revocation status list (core
> §6.3). An independent registry can be implemented from this document
> alone; the hosted broker is merely its first host. Out of scope:
> issuance (fallback-IdP API), the browser cookie lane, the agent-facing
> request/poll lanes (core §7.5), and hosted conveniences.

Cross-references written as `core §N` refer to `browserid-ng-protocol.md`.

## 1. Overview

A self-contained API for the registry role, so the user-agent half can
live anywhere. Principle 7 (openness lives in the ability to leave) is
the driver: a conformant registry is replaceable.

- **Auth**: every call carries a device cert and a proof signed with
  its key (§3). No sessions, no tokens, no exchange: the cert's
  identity names the account, its flavor sets its authority.
- **Revocation rides the device cert**: revoking a cert kills its
  access on next use, fail-closed.
- **Consent is API-complete**: approval carries the same client-signed
  warrants as the browser consent page (§5.1, §10 decision 0).
- **No CSRF** — auth is header-borne, never ambient.

## 2. Actors and terminology

| Term | Meaning |
|---|---|
| **Registry** | The service implementing this API. |
| **User agent / wallet** | The client: holds the account's device keys, builds presentations, renders consent UI. Loyal to the user (principle 8). |
| **Account** | The registry-side record owning identities, devices, and warrants. Created and changed only by §5.6 `attach`; authenticated by any of its device certs (§3) or the legacy cookie lane. All of an account's identities are equals — "which identity authenticated" is a per-call fact, never a rank. |
| **Auth cert / config cert** | The two flavors of device cert (core §4.1): `purpose: authentication` mints access certs and has the recording tier here; `purpose: authorization` signs warrants and has full authority (§3). |
| **Presentation bundle** | `access_cert~assertion~warrant~config_cert` (core §5). |
| **Status list / status ref** | The registry's signed revocation bitfield and `{uri, idx}` pointers into it (core §6.3). |

## 3. Authentication

Every call is **cert-authenticated**: no sessions, no tokens. Two
headers:

```
Authorization: Cert <device cert JWS>
Proof: <proof JWS>
```

The **routing cert** in `Authorization` MUST pass the validity bar
(§7.1's `invalid_cert` reasons, in order, are the checks —
`401 invalid_cert/<reason>`, with `WWW-Authenticate: Cert`). The call
then acts as the account owning the cert's identity; no account owns
it ⇒ `401 invalid_cert/no_account` — except on `attach`, which is how
accounts come to exist (§5.6.2). Every call re-checks the cert's status
ref fail-closed; revoking the cert kills its access on next use.

**Authority follows the cert's flavor.** A config cert
(`purpose: authorization`) has the account's full authority. An auth
cert (`purpose: authentication`) has only the **recording tier**:
`attach` of itself (§5.6.2) and `warrants/fetch` (§5.6.5) — reads and
records that grant nothing a cert doesn't already have at RPs. Any
other call with an auth cert ⇒ `403 config_required`: a compromised
auth-only device cannot escalate (§5.6.6).

Registry-rooted ("secondary") identities authenticate like any other:
this API exposes no root op (issuance, passwords, `account_cancel` are
the fallback-IdP API's), so a self-issued identity reaching the inbox
reaches nothing it shouldn't (§10 decision 7).

Abuse controls (calls are anonymous until the cert verifies, and
verification is expensive): check the proof signature against the
cert's embedded key *before* resolving the issuer; rate-limit per
source address and per cert public key (`429 slow_down` +
`Retry-After`); bound body sizes (RECOMMENDED 64 KiB, API-wide). Issuer
keys and status lists are cacheable within their validity.

### 3.1 Request proof — `browserid-registry-proof-v1`

The `Proof` header is a JWS signed by the routing cert's key, header
`{"alg": "EdDSA", "typ": "browserid-registry-proof-v1"}` (both values
MUST be exact; agility is deferred to a future `typ`), claims:

| Claim | Meaning |
|---|---|
| `htm` | REQUIRED. Uppercase HTTP method. |
| `htu` | REQUIRED. Request URI: scheme, host, path — no query or fragment. |
| `iat` | REQUIRED. Seconds; MUST be within a small window (RECOMMENDED ±300s). |
| `jti` | REQUIRED. Unique random string; replays rejected within the window (cache keyed at least by proof key). |
| `bh` | REQUIRED on requests with a body; absent otherwise. base64url(SHA-256(body bytes)) — the mutation is client-signed down to its payload, which is what lets §5.6 need no separate consent artifact. |

`htu` builds on the registry's advertised **public origin** (§5.5
`endpoint`'s origin): lowercase scheme and host, default ports
omitted, then the exact §5 route path; behind a proxy, compare against
the public origin, never the observed URI. Verification order: cert
validity bar → proof signature against the cert's key → all claims →
authority tier. Any failure ⇒ reject (`401 invalid_proof` for the
proof's own failures).

The same shape serves as **possession proof**: where §5.6 requires
proof that the caller holds a *further* cert's key, the proof is this
exact JWS signed by that cert's key. Possession proofs travel in the
body, so they cannot carry `bh`; instead every proof in a request MUST
carry the header proof's `jti`, binding the set to one envelope; the
per-key replay cache makes each single-use.

### 3.2 Relationship to the cookie lane

The `/wsapi/*` cookie+csrf surface remains a second consumer of the
same registry role; §9 maps it. A cookie session minted from a
presentation carries delegated authority and MUST NOT be weaker than
this lane per operation (§8 invariant 1).

## 4. Common conventions

- Bodies are JSON, UTF-8. No `success: true` — status codes carry
  success, §7 the errors. Refusals are cited as `<status>
  <error>/<reason>`, e.g. `422 invalid_cert/config_required`: §7
  defines every `error`, §7.1 every `reason`.
- Data-free mutations return `204`; others `200` + JSON. OPTIONAL
  fields are absent, never `null`.
- Unknown request fields MUST be rejected; unknown response fields MUST
  be ignored (additive evolution, §8).
- GETs are pure — legacy hidden-GET mutations became explicit POSTs (§9).
- Timestamps: RFC 3339 UTC; JWS claims keep epoch seconds.
- No pagination in v1; response shapes leave room to add it.

## 5. Endpoints

Everything here is §3 cert-authenticated with a config cert, except
§5.5 discovery (public) and the recording-tier calls marked in §5.6. Field lists are normative;
example values illustrative.

### 5.1 Consent inbox

**`GET /api/v1/requests`** — open consent requests. Response:
`{ "status_uri": …, "requests": [ … ] }`. `status_uri` is the registry's
status-list URI — the `uri` half of the refs the client embeds in
warrants it signs (each grant's `status_idx` is the `idx` half).
Request items carry `code`, `delegator_email`, `agent_email`, `holder`,
`label`, `grantor` (`"*"` = approver chooses), `message?`,
`display_name?`, `agent_created_at?`, `known`, `grants`
(`{audience, scopes, status_idx?, grantee?}`), `external`, `kind`
(`"agent" | "connection" | "authoring" | "notice"`), `client_host?`,
`client_name?`, `binding_id?`, `created_at`, `expires_at`.

External requests (`external: true`) are returned only when their
`code` is passed (`?code=`) — visibility rides the 15-minute capability
code the redirect delivered; keep query strings out of logs. OPTIONAL
long-poll hint `?wait=<seconds>` (cap 60); answering immediately is
conformant. `kind: "notice"` items (§5.6.3) are informational: no
respond action, they expire on their own.

**`POST /api/v1/requests/claim`** — `{ "code": … }`. Claims a pending
record request and allocates status indexes into its grants (the legacy
GET's hidden side effect, made explicit). Returns the claimed request.
Precondition: the request's core §7.5 audience proof MUST validate at
claim time (fresh fetch RECOMMENDED; else `422 invalid_warrant/audience_unproven`).
Idempotent per account; claimed by another account ⇒ `404 not_found`.

**`POST /api/v1/requests/respond`** — approve or deny:

```json
{ "code": "…", "approve": true, "warrants": ["<JWS>", …],
  "config_cert": "<JWS>", "grantor": "dan@example.com" }
```

Deny: just `code` + `approve: false`. Approve: one client-signed
warrant per grant, in order, all-or-nothing; `config_cert` signed them;
`grantor` (OPTIONAL, default the agent itself) must be an account
identity matching the request's pin if set.

Validation MUST equal the browser lane's bar; §7.1's `invalid_warrant`
reasons, in order, ARE the checks (`422 invalid_warrant/<reason>`). On approve, per grant: store the
delivery string `{warrant}~{config_cert}` for single pickup by the
requester's core §7.5 poll, and upsert a §5.2 warrant record.

That bar covers `kind: "agent"`. The other kinds carry **admission
records** (core §6.4) per core §7.5: `"connection"` — each record a
connection-bound self-grant (`grantor == grantee`, the approver)
embedding the request's broker-minted `binding.id`; `"authoring"` —
each record matching its grant's `grantee` matcher, audience, and
scopes, approver as grantor. All are client-signed with the account's
config-cert key; the registry records consent, it cannot manufacture it.

Response: `200`, `{ "return_url": … }` when the request carried one,
else `{}` (including every deny).

### 5.2 Warrant registry

**`GET /api/v1/warrants`** — registered warrants. Items carry `id`,
`delegator_email`, `agent_email`, `audience`, `scopes`, `warrant`
(JWS), `status_idx?`, `revoked` (computed live from the bit),
`holder?`, `config_cert?`, `binding_id?`, `client_host?`,
`client_name?`, `requester_origin?`, `signed_at`, `expires_at`.

**`POST /api/v1/warrants/register`** —
`{ "warrant": "<JWS>", "config_cert": "<JWS>" }` → `204`. The warrant
MUST verify against the config-cert key; the cert MUST be
`purpose: authorization` and authorize the grantor; the grantor MUST be
an account identity — the §5.1 bar again, `422 invalid_warrant/<reason>`
per §7.1. Status-ref reconciliation: a ref on this
registry's own list is re-derived from the grant identity — match ⇒
bit reactivated; mismatch ⇒ recorded with no index (log the
discrepancy); foreign ref ⇒ recorded with no index.

**`POST /api/v1/warrants/revoke`** — `{ "id": 42 }` → `204`. Flips the
status bit, sticky (re-registering is the reactivation path). No status
ref ⇒ `409 conflict/no_status_ref` (remedy: reissue with an allocated ref).

**`POST /api/v1/warrants/forget`** — `{ "id": 123 }` → `204`. Deletes
the row **without revoking** — the signed warrant stays valid to
expiry. Legitimate for expired/ref-less/foreign-authority rows;
guard-rails for the destructive case: bean `d51o`.

**`POST /api/v1/warrants/allocate_status`** —
`{ "agent_email", "audience", "scopes" }` →
`{ "uri", "idx" }`. Idempotent and stable per
`(account, agent_email, audience, scopes-as-set)` — this is what lets a
wallet mint login warrants *with* per-site revocation bits. `audience`:
non-empty, no `*`, no whitespace/control characters, ≤512 bytes.

### 5.3 Devices

**`GET /api/v1/devices`** — the account's device certs: `id`,
`identities`, `purpose`, `holder`, `pubkey`, `iss`, `issued_at`,
`expires_at`, `revoked`.

Recording certs is not a separate endpoint: wallets record newly issued
certs with §5.6 `attach`, whether the identity is new to the account or
already on it. Issuer-side recording is an internal convenience wallets
MUST NOT rely on.

**`POST /api/v1/devices/revoke`** — `{ "id": 7 }` → `200`
`{ "revoked": bool }`. Owner-scoped. When this registry is the cert's
revocation authority (`iss` is its domain) it flips the bit — sticky.
For a foreign issuer it hides the cert but MUST answer
`{ "revoked": false }` so the client routes revocation to the issuing
authority. Self-revocation is allowed, not special-cased.

**`GET /api/v1/devices/status?id=7`** —
`{ "state": "revoked" | "active" | "unknown" }` (`unknown` = no status
ref). Foreign certs get a fresh fetch of the issuer's list — a network
side effect, not a state change.

### 5.4 Holders and namespaces

| Endpoint | Request → response |
|---|---|
| `GET /api/v1/holders` | → `{ namespaces: […], holders_without_namespace: […] }`. Namespace: `name`, `prefix`, `label`, `holders`. Holder: `holder_id`, `label`, `trust` (`"trusted" | "login-only"`), `cert_count`, `issued_at?`, `warrant_count`, `revoked`, `external`, `identities`, `moving_to?`. |
| `POST /api/v1/holders/rename` | `{ holder_id, label }` |
| `POST /api/v1/holders/move` | `{ holder_id, namespace }` → `{ new_holder }`. Destructive up-front: revokes every cert on the old holder (bits flipped), records old → new for `holders/assignment`, carries the label. |
| `POST /api/v1/holders/forget` | `{ holder_id }` → `{ unrevocable: [issuer, …] }`. Revokes-then-deletes; lists issuers it couldn't revoke at. |
| `GET /api/v1/holders/assignment?holder=` | → `{ status: "current" | "moved", new_holder? }` |
| `POST /api/v1/namespaces/create` | `{ name, label? }` |
| `POST /api/v1/namespaces/rename` | `{ name, label }` |
| `POST /api/v1/namespaces/delete` | `{ name }`. Refused while it has holders (`409 conflict/namespace_not_empty`). |

Validation: namespace `name` lowercased/trimmed, then
`^[a-z][a-z0-9_-]{0,31}$`; labels 1–64 Unicode chars, single line;
holders/namespaces addressable only when on the account (`404
not_found`, no existence leaks); `move` refuses external holders
(`409 conflict/external_holder`) and same-namespace moves
(`409 conflict/already_in_namespace`).
Implementations SHOULD also accept legacy names predating this spec.

### 5.5 Discovery

A new top-level `registry` object in the existing support document,
**`GET /.well-known/browserid`** (core §3.1). One document per origin;
serve the keys for the roles you play. A missing `registry` key means
"no registry API here"; unknown keys MUST be ignored (this rule is
hereby explicit for the whole document).

| Key (under `registry`) | Meaning |
|---|---|
| `version` | REQUIRED. Highest API version served. |
| `endpoint` | REQUIRED. Absolute URL prefix of this API (`…/api/v1`); MUST be same-origin with the advertising document. Its origin is the public origin §3.1 `htu` builds on. |
| `status_list` | REQUIRED. The registry's signed status list (core §6.3), same-origin. Advertisement only — verifiers reach lists through each status ref's `uri`, never discovery. |
| `browser` | REQUIRED (may be empty). Browser-ceremony URLs for flows a native wallet can't do natively; keys defined by the fallback-IdP spec (v1: `account`). |

No key material here (core §3.1: keys come solely from DNSSEC).

### 5.6 Account membership

Which identities an account owns is registry business; the credentials
proving them (passwords, mailbox codes, bridge proofs) are the issuer's
and never appear here. Two rules:

1. **Requests are self-authenticating.** Beyond §3's routing cert, a
   call carries further device certs plus possession proofs (§3.1),
   proving the caller holds every cert it names. The header proof's
   `bh` signs the exact payload — the call is its own consent artifact.
2. **Ownership follows the identity's voucher.** Freshly issued certs
   prove *current* ownership; an account that used to hold the identity
   is notified, never asked.

#### 5.6.1 The flows

**A. Bootstrap.** Issuer ceremony for dan@example.com → auth + config
cert. `attach` routed by the new config cert, the auth cert in the
body: no account owns the identity, the routing cert is a config cert →
account created. Every later call authenticates with these certs.

**B. Add a device — including auth-only.** A second machine (say a
shared computer deliberately issued only a short-lived auth cert)
attaches: routing cert = its own auth cert, empty body. Identity
already on the account → recorded: on the device list, revocable later. Recording
grants nothing (certs work at RPs regardless of registry rows), so
auth-cert possession suffices.

**C. Add or take an identity.** Ceremony for vthunder@gmail.com, then
`attach` routed by a **config** cert of the destination account, the
fresh certs in the body. If another account owns the identity, the §5.6.3
transfer effects run first, atomically; the response is identical
either way (no existence leak).

**D. Detach** (§5.6.4) — remove an identity; config-routed.

#### 5.6.2 Attach — `POST /api/v1/account/attach`

```json
{ "certs": [ { "cert": "<JWS>", "proof": "<JWS>" }, … ] }
```

→ `204`. Recording tier: the §3 routing cert is itself attached, and
`certs` (MAY be empty) lists further certs to attach, each `proof` a
possession proof (§3.1: same shape, that cert's key, the header
proof's `jti`).

Every body cert MUST pass the validity bar (`422 invalid_cert/<reason>`),
and no cert's holder may be moved (§5.4; `409 conflict/holder_moved`).
Then, per cert, routing cert included, by identity:

- **Already owned by the target account** → recorded: idempotent on
  pubkey, holder healing, default labels (§5.3).
- **Not owned** (new, or owned elsewhere) → **membership change**: the
  identity joins the account. Requires (i) a config routing cert —
  membership is an authorization act; auth-routed requests only record
  (`403 config_required`) — and (ii) joining certs freshly issued,
  `iat` within 300s (`422 invalid_cert/cert_not_fresh`): wallets attach
  right after the ceremony; stolen-but-unexpired cert bytes fail.

**Creation.** No account owns the routing identity → it is "not owned"
above, so the routing cert must be a config cert; with one, the account
is created around it (a first cert must be a config cert or the account
could never authorize anything).

#### 5.6.3 Transfer effects

When a joining identity is owned by another account, atomically before
the join:

- The losing account's device certs naming the identity — where this
  registry is their revocation authority — are revoked, scoped to that
  (account, identity) pair; its warrants with the identity as grantor
  are revoked; their access here dies fail-closed on next use.
- Its derived agent identities of the departed parent are **revoked and
  dropped** — never transferred; the winner provisions its own agents.
- It receives a `kind: "notice"` inbox item naming the identity; the
  registry SHOULD notify its remaining addresses out-of-band. Notified,
  never asked.
- If that was its last identity, the account is deleted (remaining
  devices and warrants revoked, then dropped).

The mailbox fence is upstream: the reference fallback issues certs for
a mailbox-verified address only under a session owning it, so inbox
control alone cannot produce these certs.

**Deployment note.** Where registry and fallback-IdP share an account
table, an attached address becomes a candidate password-reset channel —
a recoverable denial-of-service, not takeover. Deployments SHOULD
exclude newly added addresses from reset eligibility until the issuer's
own ceremony blesses them (bean dksx).

#### 5.6.4 Detach — `POST /api/v1/account/detach`

```json
{ "identity": "…" }
```

→ `204`. Config-routed; `identity` MUST be owned by the account.
Revokes
the identity's device certs this registry is authority for, its grantor
warrants, revokes-and-drops its derived agent identities, then removes
it. `409 conflict/last_identity`: detach has no destination — whole-account
deletion is the issuer's `account_cancel` ceremony. Derived children
are never a refusal; they go with the parent.

#### 5.6.5 Warrant fetch — `POST /api/v1/warrants/fetch`

`{}` → the registered warrants whose holder matcher covers the routing
cert's holder, for its identities, each alongside the config cert
needed to present it. Recording tier — the read that lets a device
with no config cert use preexisting wildcard-holder warrants (e.g. the
account's `browsers.*`). It serves only artifacts every RP sees at login. The registry
SHOULD record a first-seen cert as §5.3 inventory, so any device that
ever used the account is listed.

#### 5.6.6 Auth-only devices

| Capability | Auth-only device |
|---|---|
| Mint access certs; log into wildcard-warranted sites | yes — `warrants/fetch`, zero interaction |
| Appear on the device list; be revoked from the account page later | yes — flow B (cert revocation is the issuer's status bit either way) |
| Sign warrants; membership changes; every other endpoint | no (`403 config_required`) — no config key: a compromised device cannot escalate |

## 6. Out of scope

- **Issuance** (fallback-IdP role, own spec) — the mint-authorization
  chokepoint is untouched here.
- **Agent-facing lanes** (`/warrant/*`, `/agent-provision/*`) — core
  §7.5; this API is the approver's side. Reparenting: bean `9mfw`.
- **Public surfaces** (status lists, `/verify`) — unauthenticated by
  design, core §6.
- **Credential ceremonies** (passwords, mailbox/bridge verification,
  `account_cancel`, tenants) — issuer and broker-page concerns.
  Membership is in scope (§5.6); credentials never are.

## 7. Errors

OAuth-shaped JSON, per core §9:

```json
{ "error": "invalid_proof", "error_description": "jti replayed" }
```

| HTTP | `error` | When |
|---|---|---|
| 400 | `invalid_request` | Malformed JSON, missing/unknown fields, grammar violations. |
| 401 | `invalid_cert` | The routing cert fails the §7.1 bar or owns no account. Carries `WWW-Authenticate: Cert`. |
| 401 | `invalid_proof` | A request or possession proof fails: missing, wrong `typ`, bad signature, `htm`/`htu` mismatch, stale `iat`, replayed `jti`, `bh` mismatch, or a §5.6 possession proof whose `jti` differs from the header proof's. |
| 403 | `config_required` | The routing cert is an auth cert and the operation is outside the recording tier (§3). |
| 404 | `not_found` | Owner-scoped lookup misses — including "exists but isn't yours". |
| 409 | `conflict` | State refusals. |
| 422 | `invalid_warrant` | Respond, claim, register: client-signed warrants (or the claim precondition) fail the §5.1/§5.2 bar. |
| 422 | `invalid_cert` | §5.6: a body cert fails the validity bar or the membership rules. |
| 429 | `slow_down` | Rate limits; SHOULD carry `Retry-After`. |

`error_description` is diagnostic and MUST NOT be parsed; machine
reasons ride the OPTIONAL `reason` field.

### 7.1 Machine reasons

Reasons are stable surface: implementations MAY add them; clients MUST
treat unrecognized reasons as the bare `error`. The core §7.5 poll
lanes keep their own vocabulary, disjoint from this.

With `invalid_warrant` (`422`, §5.1 respond/claim and §5.2 register),
in check order:

| Reason | Meaning |
|---|---|
| `warrant_count_mismatch` | `warrants` length ≠ grants (all-or-nothing). |
| `config_cert_invalid` | Config cert fails to parse or verify. |
| `config_cert_wrong_purpose` | Not `purpose: authorization`. |
| `config_cert_expired` | Past `exp`. |
| `grantor_not_authorized` | Config cert does not authorize the grantor. |
| `grantor_not_owned` | Grantor is not an account identity. |
| `grantor_pinned_mismatch` | Differs from the request's pinned grantor. |
| `warrant_invalid` | Warrant fails to parse or verify against the config-cert key. |
| `audience_mismatch` / `grantor_mismatch` / `grantee_mismatch` | Warrant claim differs from grant/request. |
| `not_holder_bound` | No holder matcher where one is required. |
| `wildcard_holder` | Bare `*` matcher. |
| `holder_mismatch` | Matcher does not match the agent's holder. |
| `status_ref_missing` / `status_ref_mismatch` | Grant has `status_idx` but the warrant's `status` is absent or differs from `{uri, idx}`. |
| `audience_unproven` | Claim: the core §7.5 audience proof does not validate. |

With `invalid_cert` (`401` routing cert, `422` body cert), in check order:

| Reason | Meaning |
|---|---|
| `cert_malformed` | Fails to parse as a device cert. |
| `wrong_purpose` | Purpose is neither `authentication` nor `authorization`. |
| `cert_expired` | Past `exp`. |
| `issuer_not_accepted` | Issuer is neither the identity domain's DNSSEC-published IdP nor in the registry operator's accepted-fallback set (mirror of core §8.1; reference default: the registry's own domain). |
| `signature_invalid` | Does not verify under the resolved issuer key. |
| `cert_revoked` | A status ref checks revoked or is uncheckable (fail-closed). |
| `no_account` | Routing cert only: no account owns its identity — attach first (§3). |
| `cert_not_fresh` | Joining cert issued more than 300s ago (§5.6.2). |

With `conflict` (`409`):

| Reason | Meaning |
|---|---|
| `no_status_ref` | Revoking a warrant with no status ref (§5.2). |
| `namespace_not_empty` | Deleting a namespace with holders (§5.4). |
| `external_holder` / `already_in_namespace` | `move_holder` preconditions (§5.4). |
| `holder_moved` | Attaching onto a moved holder (§5.4/§5.6). |
| `last_identity` | Detaching the only identity (§5.6.4). |

## 8. Versioning and conformance

- `/api/v1/` is the compatibility contract: additive changes only;
  breaking changes get `/api/v2/`. The proof `typ` is versioned
  independently, rejected fail-closed on mismatch.
- **Invariants**:
  1. This lane's verification is at least as strict as the cookie-lane
     sibling per operation authorized.
  2. No anonymous operations: §5.5 discovery is public; everything else
     is cert-authenticated (§3), mutations possession-proven down to
     their body bytes.
  3. Every call re-checks the routing cert's status ref, fail-closed.
  4. Auth certs never exceed the recording tier.
  5. Approval carries warrants signed by the account's config-cert key;
     the registry never signs or alters warrants.
  6. DNSSEC is the sole root of trust; no Web-PKI path.
  7. Owner-scoping: everything is scoped to the authenticated account
     (the routing cert's); cross-account existence is
     never observable, including attach vs transfer.

## 9. Legacy endpoint mapping (appendix)

| Legacy (cookie + csrf) | This API | Notes |
|---|---|---|
| `POST /wsapi/auth_with_presentation` | — | No session here; every call is cert-authenticated (§3). Cookie lane stays. |
| `GET /wsapi/warrant_requests` | `GET /api/v1/requests` + `POST /api/v1/requests/claim` | Hidden GET mutation split out. |
| `POST /wsapi/warrant_respond` | `POST /api/v1/requests/respond` | Same bar. |
| `GET /wsapi/warrants` | `GET /api/v1/warrants` | |
| `POST /wsapi/register_warrant` | `POST /api/v1/warrants/register` | |
| `POST /wsapi/revoke_warrant` | `POST /api/v1/warrants/revoke` | |
| `POST /wsapi/forget_warrant` | `POST /api/v1/warrants/forget` | Guard-rails: bean `d51o`. |
| `POST /wsapi/allocate_warrant_status` | `POST /api/v1/warrants/allocate_status` | |
| `GET /wsapi/device_certs` | `GET /api/v1/devices` | |
| `POST /wsapi/revoke_device_cert` | `POST /api/v1/devices/revoke` | |
| `GET /wsapi/cert_revocation_status` | `GET /api/v1/devices/status` | |
| `GET /wsapi/holders` etc. | §5.4 table | |
| `POST /wsapi/record_device_cert` | `POST /api/v1/account/attach` | Legacy self-heal lane stays. |
| — | `attach` / `detach` / `warrants/fetch` | Membership + auth-only reads; cookie-era transfer arms map onto §5.6.3. |
| `/warrant/request`, `/warrant/poll`, `/agent-provision/*` | — | Agent side; core §7.5. |
| `GET /wsapi/session_context` | — | CSRF has no equivalent here. |

## 10. Decision log

Resolved 2026-08-28:

0. **Consent is API-complete** — approval was always a client-side
   signing ceremony; the browser page held the same keys, so the API
   adds no capability. Human-in-the-loop is the user agent's job
   (principle 8).
1. **Naming**: collections-as-GET + body-parameter POST verbs; no
   ids/emails in URL paths; small fixed `htu` set.
2. `success: true` dropped (§4).
3. `warrants/forget` stays; guard-rails deferred (bean `d51o`).
4. Proof alg pinned `EdDSA`; agility/PQ deferred (bean `hd63`).
5. *(superseded by 10)* Exchange warrant must carry the `registry`
   scope.
6. Inbox long-poll as OPTIONAL `wait`; SSE/webpush deferred.
7. **Secondary identities accepted** (unlike the cookie lane): this
   API's authority is a strict subset excluding root ops. Any future
   surface reachable with the same cert re-justifies self-issued
   acceptance (re-review logged on `d0xb`).

Resolved 2026-08-30:

8. **Account membership lives on this API** (§5.6), replacing "no
   linking in the token lane". Transfer is on-proof: fresh issuer
   attestation is current ownership; the previous holder is notified,
   never asked. Merge deferred (identities move one at a time). Derived
   agents are revoked and dropped with the departing parent (fixes bean
   a93p). Attach is synchronous and self-approved; a second-device rule
   was declined (residual risk: recoverable DoS — bean dksx).

Resolved 2026-09-01/02:

9. **Membership is cert-authenticated and self-authenticating**,
   superseding decision 8's membership record and the separate
   `devices/register`. Certs travel with possession proofs; `bh` makes
   the call its own consent artifact; one `attach` whether an identity
   is new or already owned. Two-tier authority: auth-cert possession
   records; membership changes and creation need a config-cert routing
   proof — else a stolen auth cert could plant a foreign identity and
   escalate to account-wide control. Joining certs must be fresh
   (`iat` ≤ 300s): config certs are RP-visible, so unexpired bytes
   alone must not move an identity. The exchange no longer auto-creates
   accounts (kills the parallel-account trap). Auth-only devices are
   supported policy (§5.6.6). Terminology per core §4.1: "device cert"
   is the umbrella, auth/config its flavors; no identity outranks
   another. Follow-up: the core §7.5 agent lanes should adopt the same
   possession bar (bean 0c49).

Resolved 2026-09-02:

10. **Cert auth everywhere; the token exchange is deleted.** The
    exchanged warrant was self-issued by the very config key the token
    bound to, so its scope proved nothing beyond key possession; the
    token cached little (status was re-checked per call anyway) and
    cost a second auth mode plus a bootstrap exception. Now every call
    carries `Authorization: Cert` + `Proof`; the §5.6 two-tier rule
    became the whole authorization model (config cert = full, auth cert
    = recording tier). Bean `ig9p` (cookie lane adopts the scope bar)
    loses its anchor; the cookie lane's delegated-authority concern is
    now stated directly in §3.2.

Deferred elsewhere: agent-lane reparenting (`9mfw`);
browser-ceremony discovery keys (fallback-IdP spec, `d0xb`).
