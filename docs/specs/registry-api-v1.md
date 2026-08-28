<!-- This Source Code Form is subject to the terms of the Mozilla Public
     License, v. 2.0. If a copy of the MPL was not distributed with this
     file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Registry API v1

> **Status: draft skeleton.** This document specifies the wire API of the
> **registry** role: the service that records a user's devices, holders,
> warrants, and pending consent requests, and operates their revocation
> status list (core §6.3). It exists so that a native wallet is a
> first-class registry client, and so that an independent registry can be
> implemented from this document alone — without reverse-engineering the
> hosted broker, which is merely this API's first host. Out of scope:
> identity issuance (fallback-IdP API, specified separately in the same
> family), the browser cookie/session lane (which remains as today), the
> agent-facing consent request/poll lanes (already specified in core §7.5),
> and hosted conveniences (/verify, hosted wallet UI).

Cross-references written as `core §N` refer to `browserid-ng-protocol.md`.

## 1. Overview

The hosted broker is four roles in a trenchcoat: user-agent half, fallback
IdP, registry, and hosted conveniences. This spec gives the **registry**
role a self-contained API so the user-agent half can live anywhere —
a hosted dialog, a menubar wallet, a headless agent runtime. Principle 7
(openness lives in the ability to leave) is the design driver: a
conformant registry is replaceable, and this document is the contract.

Design summary:

- **Authentication** is a two-step: the client exchanges a presentation
  bundle (core §5) addressed to the registry's own origin for a
  short-lived, sender-constrained access token (§3). Every subsequent
  call carries the token plus a proof-of-possession signature made with
  the same device key the presentation proved. There are no refresh
  tokens: re-exchanging a fresh presentation IS the refresh.
- **Revocation rides the device cert.** A token is bound to the config
  cert it was exchanged with; revoking that cert (its status bit,
  core §6.3) kills the token on its next use, fail-closed.
- **Consent is API-complete.** Approving a warrant request through this
  API carries the same client-signed warrants as the browser consent
  page — approval is a signing ceremony, not a flag flip (§5.1). The
  human-in-the-loop obligation belongs to the user agent (principle 8);
  the registry's checks are identical in both lanes.
- **No CSRF machinery.** Authentication is header-borne and
  proof-of-possession-bound, never ambient, so the cookie lane's
  `csrf` body field does not exist here.

## 2. Actors and terminology

| Term | Meaning |
|---|---|
| **Registry** | The service implementing this API. The hosted broker's registry role is the reference deployment. |
| **User agent / wallet** | The client: holds the account's device keys, builds presentations, renders consent UI. Its loyalty runs to the user (principle 8). |
| **Account** | The registry-side record a token authenticates as. Established by the first successful token exchange (or the legacy cookie lane); identified by the verified identities presented to it. |
| **Config cert** | The `purpose: authorization` device cert (core §4.3) whose key signs warrants and, in this API, request proofs. |
| **Presentation bundle** | `access_cert~assertion~warrant~config_cert` (core §5). |
| **Status list / status ref** | The registry's signed revocation bitfield and `{uri, idx}` pointers into it (core §6.3). |

## 3. Authentication

### 3.1 Token exchange — `POST /api/v1/token`

Request:

```json
{
  "presentation": "<access_cert~assertion~warrant~config_cert>",
  "scope": "registry"
}
```

| Field | Meaning |
|---|---|
| `presentation` | REQUIRED. A presentation bundle whose `audience` is the registry's own public origin. |
| `scope` | OPTIONAL. Space-separated scope list. v1 defines the single scope `registry` (the default). The field exists so later versions can narrow tokens without a breaking change. |

The registry MUST verify the presentation exactly as core §6 requires for
its own origin as audience — DNSSEC-rooted key resolution for both the
access cert's and config cert's issuers, full signature joins, expiry,
and fail-closed status checks on every status ref the
objects carry (core §6.1). Verification here
MUST NOT be weaker in any respect than the cookie-lane sibling
`/wsapi/auth_with_presentation`; this exchange is that endpoint's
API-shaped twin (one mints a cookie session, this mints a token).

In addition to the core §6 checks, the warrant in the presentation MUST
carry scopes covering every scope requested for the token (v1: the
single scope `registry`). A plain login warrant — no scopes — for the
registry's origin therefore authenticates the cookie lane but does NOT
mint a registry-management token. This is deliberately stricter than
the cookie sibling (invariant 1 permits stricter, never weaker):
warrants are delegation instruments, and a warrant granted to a third
party whose audience happens to be the registry's origin must not
silently confer device-revocation powers. There is no bootstrap cost:
warrants are signed by the wallet's own config-cert key with no
registry involvement, and the exchange accepts a `browserid-warrant-v1`
warrant, on which `status` is OPTIONAL per core §5's v1 compatibility —
so a wallet's first exchange works before it has ever called
`warrants/allocate_status`. (A v2 warrant presented here is verified to
the full v2 bar, `status` REQUIRED, per core §6.1 — the v1 allowance is
not a status-check bypass for v2 records.) Wallets SHOULD move to v2
warrants with allocated refs once they hold a token.

The exchange additionally requires a **self-presentation**:
`grantor == grantee`. A delegated presentation is rejected (`400`,
`invalid_grant`, reason `delegated_presentation`) — the token binds to
the config-cert key, which is the *grantor's* key, so a delegated
presenter could never produce request proofs anyway; delegated registry
management is deliberately not a v1 capability.

A presentation whose identity issuer is the registry's own domain (a
registry-rooted, "secondary" identity) IS accepted at this exchange —
a deliberate, principled divergence from the cookie sibling, which
rejects those (§10 decision 7). The cookie rejection is right where it
is: for a registry-rooted identity the password is the root credential
and device certs are derived from it, and a cookie session is full
account control *including* the root (password and email operations) —
a derived credential must not mint root control. This token is
different in kind: its authority is bounded to §5's registry
operations, which exclude every root op, so a self-issued presentation
mints strictly narrower authority than the session the cookie lane
refuses. This acceptance is **per-scope**: it is justified here for
`registry` only, and any future scope in this token family MUST
re-justify accepting self-issued presentations before honoring them
(the mint-authorization chokepoint and account root ops in particular
MUST NOT become reachable this way — see the fallback-IdP spec).

On success the registry resolves the account: if an existing account
owns the verified identity, the token authenticates as that account;
otherwise a new account containing exactly that identity is created.
No account linking, merging, or transfer happens in the token lane —
the cookie lane's session-based linking has no analogue here, and
multi-identity ceremonies are a browser / fallback-IdP concern. The
response:

```json
{
  "access_token": "<opaque>",
  "token_type": "DPoP",
  "expires_in": 3600,
  "scope": "registry"
}
```

Token properties:

- **Opaque, server-side.** The token is an opaque string backed by a
  registry-side record: account id, the config cert's public key (the
  proof key), the config cert's status ref and `exp`, scope, expiry.
  It is not a JWT; nothing about its internal structure is specified.
- **Short-lived.** `expires_in` SHOULD be at most 3600 seconds, and the
  token MUST NOT outlive the config cert it is bound to
  (`min(now + ttl, config_cert.exp)`).
- **No refresh tokens.** A client that wants a new token exchanges a
  fresh presentation. (Rationale: the wallet can always mint a
  presentation, so a refresh token would only add a second long-lived
  credential to steal and revoke.)
- **Revocation follows the cert.** On every authorized call the registry
  MUST check the bound config cert's status ref, fail-closed (an
  uncheckable ref is revoked, core §6.3). A revoked device's tokens are
  therefore dead without any token-level bookkeeping. Registries MAY
  additionally revoke individual tokens server-side.
- **Entropy.** Tokens MUST carry at least 128 bits of entropy.

Abuse controls — the exchange is necessarily anonymous and its
verification work is expensive (DNSSEC resolutions, status fetches):
the registry SHOULD rate-limit it per source address and per presented
identity (`429`, with `Retry-After`), MUST bound request body sizes
(RECOMMENDED cap 64 KiB, here and API-wide), and SHOULD track the
assertion's `jti` and reject reuse within its validity window, making
the exchange single-use per assertion. A requested scope the registry
does not recognize, or that the warrant does not cover, is `400`
`invalid_scope` / `invalid_grant` reason `scope_missing` respectively.

### 3.2 Request proof — `browserid-registry-proof-v1`

Every call to a token-authed endpoint carries two HTTP headers:

```
Authorization: DPoP <access_token>
DPoP: <proof JWS>
```

The proof is a JWS signed by the config cert's key (the same key that
signed the warrant in the exchanged presentation), with header
`{"alg": "EdDSA", "typ": "browserid-registry-proof-v1"}` and claims:

| Claim | Meaning |
|---|---|
| `htm` | REQUIRED. Uppercase HTTP method of this request. |
| `htu` | REQUIRED. The request URI: scheme, host, path — no query, no fragment. |
| `iat` | REQUIRED. Issued-at, seconds. The registry MUST reject proofs outside a small acceptance window (RECOMMENDED ±300s). |
| `jti` | REQUIRED. Unique random string. The registry MUST reject a replayed `jti` within the acceptance window (replay cache keyed at least by proof key, retained at least as long as the window). |
| `ath` | REQUIRED. base64url(SHA-256(access_token)) — binds the proof to the token. |

Example proof claims:

```json
{
  "htm": "POST",
  "htu": "https://registry.example/api/v1/warrants/revoke",
  "iat": 1756400000,
  "jti": "N6b2mB4kq3xw",
  "ath": "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
}
```

Canonicalization: `htu` and the §3.1 exchange audience both build on
the registry's advertised **public origin** — the origin of §5.5's
`token_endpoint`: lowercase scheme and host, default ports omitted, no
path or trailing slash on the origin itself. `htu` appends the exact
route path as written in §5, with no query, fragment, or
percent-encoding changes. A registry deployed behind a proxy MUST
compare against its public origin, never the server-observed URI.

v1 pins the proof algorithm: `alg` MUST be `EdDSA` (Ed25519), matching
the device-key suite; any other value MUST be rejected. Algorithm
agility (including post-quantum migration) is deliberately deferred to
a future proof `typ` version, coordinated with the protocol-wide
signature-suite review.

The semantics deliberately mirror RFC 9449 (DPoP), with one difference:
the proof key is not an ephemeral DPoP key but the config cert's device
key, so no separate key registration or `jkt` binding step exists — the
binding was established cryptographically by the token exchange. The
`typ` value provides domain separation from every other JWS in the
protocol (core §4's `typ` rule); a proof whose `typ` is anything else
MUST be rejected.

Verification order per call: token exists and is unexpired → proof
signature verifies against the token's bound public key → `typ`, `htm`,
`htu`, `iat` window, `jti` replay, `ath` all check → bound config cert
status ref checked fail-closed → scope covers the endpoint. Any failure
⇒ reject — fail-closed; §7 gives the error shapes.

### 3.3 Relationship to the cookie lane

The existing browser surface (`/wsapi/*` with session cookie + `csrf`
body field) remains, unchanged, as a second consumer of the same
registry role. `POST /wsapi/auth_with_presentation` and
`POST /api/v1/token` are siblings: same input credential, same
validation bar, different session shape. Nothing in this spec retires
the cookie lane; §9 maps its endpoints onto this API so the two stay
semantically identical.

One planned alignment runs the other way: the cookie lane will adopt
this spec's §3.1 scope requirement — `auth_with_presentation` demanding
the `registry` scope on broker-audience warrants before minting a
session — so the two lanes converge on an identical bar rather than
"token lane stricter". Migration is tracked in bean `ig9p`; until it
completes, the cookie lane accepting scopeless presentations is a
documented legacy allowance, not a conformance target.

## 4. Common conventions

- All bodies are JSON, UTF-8, `Content-Type: application/json`.
- Success responses use the field shapes given per endpoint. The legacy
  `success: true` boolean is dropped in this API: HTTP status codes carry
  success/failure, errors use the §7 envelope, and a redundant boolean
  invites drift between the two signals.
- Mutations whose success carries no data return `204 No Content`.
  Mutations with response fields return `200` with a JSON body; fields
  marked OPTIONAL may be absent entirely (never `null`).
- Unknown fields in requests MUST be rejected; unknown fields in
  responses MUST be ignored by clients (additive evolution, §8).
- GET endpoints are pure — no state changes, not even bookkeeping. Where
  the legacy lane hid mutations inside a GET (§9 notes), this API moves
  them to explicit POSTs.
- Timestamps are RFC 3339 UTC strings; the JWS claims keep their core
  epoch-seconds convention.
- No pagination in v1 (registry collections are small); the response
  shapes leave room to add it additively.

## 5. Endpoints

All endpoints in this section require §3 authentication with scope
`registry` unless stated. Field tables and wire examples below are
normative for shape; example values are illustrative.

### 5.1 Consent inbox

**`GET /api/v1/requests`** — the account's open consent requests.
Replaces `GET /wsapi/warrant_requests`, minus that endpoint's hidden
side effect (claiming a code-named record request and allocating its
status indexes) — that claim step is a distinct POST, below.

Response: `{ "status_uri": "...", "requests": [PendingRequest, ...] }`.
`status_uri` is this registry's status-list URI — the `uri` half of the
status refs the client embeds in the warrants it signs (each grant's
`status_idx` supplies the `idx` half). `PendingRequest` carries the
same fields as today's
`PendingRequestInfo`: `code`, `delegator_email`, `agent_email`,
`holder`, `label`, `grantor` (`"*"` = approver chooses), `message?`,
`display_name?`, `agent_created_at?`, `known`, `grants` (each
`{audience, scopes, status_idx?, grantee?}`), `external`, `kind`
(`"agent" | "connection" | "authoring"`), `client_host?`,
`client_name?`, `binding_id?`, `created_at`, `expires_at`.

```json
{
  "status_uri": "https://registry.example/.well-known/browserid-status",
  "requests": [
    {
      "code": "wr_7f2c…",
      "delegator_email": "dan@example.com",
      "agent_email": "cal-agent@agents.example",
      "holder": "agents-9x1k…",
      "label": "Calendar agent",
      "grantor": "*",
      "known": true,
      "grants": [
        { "audience": "https://cal.example", "scopes": ["events:read"], "status_idx": 168 }
      ],
      "external": false,
      "kind": "agent",
      "created_at": "2026-08-28T17:02:11Z",
      "expires_at": "2026-08-28T17:17:11Z"
    }
  ]
}
```

External requests (`external: true`) are only returned when the request
`code` is passed explicitly (`?code=`) — visibility is tied to holding
the code the redirect delivered. Request codes are short-lived
(15-minute) capability strings; deployments SHOULD keep query strings
out of access logs.

The endpoint supports long-polling as an OPTIONAL hint: `?wait=<seconds>`
asks the server to hold the request until the inbox changes or the wait
expires (servers SHOULD cap it; RECOMMENDED cap 60), then respond
normally. A server that answers immediately, ignoring `wait`, is
conformant; clients MUST treat an immediate response as valid and
SHOULD back off between polls either way.

**`POST /api/v1/requests/claim`** — `{ "code": "..." }`. Claims a
pending record request for this account and allocates status indexes
into its grants (the legacy GET's side effect, made explicit). Returns
`200` with the claimed request in the §5.1 item shape. Precondition,
carried over from the legacy lane: the request's audience proof
(core §7.5 — the document at
`https://<audience-origin>/.well-known/browserid-audience-proof/<request_id>`)
MUST validate at claim time — a fresh fetch is RECOMMENDED; an
unproven request is not claimable (`422`, machine reason
`audience_unproven`). Claiming is idempotent for the same account; a
request already claimed by another account is `404`.

**`POST /api/v1/requests/respond`** — approve or deny. Replaces
`POST /wsapi/warrant_respond`; identical semantics minus `csrf`.

```json
{
  "code": "...",
  "approve": true,
  "warrants": ["<warrant JWS>", "..."],
  "config_cert": "<config cert JWS>",
  "grantor": "dan@example.com"
}
```

| Field | Meaning |
|---|---|
| `code` | REQUIRED. The pending request. Must belong to this account. |
| `approve` | REQUIRED. `false` = deny (all other fields absent). |
| `warrants` | REQUIRED on approve. One client-signed warrant JWS per grant, in grant order — all-or-nothing. |
| `config_cert` | REQUIRED on approve. The config cert whose key signed the warrants. |
| `grantor` | OPTIONAL. Defaults to the agent itself; a named grantor must be an identity this account owns, and must equal the request's pinned grantor when one is set. |

The registry MUST validate exactly as the browser lane does (the
`validate_grant_warrants` bar): count matches grants; config cert parses,
is `purpose: authorization`, unexpired, and authorizes the grantor; each
warrant verifies against the config cert key, matches its grant's
`audience`, `grantor`, `grantee`, is holder-bound (connection-bound
records rejected) with a non-wildcard matcher matching the agent's
holder, and — when the grant carries a `status_idx` — embeds exactly the
registry's `{uri, idx}` status ref. On approve, per grant: the registry stores the delivery string
`{warrant}~{config_cert}` for single pickup by the requester's core
§7.5 poll, and upserts one warrant record into the §5.2 registry.
Validation failures are `422` with a §7.1 machine reason.

The bar above applies to `kind: "agent"` requests, whose approval signs
presentation warrants. The other kinds carry **admission records**
(core §6.4), and their per-kind bar follows core §7.5: for
`"connection"`, each signed record MUST be a connection-bound
self-grant — `grantor == grantee`, the approver's identity — embedding
exactly the request's broker-minted `binding.id` (core §6.6
invariant 5); for `"authoring"`, each record MUST match its requested
grant's `grantee` matcher, audience, and scopes, with the approver as
grantor. In every kind the records are signed client-side with the
account's config-cert key and validated against the pending request;
the §7.1 machine reasons apply across kinds.

Response: always `200` with a JSON body — `{ "return_url":
"https://cal.example/connected" }` when the original request carried a
return URL, `{}` otherwise (including every deny).

This endpoint is the consent invariant, restated: approval requires
warrants signed by the account's own config-cert key — the registry
records consent, it cannot manufacture it. Whether a human was actually
in the loop is the user agent's obligation (principle 8); that was
equally true of the browser page, which held the same keys.

### 5.2 Warrant registry

**`GET /api/v1/warrants`** — the account's registered warrants.
Replaces `GET /wsapi/warrants`. Response items carry today's
`WarrantInfo` fields: `id`, `delegator_email`, `agent_email`,
`audience`, `scopes`, `warrant` (JWS), `status_idx?`, `revoked`
(computed live from the status bit), `holder?`, `config_cert?`,
`binding_id?`, `client_host?`, `client_name?`, `requester_origin?`,
`signed_at`, `expires_at`.

```json
{
  "warrants": [
    {
      "id": 42,
      "delegator_email": "dan@example.com",
      "agent_email": "cal-agent@agents.example",
      "audience": "https://cal.example",
      "scopes": ["events:read"],
      "warrant": "eyJhbGciOiJFZERTQSIsInR5cCI6ImJyb3dzZXJpZC13YXJyYW50LXYyIn0…",
      "status_idx": 168,
      "revoked": false,
      "holder": "agents-9x1k…",
      "signed_at": "2026-08-28T17:05:40Z",
      "expires_at": "2026-09-27T17:05:40Z"
    }
  ]
}
```

**`POST /api/v1/warrants/register`** — record an externally-minted
warrant `{ "warrant": "<JWS>", "config_cert": "<JWS>" }` → `204`. The
warrant MUST verify against the config-cert key, the config cert MUST
be `purpose: authorization` and authorize the warrant's `grantor`, and
the grantor MUST be an identity this account owns. Status-ref
reconciliation: a ref naming this registry's own list is re-derived
from the grant identity — on match the bit is reactivated, on mismatch
the row is recorded with no index (and the discrepancy SHOULD be
logged); a ref naming a foreign list is recorded with no index (this
registry cannot flip foreign bits). Validation failures are `422` with
a §7.1 machine reason.

**`POST /api/v1/warrants/revoke`** — `{ "id": 42 }` → `204`. Flips the
warrant's status bit (sticky; revocation is never undone by this API —
re-registering a warrant is the reactivation path). A warrant without a
status ref cannot be revoked: `409`, machine reason `no_status_ref`
(the remedy is reissuing the warrant with an allocated ref).

**`POST /api/v1/warrants/forget`** — `{ "id": 123 }`. Deletes the
registry row **without revoking** — the signed warrant remains valid to
expiry. Legitimate uses exist (expired rows; warrants with no status
ref; warrants whose revocation authority is foreign and unreachable);
whether the destructive case — unexpired *and* revocable — should be
server-guarded is tracked in bean `d51o`. Returns `204`.

**`POST /api/v1/warrants/allocate_status`** — allocate (idempotently)
the stable status ref for a grant before signing it. Replaces
`/wsapi/allocate_warrant_status`; this is what lets a wallet mint login
warrants **with** per-site revocation bits (closing the prototype gap).
The allocation is stable per `(account, agent_email, audience, scopes)`
— repeated calls return the same ref, and `scopes` is an
order-insensitive set for allocation identity. `audience` MUST be non-empty,
contain no `*`, no whitespace or control characters, and be at most 512
bytes.

```json
{ "agent_email": "dan@example.com", "audience": "https://cal.example", "scopes": [] }
```

→ `200`:

```json
{ "uri": "https://registry.example/.well-known/browserid-status", "idx": 171 }
```

### 5.3 Devices

**`GET /api/v1/devices`** — the account's device certs
(`/wsapi/device_certs`): `id`, `identities`, `purpose`, `holder`,
`pubkey`, `iss`, `issued_at`, `expires_at`, `revoked`.

```json
{
  "certs": [
    {
      "id": 7,
      "identities": ["dan@example.com"],
      "purpose": "authorization",
      "holder": "browsers-t5da…",
      "pubkey": "4c1Yl0…",
      "iss": "example.com",
      "issued_at": "2026-08-01T09:12:00Z",
      "expires_at": "2026-11-01T09:12:00Z",
      "revoked": false
    }
  ]
}
```

**`POST /api/v1/devices/register`** — record a newly issued device pair:

```json
{ "device_cert": "<JWS>", "config_cert": "<JWS>" }
```

→ `204`. The registration half of issuance (fallback-IdP spec §4):
issuance yields certs, and the wallet records them here at its configured
registry. This is the token lane's only device-adding write — the §3.1
exchange itself records nothing, and issuer-side recording is an internal
convenience wallets MUST NOT rely on. The registry MUST verify, and
reject otherwise:

- Both certs parse as device certs (core §4.3); `device_cert` is
  `purpose: authentication`, `config_cert` is `purpose: authorization`;
  both are unexpired; and every status ref either carries checks
  unrevoked, fail-closed (core §6.3 — uncheckable ⇒ revoked).
- Both verify against an issuer the registry accepts for their identity:
  for a domain that publishes an IdP, the domain's own DNSSEC-resolved
  key (core §3); for a domain that does not, a fallback issuer in the
  **registry operator's configured accepted-fallback set** — the
  registry-side mirror of the RP-side acceptance rule (core §8.1). The
  reference registry's default set is its own domain. A cert whose
  signature verifies but whose issuer is outside the accepted set is
  refused, not recorded.
- Every concrete (non-wildcard) identity on the pair is an identity the
  token's account owns (§3.1 resolution).
- Both certs name the same holder, and the config cert is the one the
  token is bound to (public-key match) — so registration is covered by
  the exchange's verification of that cert, and this endpoint's explicit
  verification covers the sibling `device_cert` the exchange never
  parses.
- The named holder has not been moved (§5.4 `holders/move`): registering
  onto a moved holder is refused (`409`, reason `holder_moved`) rather
  than resurrecting the old row — the client consults
  `holders/assignment` and re-issues under the new holder.

Validation failures are `422` with a §7.1 machine reason. Idempotent:
matched on cert public key, re-registering an already-recorded device is
a no-op success. The registry MAY derive a default label for a
newly seen holder from observable client metadata (e.g. `User-Agent`),
as the cookie lane does.

**`POST /api/v1/devices/revoke`** — `{ "id": 7 }` → `200` with
`{ "revoked": true }`. Owner-scoped. When this registry is the cert's
revocation authority (the cert's `iss` is this registry's domain), it
flips the status bit — sticky, never un-set. When the issuer is
foreign, the registry hides the cert from its listings but **cannot
revoke it**, and MUST say so: `{ "revoked": false }`, so the client can
route revocation to the issuing authority instead of believing the
cert dead. A device MAY revoke itself; the registry MUST NOT
special-case that (the token dies with the cert on its next check).

**`GET /api/v1/devices/status?id=7`** — `{ "state": "revoked" |
"active" | "unknown" }`, owner-scoped (`/wsapi/cert_revocation_status`).
`unknown` means the cert carries no status ref. For foreign-issued
certs this performs a fresh fetch of the issuer's signed list — a
network side effect, but not a state change (§4's pure-GET rule refers
to registry state).

### 5.4 Holders and namespaces

Same shapes as the legacy lane minus `csrf`:

| Endpoint | Replaces | Request → response |
|---|---|---|
| `GET /api/v1/holders` | `/wsapi/holders` | → `{ namespaces: [...], holders_without_namespace: [...] }` (today's `NamespaceView` / `HolderView` fields) |
| `POST /api/v1/holders/rename` | `/wsapi/rename_holder` | `{ holder_id, label }` |
| `POST /api/v1/holders/move` | `/wsapi/move_holder` | `{ holder_id, namespace }` → `{ new_holder }`. Destructive and up-front: revokes every cert on the old holder and flips each status bit, records the move (old → new) for `holders/assignment` resolution, and carries the label to the new holder. |
| `POST /api/v1/holders/forget` | `/wsapi/forget_holder` | `{ holder_id }` → `{ unrevocable: [issuer, ...] }`. Revokes-then-deletes; lists issuers it couldn't revoke at. |
| `GET /api/v1/holders/assignment?holder=` | `/wsapi/holder_assignment` | → `{ status, new_holder? }`; `status` is `"current"` or `"moved"`, `new_holder` present only when moved. |
| `POST /api/v1/namespaces/create` | `/wsapi/create_namespace` | `{ name, label? }` |
| `POST /api/v1/namespaces/rename` | `/wsapi/rename_namespace` | `{ name, label }` |
| `POST /api/v1/namespaces/delete` | `/wsapi/delete_namespace` | `{ name }`. Refused while the namespace has holders. |

`GET /api/v1/holders` response example. Namespace fields: `name`,
`prefix`, `label`, `holders`. Holder fields: `holder_id`, `label`,
`trust` (`"trusted" | "login-only"`), `cert_count`, `issued_at?`,
`warrant_count`, `revoked`, `external`, `identities`, `moving_to?`:

```json
{
  "namespaces": [
    {
      "name": "browsers",
      "prefix": "browsers-",
      "label": "Browsers",
      "holders": [
        {
          "holder_id": "browsers-t5da…",
          "label": "Menubar Wallet",
          "trust": "trusted",
          "cert_count": 2,
          "issued_at": "2026-08-01T09:12:00Z",
          "warrant_count": 3,
          "revoked": false,
          "external": false,
          "identities": ["dan@example.com"]
        }
      ]
    }
  ],
  "holders_without_namespace": []
}
```

Normative validation rules (unified from the legacy lane's two slightly
divergent grammars — implementations SHOULD additionally accept legacy
names that predate this spec):

- **Namespace name**: lowercased and trimmed, then MUST match
  `^[a-z][a-z0-9_-]{0,31}$`.
- **Label** (holder, namespace): 1–64 Unicode characters, single line
  (no CR, LF, or other control characters).
- **Ownership scoping**: a holder is addressable only if it appears on
  one of the account's device certs; a namespace only if the account
  owns it. Violations are `404` (§7, no existence leaks).
- **`move_holder` preconditions**: the holder MUST NOT be external
  (empty `pubkey`) and MUST NOT already be in the target namespace
  (`409`, machine reasons `external_holder` / `already_in_namespace`).

### 5.5 Discovery

Registry discovery rides the existing support document — **`GET
/.well-known/browserid`** (core §3.1) — as a new top-level `registry`
object. There is exactly one discovery document per origin: a service
sets the keys for the roles it serves and omits the rest. An IdP that
is not a registry has no `registry` key; a standalone registry serves
the document with *only* the `registry` key; the hosted broker serves
both. Clients MUST treat a missing `registry` key as "this origin does
not serve the registry API" and MUST ignore keys they don't recognize.

```json
{
  "authentication": "/auth",
  "provisioning": "/provision",
  "registry": {
    "version": "v1",
    "token_endpoint": "https://registry.example/api/v1/token",
    "status_list": "https://registry.example/.well-known/browserid-status",
    "browser": {}
  }
}
```

| Key (under `registry`) | Meaning |
|---|---|
| `version` | REQUIRED. Highest API version served. |
| `token_endpoint` | REQUIRED. Absolute URL of §3.1. MUST be same-origin with the document that advertises it — a support document naming an off-origin token endpoint MUST be rejected (a rogue document must not be able to redirect presentation submission elsewhere). |
| `status_list` | REQUIRED. This registry's signed status list (core §6.3), same-origin like `token_endpoint`. Advertisement only — verifiers reach the list through the `uri` inside each status ref, never through discovery; the list itself remains a separate signed artifact, not metadata. |
| `browser` | REQUIRED (may be empty). Browser-ceremony URLs a native wallet opens for flows it cannot perform natively. Keys are defined by the fallback-IdP spec; v1 defines `account` (the account-management page). Issuer ceremonies (sign-in, password reset, recovery) live behind the issuer's `device-authorization` page, not here. |

The support document carries no key material (core §3.1: an IdP's key
comes solely from DNSSEC); the `registry` object follows the same rule.
This section amends core §3.1 additively, and makes explicit a rule
core §3.1 leaves unstated: clients MUST ignore support-document keys
they do not recognize.

## 6. Out of scope (and why)

Explicitly **not** in this API:

- **Issuance** — `stage_email` / signin-code ceremonies, `/device/issue`,
  `/auth/device_cert`, `/idp/device_cert`. That is the fallback-IdP role;
  its API is specified separately in this family and shares §3 auth once
  bootstrapped. The mint-authorization chokepoint is untouched by this
  spec.
- **Agent-facing consent lanes** — `/warrant/request`, `/warrant/poll`,
  `/warrant/record-request`, `/agent-provision/*`: already
  device-cert-authed or code-authed, already native-friendly, specified
  in core §7.5. This API is the *approver's* side of the same flows.
  (Their spec placement, `/api/v1/*` reparenting, and possible adoption
  of §3-style proofs are under discussion — bean `9mfw`.)
- **Public surfaces** — `/.well-known/browserid-status`, `/verify`,
  `/status/check`: unauthenticated by design, specified in core §6.
- **Account/browser ceremonies** — password ops, email add/remove,
  `account_cancel`, tenant management, `session_context`: cookie-lane
  and/or fallback-IdP concerns, not registry operations.

## 7. Errors

Errors follow the core §9 precedent: OAuth-shaped JSON.

```json
{ "error": "invalid_proof", "error_description": "jti replayed" }
```

| HTTP | `error` | When |
|---|---|---|
| 400 | `invalid_request` | Malformed JSON, missing/unknown fields, grammar violations. |
| 400 | `invalid_grant` | Token exchange: presentation fails core §6 verification (wrong audience, bad chain, expired, revoked ref). |
| 401 | `invalid_token` | Missing/expired/revoked token — including a revoked or expired bound config cert (fail-closed). Response carries `WWW-Authenticate: DPoP`. |
| 401 | `invalid_proof` | Proof missing, wrong `typ`, bad signature, `htm`/`htu` mismatch, stale `iat`, replayed `jti`, `ath` mismatch. |
| 403 | `insufficient_scope` | Token scope does not cover the endpoint (future-proofing; cannot occur with v1's single scope). |
| 404 | `not_found` | Owner-scoped lookup misses — including "exists but isn't yours" (no existence leaks). |
| 409 | `conflict` | State refusals, e.g. deleting a non-empty namespace. |
| 422 | `invalid_warrant` | Respond, claim, and register: client-signed warrants (or the claim precondition) fail the §5.1/§5.2 validation bar. |
| 422 | `invalid_cert` | `devices/register`: the submitted cert pair fails the §5.3 validation bar. |
| 429 | `slow_down` | Rate limits. Responses SHOULD carry `Retry-After`. |

`error_description` is a human-readable diagnostic and MUST NOT be
parsed; machine-readable sub-reasons appear in an OPTIONAL `reason`
field, enumerated below.

### 7.1 Machine reasons

Reason strings are part of the API's stable surface: implementations
MAY add reasons, and clients MUST treat an unrecognized reason as the
bare `error` code. The agent-facing poll lanes (core §7.5) keep their
own vocabulary (`unknown_agent`, `grants_denied`); this API's reasons
are disjoint from it.

With `invalid_grant` (token exchange, §3.1):

| Reason | Meaning |
|---|---|
| `verification_failed` | The presentation fails core §6 verification (chain, signatures, expiry, audience, or a fail-closed status check). No finer distinction is surfaced: the endpoint is anonymous, and detailed failure reasons would turn it into a verification oracle. |
| `delegated_presentation` | `grantor != grantee` — the exchange requires a self-presentation (§3.1). |
| `scope_missing` | The warrant does not carry the scopes requested for the token. |

With `invalid_warrant` (`422`, §5.1 respond / claim and §5.2 register)
— one reason per check of the §5.1 validation bar, in check order:

| Reason | Meaning |
|---|---|
| `warrant_count_mismatch` | `warrants` length ≠ number of grants (all-or-nothing). |
| `config_cert_invalid` | Config cert fails to parse or verify. |
| `config_cert_wrong_purpose` | `purpose` is not `authorization`. |
| `config_cert_expired` | Config cert past `exp`. |
| `grantor_not_authorized` | Config cert does not authorize the grantor identity. |
| `grantor_not_owned` | Named grantor is not an identity this account owns. |
| `grantor_pinned_mismatch` | Request pins a grantor and the supplied one differs. |
| `warrant_invalid` | A warrant fails to parse or its signature does not verify against the config-cert key. |
| `audience_mismatch` / `grantor_mismatch` / `grantee_mismatch` | Warrant claim differs from the grant / request. |
| `not_holder_bound` | Warrant carries no holder matcher (connection-bound where holder-bound is required). |
| `wildcard_holder` | Holder matcher is a bare `*`. |
| `holder_mismatch` | Matcher does not match the agent's holder. |
| `status_ref_missing` / `status_ref_mismatch` | Grant carries a `status_idx` but the warrant's `status` is absent, or differs from the registry's `{uri, idx}`. |
| `audience_unproven` | Claim (§5.1): the request's core §7.5 audience proof does not validate. |

With `invalid_cert` (`422`, §5.3 `devices/register`) — in check order:

| Reason | Meaning |
|---|---|
| `cert_malformed` | Either cert fails to parse as a device cert. |
| `wrong_purpose` | `device_cert` is not `purpose: authentication`, or `config_cert` is not `purpose: authorization`. |
| `cert_expired` | Either cert is past `exp`. |
| `cert_revoked` | A status ref on either cert checks revoked, or is uncheckable (fail-closed). |
| `issuer_not_accepted` | The cert's issuer is neither the identity domain's DNSSEC-published IdP nor in the registry's accepted-fallback set. |
| `signature_invalid` | A cert's signature does not verify under the resolved issuer key. |
| `identity_not_owned` | A concrete identity on the pair is not owned by the token's account. |
| `holder_mismatch` | The two certs name different holders. |
| `config_cert_not_bound` | The config cert is not the one the token is bound to. |

With `conflict` (`409`):

| Reason | Meaning |
|---|---|
| `no_status_ref` | Revoking a warrant that has no status ref (§5.2). |
| `namespace_not_empty` | Deleting a namespace that still has holders (§5.4). |
| `external_holder` / `already_in_namespace` | `move_holder` preconditions (§5.4). |
| `holder_moved` | `devices/register` onto a holder that has been moved (§5.3). |

## 8. Versioning and conformance

- The path prefix `/api/v1/` is the compatibility contract: within v1,
  changes are additive only (new endpoints, new OPTIONAL fields).
  Breaking changes get `/api/v2/`.
- The proof `typ` is versioned independently
  (`browserid-registry-proof-v1`) and rejected fail-closed on mismatch,
  per the core §4 domain-separation convention.
- **Invariants** (conformance checklist, numbered):
  1. Token-lane verification MUST be at least as strict as the
     cookie-lane sibling for the same operation; no operation is
     reachable with less proof than the browser lane requires.
     (Strictness is measured per operation authorized: the §3.1
     acceptance of self-issued presentations is not a weakening,
     because the minted authority is a strict subset of the session
     the cookie lane refuses to mint for them.)
  2. No new anonymous surface: the API's only unauthenticated
     endpoints are the §3.1 exchange (the API sibling of the existing
     anonymous `auth_with_presentation`, with §3.1's abuse controls)
     and §5.5 discovery (static, account-free); every §5 operation
     requires §3 auth.
  3. Every authorized call re-checks the bound config cert's status
     ref, fail-closed (core §6.3: uncheckable ⇒ revoked).
  4. Tokens MUST NOT outlive their bound config cert.
  5. Approval MUST carry warrants signed by the account's config-cert
     key and validated to the §5.1 bar; the registry never signs or
     alters warrants on the client's behalf.
  6. DNSSEC remains the sole root of trust (core §3); nothing in this
     API introduces a Web-PKI trust path.
  7. Owner-scoping: every read and mutation is scoped to the token's
     account; cross-account existence is not observable.

## 9. Legacy endpoint mapping (appendix)

| Legacy (cookie + csrf) | This API | Notes |
|---|---|---|
| `POST /wsapi/auth_with_presentation` | `POST /api/v1/token` | Siblings; same credential, session vs token. Cookie lane stays. |
| `GET /wsapi/warrant_requests` | `GET /api/v1/requests` (+ `POST /api/v1/requests/claim`) | Hidden GET mutation split out. |
| `POST /wsapi/warrant_respond` | `POST /api/v1/requests/respond` | Same validation bar; consent now API-complete. |
| `GET /wsapi/warrants` | `GET /api/v1/warrants` | |
| `POST /wsapi/register_warrant` | `POST /api/v1/warrants/register` | |
| `POST /wsapi/revoke_warrant` | `POST /api/v1/warrants/revoke` | |
| `POST /wsapi/forget_warrant` | `POST /api/v1/warrants/forget` | Guard-rails discussion: bean `d51o` (§5.2). |
| `POST /wsapi/allocate_warrant_status` | `POST /api/v1/warrants/allocate_status` | Closes the wallet's no-status-ref gap. |
| `GET /wsapi/device_certs` | `GET /api/v1/devices` | |
| `POST /wsapi/revoke_device_cert` | `POST /api/v1/devices/revoke` | |
| `GET /wsapi/cert_revocation_status` | `GET /api/v1/devices/status` | |
| `GET /wsapi/holders` etc. | §5.4 table | |
| `POST /wsapi/record_device_cert` | `POST /api/v1/devices/register` | Legacy lane records only the config cert (best-effort self-heal); `devices/register` verifies and records the pair. Cookie endpoint stays for the self-heal lane. |
| `/warrant/request`, `/warrant/poll`, `/warrant/record-request`, `/agent-provision/*` | — (out of scope) | Agent side; core §7.5. |
| `GET /wsapi/session_context` | — (not needed) | CSRF token has no token-lane equivalent. |

## 10. Decision log and deferred items

Resolved (2026-08-28 review):

0. **Consent is API-complete** — a deliberate redesign of the earlier
   "human-in-browser" invariant (design-handoff doc), decided with Dan:
   approval was always a client-side signing ceremony (the browser
   consent page signs with the same config-cert key the wallet holds),
   so routing through a browser page added ceremony, not security — a
   config-key holder could already mint a cookie session and approve.
   The API adds no capability beyond what key possession grants;
   human-in-the-loop is the user agent's obligation (principle 8).
1. **Endpoint naming**: collections-as-GET + body-parameter POST verbs,
   held throughout. Matches the house RPC idiom, keeps the legacy
   mapping 1:1, avoids opaque ids/emails in URL paths (encoding
   hygiene; the one capability string in a query, §5.1's `?code=`,
   carries a log-hygiene caveat there), and keeps the proof `htu` set
   small and fixed.
2. **`success: true` dropped** (§4).
3. **`warrants/forget`** stays, with its legitimate uses noted in §5.2;
   guard-rail design deferred to bean `d51o`.
4. **Proof alg pinned to `EdDSA`** (§3.2); agility/PQ deferred to bean
   `hd63` as part of the protocol-wide signature-suite review.
5. **Exchange warrant must carry the `registry` scope** (§3.1) —
   confirmed, and extended: the cookie lane will adopt the same
   requirement so both lanes share an identical bar (§3.3;
   migration bean `ig9p`).
6. **Inbox long-poll** included as an OPTIONAL `wait` hint (§5.1);
   SSE/webpush deferred.

Deferred elsewhere:

- Agent-facing consent lanes: spec placement, `/api/v1/*` reparenting,
  §3-style auth — bean `9mfw`.
- Browser-ceremony discovery keys under the support document's
  `registry.browser` object (password reset, account management,
  recovery) — fallback-IdP spec (`d0xb`).

7. **Registry-rooted (secondary) identities at the token exchange:
   accepted** (§3.1) — resolved with Dan 2026-08-28. The cookie lane
   keeps rejecting (a session is full account control including the
   password root that secondary certs derive from); the token lane
   accepts because its authority is scope-bounded to registry
   operations, a strict subset excluding every root op — so acceptance
   here mints less than the session the cookie lane refuses.
   Per-scope gate recorded: every future scope must re-justify
   self-issued acceptance (re-review obligation logged on `d0xb`).
