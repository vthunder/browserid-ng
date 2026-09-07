<!-- This Source Code Form is subject to the terms of the Mozilla Public
     License, v. 2.0. If a copy of the MPL was not distributed with this
     file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Registry API v1

> **Status: draft.** The wire API of the **registry** role: the service
> that records a user's certs, holders, and warrants, carries pending
> consent requests, and operates their revocation status list (core
> §6.3). Together with the core protocol it is enough to implement an
> interoperable registry. Not covered here: issuance (the fallback-IdP
> API), the agent-facing request and poll lanes (core §7.5, a separate
> document that binds registries serving such holders), and any
> operator's own conveniences.

Cross-references written as `core §N` refer to `browserid-ng-protocol.md`.

## 1. Overview

This API lets any wallet talk to any registry, and lets a user move
their account to another registry (§5.2.3).

- **Auth**: a wallet opens a session on an account by proving it holds
  one or more device-cert keys, then signs every request with one of
  those keys (§4). What a session may do depends on which kinds of
  cert opened it. A cert alone never admits a device to an existing
  account; the account's guard (§4.2) does.
- **Revocation rides the device cert**: revoking a cert kills its
  access on next use, fail-closed.
- **Consent is API-complete**: approval carries the same client-signed
  warrants as a browser consent page would (§5.3).
- **No CSRF** — auth is header-borne, never ambient.

The flows, at a glance (the wallet's side; RP login itself is core
§7.3):

| Flow | What the wallet does |
|---|---|
| First use | Issuer sign-in → auth + config cert → `attach` naming no account (§5.2.1): account created, its id and a session returned. Registries SHOULD prompt the user to set up a guard kind a lone device can pass (§4.2). |
| New device | Issuer sign-in → certs → `attach`; pass the guard (§4.2): approval from an existing device, a password, further identities, or a page the registry runs. An auth-only device may skip the guard and gets lookup tier. |
| Sign in at an RP | `warrants/lookup` (§5.4) for the site if the device lacks the warrant, `allocate_status` (§5.4) when minting one; then present. |
| Approve an agent | `GET requests` → `respond` with client-signed warrants (§5.3). |
| Add an identity | Issuer sign-in for it → `attach` naming the account under a write session (§5.2.1). |
| Take an identity from another account | The same, with the user's confirmation; the previous account is notified and its rows go on hold (§4.1). |
| Remove an identity; leave | `detach` (§5.2.2); `delete` (§5.2.3). |
| Manage | Warrants (§5.4), certs (§5.5), holders (§5.6), sessions (§4.5). |

## 2. Actors and terminology

| Term | Meaning |
|---|---|
| **Registry** | The service implementing this API. |
| **Wallet** | The client: holds the user's device keys, builds presentations, renders consent UI. |
| **Issuer** | The identity provider for an address's domain, or an accepted fallback: it issues the device certs a wallet presents here (core §4). |
| **Identity** | An email-shaped address a cert names; a *derived agent identity* (`dan+cal@…`) is one carved from it for an agent (core §4.6). Identities compare after lowercasing; a derived identity is held wherever its root is. |
| **Device cert** | A cert an issuer signs over a wallet's key for an identity (core §4.1): an **auth cert** (`purpose: authentication`) mints the short-lived *access certs* a login presents; a **config cert** (`purpose: authorization`) signs warrants. Here they earn the read and write tiers (§4.3). A cert is **fresh** when issued within the last 300 s. |
| **Warrant** | A grant the user's config cert signs for an audience, with scopes and a holder matcher, checked by relying parties against the registry's status list (core §5, §6.3). |
| **Presentation** | What a login shows an RP: `access_cert~assertion~warrant~config_cert` (core §5). |
| **Holder** | An opaque id the wallet chooses and the issuer stamps on a device's certs; warrants bind to holders, and namespaces group them (core §4.5). |
| **Account** | The identities that share one set of warrants, certs, holders, and an inbox, named by an opaque id (§3). Created and changed only by §5.2 `attach` / `detach` / `delete`. All of an account's identities are equals: which one authenticated is a per-call fact, never a rank. |
| **Session / member** | An opaque token on one account, bound to a set of recorded certs — its *members*, the certs whose proofs opened it (§4.5) — at one tier (§4.3). |
| **Recorded / guarded / retired** | A cert is *recorded* on an account by `attach`; *guarded* when it was recorded past the guard or under a session (§4.3); *retired* when the account revokes it, its holder is moved or forgotten, or it is dropped (§5.5). Retirement is permanent. |
| **Validity bar** | The `invalid_cert` checks of §7.1, `cert_malformed` through `cert_revoked`; every cert passes it when recorded and every member on every call. |
| **Guard** | The registry's check (§4.2) that a device belongs to the account's owner, not merely to whoever controls one of its addresses now. |
| **Suspended** | The state of an identity that has left an account (§4.1): its records kept but inert for the **hold**, restorable if it returns. |
| **Transfer / takeover** | An identity leaving one account for another: a *transfer* when the destination's session did it; a *takeover* when a fresh config cert with no session and no guard did. Both need the user's confirmation and land the identity with nothing inherited. |
| **Capability code** | The opaque `code` that names a pending request (§5.3); the agent lanes (core §7.5) call it `request_id`. |
| **Status list / status ref** | The registry's signed revocation bitfield and `{uri, idx}` pointers into it (core §6.3). A warrant record is *indexed* when its ref is on this registry's list. |

## 3. Common conventions

- Bodies are JSON, UTF-8. No `success: true` — status codes carry
  success, §7 the errors. Refusals are cited as `<status>
  <error>/<reason>`, e.g. `403 forbidden/write_required`: §7
  defines every `error`, §7.1 every `reason`.
- Data-free mutations return `204`; others `200` + JSON. OPTIONAL
  fields are absent, never `null`.
- Unknown request fields MUST be rejected (`400 invalid_request`);
  unknown response fields MUST be ignored (additive evolution, §8).
  Unknown query parameters are ignored.
- GETs are pure; every mutation is a POST. A POST MAY carry an
  `Idempotency-Key` header (≤ 128 bytes); a repeat with the same key
  from the same session within 24 h returns the first response.
- Timestamps: RFC 3339 UTC; JWS claims keep epoch seconds.
- No pagination in v1; response shapes leave room to add it.
- Limits: bodies ≤ 64 KiB (`400 invalid_request` above); labels 1–64
  Unicode characters, one line; `scopes` 1–32 tokens of `[a-z0-9_:.-]`,
  ≤ 64 bytes each; `audience` non-empty, no `*`, no whitespace or
  control characters, ≤ 512 bytes; `?wait` ignored when `?code` is
  given.
- Rate limits: `429 slow_down` + `Retry-After`, per source address,
  per cert public key, and per identity or account where §4–§5 say
  so, applied before any network fetch. A registry MAY rate-limit
  account-changing attaches per identity (takeover and return alike)
  so a contested address flips no faster than verifiers refresh
  status lists. Issuer keys and status lists are cacheable within
  their validity.
- Identifiers: `id` is an integer, registry-scoped; `account` is an
  opaque string of ≥ 128 bits, per registry, not a secret — knowing it
  proves nothing; `pubkey` is the base64url raw Ed25519 public key;
  `fingerprint` = `kid` (§4.4); `code` and tokens are opaque strings
  of ≥ 128 bits of entropy; `version` is an integer.
- Fetching a status list from a URI found in a cert or warrant follows
  the safe-fetch rules of core §7.5 (public unicast hosts, no
  redirects, bounded time and size); a cert's `status.uri` host MUST
  equal its `iss`.

## 4. Authentication

Two things authenticate here. A wallet proves it holds device-cert
keys, on every call. And a device proves it belongs to the account's
owner by passing the account's **guard** (§4.2): when it first joins,
and again if the registry asks. The model comes first (§4.1), then
the guard, then what a session may do (§4.3), then the proof (§4.4)
and the session (§4.5) that carry it all.

### 4.1 Identities and accounts

Which identities an account holds is the registry's business; proving
an identity is the issuer's. Three rules:

1. **The issuer decides who holds an address.** A fresh config cert
   proves holding it now. Its presenter, on confirming it (§5.2.1),
   gets the identity at once, inheriting nothing; the account that
   held it is told, not asked. A contested address flips between two
   accounts — each flip notified, each reversible (rule 3) — until
   the issuer stops issuing to one side. The registry never picks a
   winner.
2. **Joining an account needs the guard.** An identity, or a new key
   for one, joins an existing account only under a session on it or
   past its guard (§4.2). Without either, a fresh config cert is
   refused until the user confirms a takeover, and a fresh auth cert
   gets only the lookup tier.
3. **Leaving puts the identity on hold.** When an identity leaves an
   account — transferred, taken over, or detached — it is marked
   **suspended** there: its warrants' bits set, its derived agents
   suspended with it, its records inert, a `notice` (§5.3) filed. The
   account's certs, sessions, and other identities are untouched.
   Within the **hold** (RECOMMENDED 30 days) the identity may
   **return** by rule 2 and is restored: the bits suspension set are
   cleared, bits set by an explicit revoke stay set. After the hold
   the records are dropped, and so is an account with nothing left
   that a live cert can act on, together with its open requests and
   tokens.

A suspended identity still counts as held at the door (§5.2.1), so a
fresh cert for it can pass that account's guard and return. It shows
in the roster with `state: "suspended"` and in `GET warrants` with
`suspended: true`. The hold protects against issuer mistakes and
races over a mailbox, not against losing the address: an owner with
no other device and no other guard kind cannot return, and when the
issuer has revoked their old certs the password or page guard is the
way. A registry that also runs an issuer MUST NOT let a newly joined
address reset the issuer's password until the issuer has verified it
itself.

### 4.2 The guard

A cert proves that its holder controls an address today. It cannot
prove that the holder is the person whose account that address is on.
The guard is the registry's check for that. A device passes it when
it first joins an account (§5.2.1); a registry MAY also make an
existing device pass it again at its next session, by answering
`session` `403 forbidden/guard_required`, provided another device on
the account still holds a session or a kind is offered that needs no
other device — a registry MUST NOT re-guard its way into an account
nobody can approve. No other call is refused for the guard alone.

**Token.** Every kind of guard ends as a guard token: opaque,
single-use, valid for the registry's window (RECOMMENDED 1 h from
mint), bound to the account that held `identity` at mint and to the
set of certs it was requested for. It is spent through the `guard`
field of `session`, `attach`, `detach`, or `delete` by a call whose
header proof is signed by one of those certs' keys and which acts on
that account; `attach` spending it MUST carry exactly that set. A
refused call does not spend it. Approval says the device is part of
the account, nothing narrower.

**Refusal.** A call that needs a guard and carries none answers
`403 forbidden/guard_required` with the kinds the registry accepts,
one object each, the same list for every account, never naming
identities:

```json
{ "error": "forbidden", "reason": "guard_required",
  "guard_kinds": [
    { "kind": "device_approval" },
    { "kind": "password" },
    { "kind": "additional_identities", "min": 1, "distinct_issuer": true },
    { "kind": "page", "url": "https://…" } ] }
```

**`POST /api/v1/guard`** — Obtains a token. Carries a `Proof` header
and the device's certs (1–2, one holder) with possession proofs
(§4.4), so the token binds to what `attach` will carry. Body:
`{ "kind", "identity", "account"?, "certs": [ { "cert", "proof" } ], … }`
plus the kind's own fields; `account` names the account when the
wallet has one (an identity may be active on one and suspended on
another, §4.1; otherwise the active one is meant). Response
`200 { "guard": "<token>" }`. Any failure — wrong secret, unknown
identity, policy not met — answers `403 forbidden/guard_rejected`; the
endpoint never reveals whether an address is in use. Cert failures
answer `422 invalid_cert/<reason>`.

Kinds (every registry offers the first; the rest are OPTIONAL and
advertised in `guard_kinds`, §5.1, the same list the refusal carries;
registries SHOULD offer one a user with no other device can pass):

- **`device_approval`** — approval from a device already on the
  account. The call files a `kind: "device"` request (§5.3), valid for
  the window, and answers `202 { "guard": "<request code>" }`: the
  code is the token, usable once approved. At most one open request
  per set of keys and 3 per (identity, source); a further one evicts
  the oldest from that source. An existing device shows it (identity,
  issuer, holder label, every key fingerprint) and answers
  `requests/respond` `{ "code", "approve" }` at write tier. The new
  device retries its call with `guard` set to the code, MAY long-poll
  the retry with `?wait=<seconds>` (cap 60), and gets
  `403 forbidden/guard_required` again while pending,
  `403 forbidden/guard_rejected` once denied or expired, and success
  once approved. Wallets SHOULD show the fingerprints on the new
  device for comparison.
- **`password`** — a secret the registry holds for the account, sent
  as `"secret"`. Wrong secrets are rate-limited per source and per
  account with backoff, never reported as a lockout. The secret SHOULD
  NOT be resettable using only the address being joined: whoever
  controls that address is who the guard exists to stop.
- **`additional_identities`** — fresh certs for further identities on
  the account, sent as `"extra": [ { "cert", "proof" }, … ]`, not
  recorded by this call. They MUST be distinct from `identity` and
  from each other's root (core §4.6) and active on the account; the
  policy is the advertised `min` and `distinct_issuer`.
- **`page`** — any check the registry runs in a browser. The wallet
  opens `url#certs=…&identity=…&return_url=…&return_origin=…` (the
  fragment and return convention of the issuer sign-in page,
  fallback-IdP API §3.1) and the page ends with
  `return_url#guard=<token>`. The page MUST show the identity and key
  fingerprints, MUST require an explicit user action, MUST NOT complete
  on ambient credentials alone, and MUST validate `return_origin`.

A wallet ignores kinds it does not recognise.

### 4.3 Authority — tiers

A session holds one of three **tiers** on its account, fixed when it
opens from the certs that opened it:

| Tier | Members | Reaches |
|---|---|---|
| **lookup** | auth certs only, none guarded | `warrants/lookup` (§5.4), for the identities the certs name; `certs/revoke` for its own certs; `session/end` |
| **read** | guarded, no config cert | every read on the account |
| **write** | a guarded config cert | everything |

Data belongs to the account: warrants, requests, certs, holders.
Everyone admitted sees and manages everything; two people who share an
address share the account it is on. A read session may attach a
config cert for its identity and open a write session: read is one
issuer sign-in away from write, by design.

Where a particular identity matters:

| Where | Rule |
|---|---|
| `respond`, `register` | the config cert MUST be a guarded, unretired cert of the account and MUST authorize the warrant's grantor (§7.1), judged by the identities it was *recorded* for |
| `warrants/lookup` | serves warrants for the identities the session's certs were recorded for |
| a suspended identity (§4.1) | its records are inert: `respond`, `register`, `detach`, and `allocate_status` naming it answer `403 forbidden/identity_suspended`; reads and lookup skip it |

A call below the tier it needs answers `403 forbidden/<reason>`:
`read_required` (a lookup session) or `write_required`.

Identities the registry's operator issues itself use this API like any
other. Issuing certs, passwords, and deleting the account are the
issuer API's operations, not this one's, so nothing here lets an
identity affect its own issuance.

### 4.4 Request proof — `browserid-registry-proof-v1`

A proof is a compact JWS with three parts: a protected header, a JSON
payload of claims, and a signature by a device-cert key over both.
Header: `{"alg": "EdDSA", "typ": "browserid-registry-proof-v1",
"kid": …}` — `alg`/`typ` MUST be exact; `kid` names the signing key
so the registry can find its cert, and is base64url(SHA-256(the key's
raw public bytes)). Payload claims:

| Claim | Meaning |
|---|---|
| `htm` | REQUIRED. Uppercase HTTP method. |
| `htu` | REQUIRED. Request URI: scheme, host, path — no query or fragment. |
| `iat` | REQUIRED. Seconds; MUST be within a small window (RECOMMENDED ±300s). |
| `jti` | REQUIRED. Unique random string; replays rejected within the window. |
| `bh` | base64url(SHA-256(request body bytes)). REQUIRED on the `Proof` header of every POST, `{}` included; absent on GET and on possession proofs carried inside a body. |

`htu` builds on the registry's advertised **public origin** (§5.1
`endpoint`'s origin): lowercase scheme and host, default ports
omitted, then the exact §5 route path; behind a proxy, compare against
the public origin, never the observed URI.

Every call carries two headers:

```
Authorization: Bearer <session token>
Proof: <proof JWS>
```

except the three that a device makes before it has a session —
`attach` (§5.2.1), `session` (§4.5), and `guard` (§4.2) — which carry
the header proof alone. Verification runs in this order, and the
first failure is the response:

1. parse the proof (`401 invalid_proof`);
2. resolve `kid` to a cert: on `attach` and `guard`, one carried in
   the call; on `session`, one recorded and unretired on the named
   account (`401 invalid_cert/unknown_key`); on any other call, a
   session member (`401 invalid_session`);
3. verify the signature under that cert's key (`401 invalid_proof`) —
   before anything that costs a network fetch;
4. the cert passes the validity bar (`401` on `session`, `422` on
   `attach` and `guard`, both `invalid_cert/<reason>`); for a session
   member, `exp` and status are re-checked, the signature is not;
5. every claim checks (`401 invalid_proof`);
6. tier (§4.3) and, where the call needs it, the guard (§4.2).

Proofs also travel inside the bodies of `session`, `attach`, and
`guard` as **possession proofs**: one per cert, signed by that cert's
key, without `bh`, all sharing the header proof's `jti`. The replay
cache is keyed by `kid` whether or not the key is recorded yet, and
holds each entry until its `iat` window closes.

### 4.5 Sessions

**`POST /api/v1/session`** — Opens a session.

```json
{ "account": "…", "proofs": [ "<JWS>", … ], "guard"?: "<token>" }
```

`proofs`: 1–8 possession proofs, each naming by `kid` a cert recorded
and unretired on `account` (`401 invalid_cert/unknown_key` otherwise —
including an unknown account or a key recorded elsewhere); every cert
passes the validity bar (`401 invalid_cert/<reason>`). `guard`: only
when the registry has asked this device to pass the guard again
(§4.2). Response `200`:

```json
{ "token": "…", "expires_at": "…", "account": "…", "tier": "write",
  "members": [ { "id": 7, "kid": "…" }, … ],
  "roster": [ { "identity": "dan@example.com", "state": "active" }, … ] }
```

`tier` is fixed for the token's life (§4.3). `members`: the certs the
session holds. `roster`: the account's identities, each
`state: "active" | "suspended"`; present at read tier and above. The
token is opaque to the client; server-side it identifies the member
set. Lifetime RECOMMENDED ≤ 24 h, ≤ 1 h at lookup tier.

On every call the registry re-checks each member's `exp` and status —
against a status list no older than its cache lifetime (§3) — and
drops any that fails or has been retired; every `2xx` response carries
`Session-Members: <n>`. A session with no member left answers
`401 invalid_session` (`WWW-Authenticate: Bearer`) and the wallet
opens a new one. A wallet opens a new session whenever it gains a
cert; two sessions may hold overlapping members.

**`GET /api/v1/sessions`** — Lists the account's live sessions: `id`,
`tier`, `members` (kids), `opened_at`, `expires_at`, `current`
(boolean). Read tier.

**`POST /api/v1/session/end`** — Ends a session: `{}` for the one the
call carries (any tier), or `{ "id": … }` for another (write tier).
Response `204`.

## 5. Endpoints

Everything here is §4 session-authenticated at the tier §4.3 names,
except §5.1 discovery (public) and `attach`, `session`, and `guard`
(§4.4). Each endpoint states what it does, its request, its response,
and its refusals as `<status> <error>/<reason>` (§7). Field lists are
normative; example values illustrative. Checks run in the order
written; where a call names a record, an unknown or foreign id answers
`404 not_found` before any tier check, except that an unknown
`account` on `attach` answers `403 forbidden/guard_required` (§5.2.1).

### 5.1 Discovery

A top-level `registry` object in the existing support document,
**`GET /.well-known/browserid`** (extends core §3.1). One document per
origin; a registry serves the keys for the roles it plays. A missing
`registry` key means "no registry API here"; unknown keys MUST be
ignored.

| Key (under `registry`) | Meaning |
|---|---|
| `version` | REQUIRED. Highest API version served (integer). |
| `endpoint` | REQUIRED. Absolute URL prefix of this API (`…/api/v1`, no trailing slash); MUST be same-origin with the advertising document. Its origin is the public origin §4.4 `htu` builds on. |
| `status_list` | REQUIRED. The registry's signed status list (core §6.3), same-origin. Advertisement only — verifiers reach lists through each status ref's `uri`, never discovery. |
| `browser` | REQUIRED (may be empty). Browser-ceremony URLs for flows a native wallet can't do natively; keys defined by the fallback-IdP spec (v1: `account`). |
| `guard_kinds` | REQUIRED. Every guard kind the registry offers (§4.2), as the `guard_required` body lists them, `device_approval` included. |
| `lookup_tier` | OPTIONAL, default `true`. `false`: the registry does not record unguarded auth certs (§5.2.1); a wallet then knows a shared-computer login needs a guard. |

No key material here (core §3.1: keys come solely from DNSSEC).

### 5.2 Account membership

Every call here concerns one identity. Rules in §4.1, guard in §4.2.

#### 5.2.1 Attach — `POST /api/v1/account/attach`

Records device certs for one identity on an account. It is the only
way a key becomes recorded and the only way an account is created.

| Field | Meaning |
|---|---|
| `Proof` header | REQUIRED. A §4.4 proof with `bh`, signed by the key of one of the carried certs. |
| `identity` | REQUIRED. The identity this call concerns. |
| `certs` | REQUIRED, 1–2 entries. `[{ "cert": "<JWS>", "proof": "<JWS>" }]`: the identity's auth cert, config cert, or both, each with a possession proof (§4.4) signed by its own key; every cert MUST name `identity` and both MUST carry one holder (`422 invalid_cert/holder_mismatch`). A cert naming further identities is recorded for those only where they are already on the account and its issuer is accepted for them; glob identities are refused (`422 invalid_cert/glob_identity`). |
| `account` | OPTIONAL. The account being joined. |
| `guard` | OPTIONAL. A guard token (§4.2). |
| `confirm_takeover` | OPTIONAL, default `false`. The user's explicit choice to take the identity away from the account that holds it. A wallet MUST set it only on a user's own act. |
| `Authorization: Bearer` | OPTIONAL. A session on `account`; a lookup session counts as none. |

Checks, in order: the header proof (§4.4); every cert against the
validity bar (`422 invalid_cert/<reason>`) and the holder rule; a
key already retired here (`422 invalid_cert/cert_revoked` — a retired
record is never revived); `409 conflict/holder_moved` if a cert's
holder has been moved, with `new_holder` in the body; then the case
below. Where a case needs them, freshness
(`422 invalid_cert/cert_not_fresh`) is checked before the guard
(`403 forbidden/guard_required`), and a valid `guard` is consumed
before `confirm_takeover` is considered. "Held by *a*" means the
account on which the identity is active; a suspended copy elsewhere
does not count.

**No account named.**

- *Held by no account* → a new account is created around the certs; a
  config cert is required (`422 invalid_cert/config_required`).
  Response names it.
- *Held by *a*, with a guard token for *a** → recorded on *a* at the
  certs' tier. The owner's new device.
- *Held by *a*, auth cert only, no guard* → recorded on *a* at
  **lookup** tier; a `joined` notice (§5.3) filed; response is the
  session body without `account`. A lookup device renews by
  repeating this call, which files no further notice. Refused
  (`403 forbidden/guard_required`) where `lookup_tier` is `false`
  (§5.1); with `confirm_takeover`, `422 invalid_cert/config_required`.
- *Held by *a*, config cert, no guard, no `confirm_takeover`* →
  `403 forbidden/guard_required`. Nothing is filed; the wallet obtains
  a guard (§4.2) or asks the user to confirm a takeover.
- *Held by *a*, config cert, `confirm_takeover`* → **takeover**: the
  identity leaves *a* (§4.1) into a new account created around the
  fresh certs.

**Account named** — the caller must hold a session on it or a guard
token for it; an unknown account, or one on which it holds neither,
answers `403 forbidden/guard_required`.

- *On this account* → recorded at the certs' tier, guarded.
  Idempotent on pubkey; a re-attached cert keeps its record and holder
  label.
- *Suspended on this account* → **restored** (§4.1): the identity
  leaves wherever it is active and returns. Fresh certs required.
- *Held by no account* → joins, under a write session. Fresh certs
  required.
- *Held by another account* → **transferred**: leaves there (§4.1) and
  joins here, under a write session, with `confirm_takeover`. Fresh
  certs required.

Freshness applies wherever an identity's account changes; recording a
cert for an identity already here needs none. Response `200`: the
§4.5 session body, naming the account except at lookup tier. Under an
existing session, the new token's members are the union of the call's
certs and the caller's members; the old token stays valid to expiry.

#### 5.2.2 Detach — `POST /api/v1/account/detach`

Removes an identity from the account. Request:
`{ "identity": "…", "guard"?: "<token>" }`; `identity` MUST be active
on the account (`404 not_found`; suspended ⇒
`403 forbidden/identity_suspended`). Authority: write; a registry MAY
require its guard as well (`403 forbidden/guard_required`). Effects:
those of an identity leaving an account (§4.1). Response `204`. The
last identity cannot be detached (`409 conflict/last_identity`): use
`delete`. Derived agent identities go with their parent, never a
refusal.

#### 5.2.3 Delete — `POST /api/v1/account/delete`

Deletes the account at this registry: every identity leaves (§4.1,
records on hold), then the account is dropped after the hold — or at
once with `"immediate": true`. Request:
`{ "immediate"?: true, "guard"?: "<token>" }`. Authority: write; a
registry MAY require its guard as well, and SHOULD for `immediate`.
Response `204`. Status bits already set stay set forever; indexes are
never reused (§8). This is the ability to leave a registry; it does
not touch the identities at their issuers. Exporting warrants and
holders for use at another registry is a v2 concern.

### 5.3 Consent inbox

Where agent requests wait for the user's decision. A requester (an
agent, a site, a page) files a request through the core §7.5 lanes;
the wallet lists it here, shows it to the user, signs the warrants,
and answers.

**`GET /api/v1/requests`** — Lists the account's open requests and
notices. Read tier; device requests are omitted below write tier.

Query: `?code=` shows one external request (`external: true`) by its
capability code — such requests are otherwise invisible, and query
strings SHOULD stay out of logs. `?wait=<seconds>` (cap 60) is an
OPTIONAL long-poll hint; answering at once is conformant.

Response `200`: `{ "status_uri": …, "requests": [ … ] }`. `status_uri`
is the registry's status-list URI, the `uri` half of the status refs
the wallet embeds in warrants it signs.

Every item has a `kind`, which says who is asking for what:

- `"agent"` — an agent asks the user for warrants (core §7.5);
- `"connection"` — a site asks the user to admit an agent's
  connection to it, which the user answers with a self-grant
  (core §7.5);
- `"authoring"` — a site asks the user to admit an agent as an
  author on it (core §7.5);
- `"device"` — a new device asks to join the account (§4.2);
- `"notice"` — the registry tells the user an identity changed
  hands (§4.1); nothing to answer.

Which fields an item carries depends on its kind; a ✓ below means
present:

| Field | agent | connection | authoring | device | notice |
|---|---|---|---|---|---|
| `code` — the capability code | ✓ | ✓ | ✓ | ✓ | ✓ |
| `grantor` — the identity to sign as; `"*"` lets the approver choose | ✓ | ✓ | ✓ | | |
| `grantee` — the agent identity asking | ✓ | | ✓ | | |
| `holder` — the holder id the grant binds to | ✓ | | ✓ | | |
| `grants` — `[{ audience, scopes, status_idx?, grantee? }]`, one warrant per entry, in order; `grantee` absent means the request's | ✓ | ✓ | ✓ | | |
| `label`, `display_name?`, `message?`, `client_host?`, `client_name?`, `agent_created_at?`, `known` (the grantee already holds a warrant here) | ✓ | ✓ | ✓ | | |
| `binding_id` — the connection's broker-minted binding (core §7.5) | | ✓ | | | |
| `devices` — `[{ identity, iss, holder, label?, fingerprint, purpose, issued_at }]`, every cert shown; answered with `approve` alone | | | | ✓ | |
| `notice` — `{ identity, reason, at, hold_until?, cert_id?, holder_label? }`; `reason` one of `"transferred"`, `"taken"`, `"detached"`, `"restored"`, `"joined"` (a lookup key joined; `cert_id` names it); no response, expires after the hold | | | | | ✓ |
| `external`, `created_at`, `expires_at` | ✓ | ✓ | ✓ | ✓ | ✓ |

`expires_at` mirrors the filing lane's `expires_in` (core §7.5);
device requests use the §4.2 window. A wallet SHOULD render a request
from a grantee it has never met deny-first.

**`POST /api/v1/requests/claim`** — Claims a pending agent,
connection, or authoring request and allocates a status index into
each of its grants that lacks one, so every warrant the wallet signs
carries a ref (core §5). Request: `{ "code": … }`. Response `200`: the
request item as `GET requests` shows it. Write tier. The request's
core §7.5 audience proof MUST validate at claim time (a fresh fetch is
RECOMMENDED); otherwise `422 invalid_warrant/audience_unproven`.
Idempotent per account; a code that is unknown, expired, or claimed by
another account answers `404 not_found`.

**`POST /api/v1/requests/respond`** — Approves or denies a request.

| Field | Meaning |
|---|---|
| `code` | REQUIRED. Unknown, expired, already answered, or a notice ⇒ `404 not_found`. |
| `approve` | REQUIRED. When `false`, the other fields are ignored. For `kind: "device"`, `true` needs nothing else either. |
| `warrants` | On approve: `["<JWS>", …]`, one client-signed warrant per grant, in order; all or nothing (`422 invalid_warrant/warrant_count_mismatch`). |
| `config_cert` | On approve: the config cert whose key signed them. MUST be a guarded, unretired cert of the account (`422 invalid_warrant/config_cert_not_recorded`). |
| `grantor` | OPTIONAL, default the request's `grantor`. Must equal it when pinned (`grantor_pinned_mismatch`); when the pin is `"*"`, any identity on the account the `config_cert` authorizes. |

Authority: write. Validation follows §7.1's `invalid_warrant` reasons
in order (`422 invalid_warrant/<reason>`). That bar is written for
`kind: "agent"`. The other kinds carry **admission records** — a
warrant the approver signs to admit a connection or an authoring
grantee (core §6.4): for `"connection"` each is a self-grant by the
approver (`grantor == grantee`, else `not_self_grant`) embedding the
request's `binding_id` (else `binding_mismatch`); for `"authoring"`
each matches its grant's `grantee`, audience, and scopes, with the
approver as grantor. Every record is signed with the account's
config-cert key.

On approve the registry stores each `{warrant}~{config_cert}` for
single pickup by the requester's core §7.5 poll and upserts a §5.4
warrant record. Response `200`: `{ "return_url": … }` when the request
carried one (an absolute URL the requester supplied at filing), else
`{}` (always `{}` for a deny).

### 5.4 Warrant registry

The account's record of the warrants it has signed, with per-warrant
revocation bits on the registry's status list. A revoke is reflected
in the published list within the list's own cache lifetime; `revoked`
in `GET warrants` reflects the registry's state at once and MAY lead
the list. Records are keyed by
`(account, grantor, grantee, audience, scopes-as-set)`.

**`GET /api/v1/warrants`** — Lists the account's registered warrants.
Each item: `id`, `grantor`, `grantee`, `audience`, `scopes`,
`warrant` (JWS), `status` (`{ uri, idx }`, absent unless indexed on
this registry's list), `revoked` (the bit, or `false` when unindexed),
`holder?` (matcher string), `config_cert?` (JWS), `binding_id?`,
`client_host?`, `client_name?`, `requester_origin?`, `suspended`
(§4.1), `signed_at`, `expires_at`.

**`POST /api/v1/warrants/lookup`** — Returns the warrants for one
audience, so a device can log into a site with a warrant it does not
hold. Request: `{ "audience": "…" }`. Response `200`:
`{ "warrants": [ { warrant, config_cert, holder?, status? } ] }`, the
records that

- are for exactly that audience,
- are not suspended,
- have a grantor among the identities any member cert was recorded
  for, and
- have a holder matcher covering that cert's holder,

each with the config cert needed to present it; an empty list when
none (never `404`). Lookup tier — the one call open to a lookup
session (§4.3). A miss reveals whether the account uses a site, so
registries MUST rate-limit lookups per identity and per account and
SHOULD lock an identity's lookup keys after repeated misses, counted
per audience (`429 slow_down`); thresholds are the registry's.

**`POST /api/v1/warrants/register`** — Records a warrant the wallet
signed outside the inbox flow (for example a login warrant). Request:
`{ "warrant": "<JWS>", "config_cert": "<JWS>" }`. Response `200`:
`{ "id", "indexing": "indexed" | "unindexed" }`. Authority: write. The
warrant MUST verify against the config-cert key; the cert MUST be
`purpose: authorization`, authorize the grantor, and be a guarded,
unretired cert of the account; the grantor MUST be an account identity
— `422 invalid_warrant/<reason>` per §7.1. A ref on this registry's
own list is recomputed from the record key as `allocate_status` would
— match ⇒ `indexed`; mismatch or a foreign ref ⇒ recorded with no
index, `unindexed`. Registering never clears a set bit: a revoked
warrant stays revoked, and re-registering the same record replaces
its `warrant`, `signed_at`, and `expires_at`.

**`POST /api/v1/warrants/revoke`** — Revokes a warrant by setting its
status bit; sticky; a second revoke is a `204`. Request:
`{ "id": 42 }`. Response `204`. After a revoke, the record's key
allocates a fresh index on the next `allocate_status` or `claim`, so a
later grant to the same agent never revives the old bytes. An
unindexed record cannot be revoked here (`409 conflict/no_status_ref`):
`unlist` it and, if the agent still needs access, let it request
again.

**`POST /api/v1/warrants/unlist`** — Deletes the record **without
revoking**; the signed warrant stays valid to expiry. Request:
`{ "id": 123, "confirm_unrevoked"?: true }`. Response `204`. Meant for
expired or unindexed records; an unexpired indexed record is refused
(`409 conflict/live_warrant`) unless `confirm_unrevoked` is `true`.

**`POST /api/v1/warrants/allocate_status`** — Allocates a status ref
before the wallet signs, so login warrants carry per-site revocation
bits. Request: `{ "grantee", "audience", "scopes" }` (`grantee` is the
identity that will present the warrant; for a login warrant, the
wallet's own). Response `200`: `{ "uri", "idx" }`, stable for the
record key until that record is revoked. An index once allocated is
never reused for the lifetime of the list URI (§8).

### 5.5 Certs

The certs recorded on the account, one record per cert. Certs are
recorded by `attach` (§5.2); there is no separate recording call.
Retired certs stay listed.

**`GET /api/v1/certs`** — Lists the account's recorded certs: `id`,
`kid`, `identities` (those it was recorded for), `purpose`, `guarded`
(§4.3), `holder`, `pubkey`, `iss`, `issued_at`, `expires_at`,
`revoked` (retired here, or the issuer's bit where this registry reads
it), `status?` (`{ uri, idx }`).

**`POST /api/v1/certs/revoke`** — Revokes a cert. Request:
`{ "id": 7 }` or `{ "kid": "…" }` (not both). Response `200`:
`{ "revoked": bool }`. Authority: any tier for a cert the session
itself holds; otherwise write, and a registry SHOULD require its guard
(§4.2) for another device's cert. When this registry is the cert's
revocation authority (`iss` is its domain) it sets the bit, sticky,
and answers `true`. Either way the cert is **retired** here: excluded
from holder matching and from session membership, dropped from any
session on its next call. For a foreign issuer the registry cannot set
the bit and answers `{ "revoked": false }`; the wallet MUST then
revoke at the issuer before telling the user the device is gone, since
the cert still works at RPs until the issuer's bit is set.

### 5.6 Holders and namespaces

Holders are the devices and agents that present warrants; namespaces
group them under a shared prefix. A device's auth and config certs
carry the same holder (core §4.1). Namespaces are the three core §4.5
defines — `browsers`, `agents`, `services` — each with a prefix the
registry assigns; an account may relabel them, not create or delete
them.

**`GET /api/v1/holders`** — Lists holders by namespace. Response
`200`: `{ "namespaces": [ { name, prefix, label, holders: [ … ] } ],
"holders_without_namespace": [ … ] }`, both holder lists the same
shape: `holder_id` (string), `label`, `trust` (`"trusted"`: holds a
config cert; `"login-only"`), `cert_count`, `issued_at?`,
`warrant_count`, `revoked` (every cert retired), `external` (the holder
of another account's agent admitted by a connection, core §6.6),
`identities`, `moving_to?` (holder id).

**`POST /api/v1/holders/rename`** — Relabels a holder. Request:
`{ "holder_id", "label" }`. Response `204`.

**`POST /api/v1/holders/move`** — Moves a holder into a namespace.
Request: `{ "holder_id", "namespace" }`. Response `200`:
`{ "new_holder": "<holder id>" }`. Retires every cert on the old
holder, keeps the label, and records the new holder id; the device
learns it from the `holder_moved` refusal on its next `attach`
(§5.2.1) and re-issues under it. Warrants whose matcher named the old
holder keep their bits. If the caller's own members are on the holder,
the call succeeds and the session dies on its next call. Refused for
external holders (`409 conflict/external_holder`) and same-namespace
moves (`409 conflict/already_in_namespace`).

**`POST /api/v1/holders/forget`** — Retires a holder's certs (setting
bits where it can), then deletes it. Request: `{ "holder_id" }`.
Response `200`: `{ "unrevocable": [ "<issuer domain>", … ] }`, the
issuers whose bits it could not set; the wallet MUST revoke there.

**`POST /api/v1/namespaces/rename`** — Relabels a namespace. Request:
`{ "name", "label" }`. Response `204`.

Authority: write for every mutation; a registry SHOULD require its
guard (§4.2) for `move` and `forget` of a holder the session does not
itself hold. Labels per §3. Holders are addressable only when on the
account (`404 not_found`, no existence leaks).

## 6. Out of scope

- **Issuance** (fallback-IdP role, own spec).
- **Agent-facing lanes** (`/warrant/*`, `/agent-provision/*`) — core
  §7.5; this API is the approver's side.
- **Public surfaces** (status lists, `/verify`) — unauthenticated by
  design, core §6.
- **Credential ceremonies** (passwords, mailbox and bridge
  verification, `account_cancel`, tenants) — issuer concerns.
  Membership is in scope (§5.2); the identities' credentials are not.

## 7. Errors

JSON in the shape of RFC 6749 §5.2:

```json
{ "error": "invalid_proof", "error_description": "jti replayed" }
```

| HTTP | `error` | When |
|---|---|---|
| 400 | `invalid_request` | Malformed JSON, missing or unknown fields, grammar violations, bodies over the limit. |
| 401 | `invalid_session` | Token missing, unknown, expired, or ended; no member left after the per-call re-check (§4.5); the `Proof` key is not a member. Carries `WWW-Authenticate: Bearer`. |
| 401 / 422 | `invalid_cert` | A cert fails the validity bar or a membership rule: `401` on `session`, `422` on `attach` and `guard`. |
| 401 | `invalid_proof` | A request or possession proof fails, on any call: missing, wrong `typ`, bad signature, `htm`/`htu` mismatch, stale `iat`, replayed `jti`, `bh` mismatch, or proofs in one request with differing `jti`. |
| 403 | `forbidden` | The session is below the tier the call needs, the identity named is suspended, or a guard is needed or rejected (§7.1). |
| 404 | `not_found` | Owner-scoped lookup misses — including "exists but isn't yours" — and requests that are unknown, expired, or answered. |
| 409 | `conflict` | State refusals. |
| 422 | `invalid_warrant` | Respond, claim, register: client-signed warrants (or the claim precondition) fail the §5.3/§5.4 bar. |
| 429 | `slow_down` | Rate limits; SHOULD carry `Retry-After`. |

`error_description` is diagnostic and MUST NOT be parsed; machine
reasons ride the OPTIONAL `reason` field, and a reason MAY define
further top-level fields (`guard_required` does, §4.2). When a token
and a proof are both bad, the proof's error is reported.

### 7.1 Machine reasons

Reasons are stable surface: implementations MAY add them; clients MUST
treat unrecognized reasons as the bare `error`. The core §7.5 poll
lanes keep their own vocabulary, disjoint from this.

With `invalid_warrant` (`422`, §5.3 respond/claim and §5.4 register),
in check order:

| Reason | Meaning |
|---|---|
| `warrant_count_mismatch` | `warrants` length ≠ grants (all-or-nothing). |
| `config_cert_invalid` | Config cert fails to parse or verify. |
| `config_cert_wrong_purpose` | Not `purpose: authorization`. |
| `config_cert_expired` | Past `exp`. |
| `config_cert_not_recorded` | Not a guarded, unretired cert of the account (§5.3, §5.4). |
| `grantor_not_authorized` | Config cert was not recorded for the grantor. |
| `grantor_not_owned` | Grantor is not an account identity. |
| `grantor_pinned_mismatch` | Differs from the request's pinned grantor. |
| `warrant_invalid` | Warrant fails to parse or verify against the config-cert key. |
| `audience_mismatch` / `grantor_mismatch` / `grantee_mismatch` | Warrant claim differs from grant/request. |
| `not_self_grant` / `binding_mismatch` | Connection record is not a self-grant, or does not embed the request's `binding_id` (§5.3). |
| `not_holder_bound` | No holder matcher where one is required. |
| `wildcard_holder` | Bare `*` matcher. |
| `holder_mismatch` | Matcher does not match the grantee's holder. |
| `status_ref_missing` / `status_ref_mismatch` | Grant has `status_idx` but the warrant's `status` is absent or differs from `{uri, idx}`. |
| `audience_unproven` | Claim: the core §7.5 audience proof does not validate. |

With `forbidden` (`403`):

| Reason | Meaning |
|---|---|
| `write_required` | The session is at read tier. |
| `read_required` | The session is at lookup tier (§4.3). |
| `identity_suspended` | The call names an identity suspended on this account (§4.1). |
| `guard_required` | The guard was not passed (§4.2): on `attach`, `detach`, `delete`, or `session` when the registry asks; a device-approval retry still pending; body carries `guard_kinds`. |
| `guard_rejected` | `guard`: wrong secret, unknown identity, denied or expired approval, or a policy the extra identities do not meet (§4.2). |

With `invalid_cert` — the **validity bar** (`401` on `session`, `422`
on `attach` and `guard`), in check order:

| Reason | Meaning |
|---|---|
| `unknown_key` | `session` only: a proof's `kid` matches no unretired cert recorded on the named account, or the account is unknown — attach first (§4.4). |
| `cert_malformed` | Fails to parse as a device cert. |
| `wrong_purpose` | Purpose is neither `authentication` nor `authorization`. |
| `cert_expired` | Past `exp`. |
| `issuer_not_accepted` | For any identity the cert is recorded for: the issuer is neither that domain's DNSSEC-published IdP nor in the registry operator's accepted-fallback set (core §8.1; default: the registry's own domain). |
| `signature_invalid` | Does not verify under the resolved issuer key. |
| `cert_revoked` | The cert carries a status ref and it checks revoked or cannot be fetched (fail-closed), or the key was retired here; a cert with no ref passes. |

And the **membership rules** (`422`, `attach` and `guard` only):

| Reason | Meaning |
|---|---|
| `cert_not_fresh` | A cert moving an identity was issued more than 300 s ago (§5.2.1). |
| `config_required` | Creating an account, or confirming a takeover, with no config cert (§5.2.1). |
| `glob_identity` | The cert's `identities` contain a glob (§5.2.1). |
| `holder_mismatch` | The two certs carry different holders (§5.2.1). |

With `conflict` (`409`):

| Reason | Meaning |
|---|---|
| `no_status_ref` | Revoking an unindexed warrant (§5.4). |
| `live_warrant` | Unlisting an unexpired indexed warrant without confirmation (§5.4). |
| `external_holder` / `already_in_namespace` | `holders/move` preconditions (§5.6). |
| `holder_moved` | Attaching onto a moved holder; body carries `new_holder` (§5.2.1). |
| `last_identity` | Detaching the only identity (§5.2.2). |

## 8. Versioning and conformance

`/api/v1/` is the compatibility contract: additive changes only;
breaking changes get `/api/v2/`. The proof `typ` is versioned
independently, rejected fail-closed on mismatch. Beyond the rules of
§4 and §5, a conformant registry upholds:

1. No anonymous operations. Discovery (§5.1) is public; every other
   call is proven by a device-cert key, mutations signed down to their
   body bytes.
2. The guard is the account's boundary. A key joins an existing
   account only past the guard or under a session on it; from outside
   an account nothing is observable but that an address is in use and,
   where the lookup tier is on, which of its warrants cover a named
   site for a fresh auth cert's holder. Whoever takes an identity
   inherits nothing.
3. The registry never signs or alters warrants; approval carries
   warrants signed by the account's config-cert key.
4. DNSSEC is the sole root of trust for identity keys; no Web-PKI path
   to a key.
5. A status index, once allocated, is never reused for the lifetime of
   its list URI; bits of dropped records stay set.
