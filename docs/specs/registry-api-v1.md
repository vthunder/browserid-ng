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
their account to another registry (§5.2.6).

- **Auth**: a wallet logs in to an account (§4.2) with a **login key**
  of its own, gets a session bound to that key, and signs every
  request with it (§4.4). Identity certs prove who holds an address;
  they never open a session by themselves and never sign requests.
- **Revocation is a record**: revoking a login key ends its sessions
  and sends the device back to login; revoking a cert retires it from
  the account, fail-closed.
- **Consent is API-complete**: approval carries the same client-signed
  warrants as a browser consent page would (§5.3).
- **No CSRF** — auth is header-borne, never ambient.

The flows, at a glance (the wallet's side; RP login itself is core
§7.3):

| Flow | What the wallet does |
|---|---|
| First use | Issuer sign-in → auth + config cert → `accounts` (§5.2.1) with the wallet's login key: the account is created around the identity, the key is enrolled, and a session returned. |
| New device | Issuer sign-in → certs → `accounts/lookup` for the account → `login` (§4.2) with the wallet's login key: the registry's login page the first time, the stored key after; then `attach` the certs. A shared computer is a new device like any other. |
| Sign in at an RP | `GET warrants` (§5.4) for a warrant the device may present when it lacks one, `allocate_status` (§5.4) when minting one; then present. |
| Approve an agent | `GET requests` → `respond` with client-signed warrants (§5.3). |
| Add an identity | Issuer sign-in for it → `attach` under a session (§5.2.4). |
| Take an identity from another account | The same, with the user's confirmation; the previous account is notified and its rows go on hold (§4.1). |
| Remove an identity; leave | `detach` (§5.2.5); `delete` (§5.2.6). |
| Manage | Warrants (§5.4), certs (§5.5), holders (§5.6). |

## 2. Actors and terminology

| Term | Meaning |
|---|---|
| **Registry** | The service implementing this API. |
| **Wallet** | The client: holds the user's device keys, builds presentations, renders consent UI. |
| **Issuer** | The identity provider for an address's domain, or an accepted fallback: it issues the device certs a wallet presents here (core §4). |
| **Identity** | An email-shaped address a cert names; a *derived agent identity* (`dan+cal@…`) is one carved from it for an agent (core §4.6). Identities compare after lowercasing; a derived identity is held wherever its root is. |
| **Device cert** | A cert an issuer signs over a wallet's key for an identity (core §4.1): an **auth cert** (`purpose: authentication`) mints the short-lived *access certs* a login presents; a **config cert** (`purpose: authorization`) signs warrants (§4.3). A cert is **fresh** when issued within the last 300 s. |
| **Warrant** | A grant the user's config cert signs for an audience, with scopes and a holder matcher, checked by relying parties against the registry's status list (core §5, §6.3). |
| **Presentation** | What a login shows an RP: `access_cert~assertion~warrant~config_cert` (core §5). |
| **Holder** | An opaque id the wallet chooses and the issuer stamps on a device's certs; warrants bind to holders, and namespaces group them (core §4.5). |
| **Account** | The identities that share one set of warrants, certs, holders, and an inbox, named by an opaque id (§3). Created by §5.2.1 `accounts`; changed only under a session. All of an account's identities are equals: which one authenticated is a per-call fact, never a rank. |
| **Login / login key** | A login (§4.2) is how a wallet authenticates to an account by a method the registry offers; it yields a session. A *login key* is a key the wallet generates for itself, enrolled on the account at login, that opens later sessions with no human and signs every request (§4.4). |
| **Session** | An opaque token on one account, opened by a login and bound to the login key that opened it (§4.5). |
| **Member** | An identity on the account, or a cert recorded for one. |
| **Device** | A login key and the certs attached under it (§5.2.4). What the account page lists and what "sign out" acts on (§5.2.3). Agents and services have no login key; their device is their holder (§5.6). |
| **Recorded / retired** | A cert is *recorded* on an account by `attach`, always under a session; *retired* when the account revokes it, its holder is forgotten, or it is dropped (§5.5). Retirement is permanent. |
| **Validity bar** | The `invalid_cert` checks of §7.1, `cert_malformed` through `cert_revoked`; every cert passes it when recorded. |
| **Suspended** | The state of an identity that has left an account (§4.1): its records kept but inert for the **hold**, restorable if it returns. |
| **Transfer / takeover** | An identity leaving one account for another: a *transfer* when the destination's session did it (`attach`); a *takeover* when a fresh config cert created a new account around it (`accounts`). Both need the user's confirmation and land the identity with nothing inherited. |
| **Capability code** | The opaque `code` that names a pending request (§5.3); the agent lanes (core §7.5) call it `request_id`. |
| **Status list / status ref** | The registry's signed revocation bitfield and `{uri, idx}` pointers into it (core §6.3). A warrant record is *indexed* when its ref is on this registry's list. |

## 3. Common conventions

- Bodies are JSON, UTF-8. No `success: true` — status codes carry
  success, §7 the errors. Refusals are cited as `<status>
  <error>/<reason>`, e.g. `403 forbidden/login_rejected`: §7
  defines every `error`, §7.1 every `reason`.
- Data-free mutations return `204`; others `200` + JSON. OPTIONAL
  fields are absent, never `null`.
- Unknown request fields MUST be rejected (`400 invalid_request`);
  unknown response fields MUST be ignored (additive evolution, §8).
  Unknown query parameters are ignored.
- GETs are pure; every mutation is a POST. Mutations are idempotent
  where §5 says so (attach on pubkey, revokes sticky); a wallet
  retrying an ambiguous failure repeats the call.
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

Two things authenticate here. A wallet **logs in** to an account by a
method the registry offers (§4.2), bringing a **login key** of its own,
which yields a session bound to that key. And every call under that
session is proven by that key (§4.4).
The model comes first (§4.1), then login, then what a session may do
(§4.3), then the proof (§4.4) and the session (§4.5) that carry it all.

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
2. **Joining an account needs a session on it.** An identity, or a new
   key for one, joins an existing account only under a session on it
   (§4.5), which only a login opens (§4.2). Outside any account a
   fresh config cert may create a new one (§5.2.1), taking a held
   identity only when the user confirms; an auth cert alone creates
   nothing.
3. **Leaving puts the identity on hold.** When an identity leaves an
   account — transferred, taken over, or detached — it is marked
   **suspended** there: its warrants' bits set, its derived agents
   suspended with it, its records frozen, a `notice` (§5.3) filed. The
   account's certs, sessions, and other identities are untouched.
   Within the **hold** (RECOMMENDED 30 days) the identity may
   **return** by rule 2 and is restored: the bits suspension set are
   cleared, bits set by an explicit revoke stay set. After the hold
   the records are dropped; an account whose every identity has left
   is dropped with them, together with its open requests and tokens.

A suspended identity shows in the roster with `state: "suspended"`
and is not an account identity for any other purpose: a call naming
it is refused as it would be for a stranger's identity. The hold
protects against issuer mistakes and races over a mailbox, not
against losing the address: an owner who cannot log in cannot
return. A registry that also runs an issuer MUST NOT let a
newly joined address reset the issuer's password until the issuer
has verified it itself.

### 4.2 Login

A cert proves that its holder controls an address today. It cannot
prove that the holder is the person whose account that address is on.
Login is the registry's check for that, and the only way a session is
opened. Which methods a registry offers is its business; v1 defines
two, and a registry MUST offer both:

- **`login_page`** — a page the registry runs. The wallet opens
  `url#account=…&return_url=…&return_origin=…` (the fragment and return
  convention of the issuer sign-in page, fallback-IdP API §3.1) and the
  page ends with `return_url#login=<token>` or
  `return_url#login_error=<reason>`. What the page checks is the
  registry's business: a password, approval from a device already
  logged in, proof of another identity on the account obtained through
  the login mediator (core §7.3) as any site would. The page MUST
  require an explicit user action, MUST NOT complete on ambient
  credentials alone, and MUST validate `return_origin` (same-origin
  with `return_url`; no allowlist — whoever holds the token still needs
  the account, and the token is one-time, short-lived, and bound to it).
- **`stored_key`** — possession of a login key enrolled on this
  account, unexpired and unrevoked; no human involved.

**Login keys.** Every wallet generates one login key per registry
(non-extractable where the platform allows) and brings it to every
call that opens a session: `accounts` (§5.2.1) and `login`. The
registry **enrols** the key on the account the first time it sees it
pass a login, keeping `{ id, kid, pubkey, label, holder?, enrolled_at,
expires_at, revoked_at? }`, and issues nothing: it is the only party
that ever checks a login key. `holder` is the device's holder, set
when certs are recorded under a session on this key (§5.2.4), and is
what lets forgetting a device (§5.6) log it out. Expiry is registry
policy, RECOMMENDED 90 days from the last login through the page.
Login keys are listed and revoked at §5.2.3; a re-enrolment of a key
the registry already knows — expired or revoked — restores its record,
label and holder kept, since a human just passed the check. They are
the registry's credential, independent of identity certs: a device
stays able to log in to its account whatever happens to its identities
at their issuers — which is what lets it see a notice and restore an
identity within the hold (§4.1).

**`POST /api/v1/login`** — Opens a session.

```json
{ "account": "…", "method": "login_page", "token"?: "…",
  "login_key": { "pubkey": "…", "label"?: "…", "proof": "<JWS>" } }
{ "account": "…", "method": "stored_key", "proof": "<JWS>" }
```

Both carry the §4.4 header proof signed by the login key; `login_key`
(`pubkey` the base64url raw Ed25519 key, `label` per §3, `proof` a
possession proof by it) names the key `login_page` enrols, and
`stored_key`'s `proof` is the possession proof of the key already
enrolled, named by its `kid`. Success answers the §4.5 session body.

Two refusals. `403 forbidden/login_required` with `{ "url": … }`, the
page to open, is the answer whenever the registry will not open a
session headlessly: `login_page` without a token, and `stored_key`
with a key that is unknown, expired, or revoked. `403 forbidden/
login_rejected` is a bad or spent token, or the page refused. Neither
reveals whether an account or key exists — the URL is handed to
anyone, and a spent token looks like a bad one. Rate-limited per
source and per account (§3).

### 4.3 Authority

Data belongs to the account: warrants, requests, certs, holders.
A session sees and manages everything on its account; two people
who share an address share the account it is on. There is no tier
above a session: login (§4.2) is the whole check, and a session
opened by a login key alone — a page, a device with no identity
certs — manages the account like any other.

What a session cannot do is sign. Calls that store a signature the
wallet made — `respond`, `register` — carry the signing **config
cert**, which MUST be an unretired cert of the account and MUST
authorize the warrant's grantor (§7.1), judged by the identities it
was *recorded* for. The session proves the caller may act on the
account; the cert proves the signature is the account's.

Identities the registry's operator issues itself use this API like any
other. Issuing certs, passwords, and deleting the account are the
issuer API's operations, not this one's, so nothing here lets an
identity affect its own issuance.

### 4.4 Request proof — `browserid-registry-proof-v1`

A proof is a compact JWS with three parts: a protected header, a JSON
payload of claims, and a signature over both by the key it is for —
the session's login key on the `Proof` header, the cert or key being
proven in a possession proof.
Header: `{"alg": "EdDSA", "typ": "browserid-registry-proof-v1",
"kid": …}` — `alg`/`typ` MUST be exact; `kid` names the signing key
so the registry can find it, and is base64url(SHA-256(the key's raw
public bytes)). Payload claims:

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

except the calls a device makes before it has a session — `accounts`
and `accounts/lookup` (§5.2.1) and `login` (§4.2) — which carry the
header proof alone. The header proof is signed by the login key: the
session's, or on `accounts` and `login` the one the call brings. The
one exception is `accounts/lookup`, whose caller has certs and no
account yet: it is signed by a carried cert. Verification runs in this
order, and the first failure is the response:

1. parse the proof (`401 invalid_proof`);
2. resolve `kid` to a key: on `accounts/lookup`, a cert carried in the
   call; on `accounts` and `login` by `login_page`, the `login_key`
   the call carries; on `login` by `stored_key`, an enrolled key of the
   named account (`403 forbidden/login_required`); on any other call,
   the session's key (`401 invalid_session`);
3. verify the signature under that key (`401 invalid_proof`) — before
   anything that costs a network fetch;
4. a carried identity cert passes the validity bar
   (`422 invalid_cert/<reason>`); the session's key is unexpired and
   unrevoked (`401 invalid_session`);
5. every claim checks (`401 invalid_proof`).

Proofs also travel inside the bodies of `accounts`, `login`, and
`attach` as **possession proofs**: one per cert or key being enrolled
or proven, signed by it, without `bh`, all sharing the header proof's
`jti`. They are where a key is authenticated; the header proof is how
a session is used. The replay cache
is keyed by `kid` whether or not the key is recorded yet, and holds
each entry until its `iat` window closes.

### 4.5 Sessions

A session is opened only by `login` (§4.2) or `accounts` (§5.2.1),
and is bound to the login key that call carried. Response `200`, the
**session body**:

```json
{ "token": "…", "expires_at": "…", "account": "…",
  "key": { "id": 3, "kid": "…", "label": "Dan's laptop" },
  "roster": [ { "identity": "dan@example.com", "state": "active" }, … ] }
```

`key`: the login key that signs this session's proofs. `roster`: the
account's identities, each `state: "active" | "suspended"`. The token
is opaque to the client. Lifetime RECOMMENDED ≤ 24 h.

A session ends at expiry, by `session/end`, when its key is revoked
(§5.2.3) or expires, or when the registry ends it for any reason of
its own. Every ending looks the same to the wallet:
`401 invalid_session` (`WWW-Authenticate: Bearer`), and it logs in
again by `stored_key`. These are the registry's two levers over a
device: end a session, and the device carries on after a headless
login; revoke its key, and the device gets `login_required` (§4.2) and
must pass the page again. Recording certs (`attach`) does not change
the session.

**`POST /api/v1/session/end`** — Ends the session the call carries.
Request `{}`. Response `204`.

## 5. Endpoints

Everything here is §4 session-authenticated, except §5.1 discovery
(public), `accounts` and `accounts/lookup` (§5.2.1), and `login`
(§4.2). Each
endpoint states what it does, its request, its response, and its
refusals as `<status> <error>/<reason>` (§7). Field lists are
normative; example values illustrative. Checks run in the order
written; where a call names a record, an unknown or foreign id answers
`404 not_found`.

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
| `browser` | REQUIRED. Browser-ceremony URLs for flows a native wallet can't do natively; keys defined by the fallback-IdP spec (`account`) and this one (`login`, the §4.2 login page). |
| `login_methods` | REQUIRED. The §4.2 methods this registry offers: `["login_page", "stored_key"]` in v1. |

No key material here (core §3.1: keys come solely from DNSSEC).

### 5.2 Accounts and membership

Every call here concerns one account or one identity. Rules in §4.1,
login in §4.2.

#### 5.2.1 Accounts — `POST /api/v1/accounts`, `POST /api/v1/accounts/lookup`

**`accounts`** creates an account around one identity. It is the only
way an account is created.

| Field | Meaning |
|---|---|
| `Proof` header | REQUIRED. A §4.4 proof with `bh`, signed by the login key. |
| `identity` | REQUIRED. |
| `login_key` | REQUIRED. `{ "pubkey", "label"?, "proof" }` as in `login` (§4.2): the wallet's login key, enrolled on the new account with the certs' holder. |
| `certs` | REQUIRED, 1–2 entries, `[{ "cert", "proof" }]` as in `attach` (§5.2.4); a config cert is required (`422 invalid_cert/config_required`), and every cert MUST be fresh (`422 invalid_cert/cert_not_fresh`). |
| `confirm_takeover` | OPTIONAL, default `false`. The user's explicit choice to take the identity away from the account that holds it. A wallet MUST set it only on a user's own act. |

Checks, in order: the header proof (§4.4); every cert against the
validity bar, the holder rule, and the retired-key rule (§5.2.4); then:
held by no account → created; held by an account and
`confirm_takeover` unset → `409 conflict/identity_held`, nothing
filed; held and confirmed → **takeover**: the identity leaves that
account (§4.1) into the new one. Either way the certs are recorded
on the new account, the login key is enrolled, and the response is its
§4.5 session body — the creator's first session. Setting up a way for
other devices to log in (a password) is the wallet's next move.

**`accounts/lookup`** finds the account an identity is active on.
Request: `{ "identity", "certs": [ { "cert", "proof" } ] }` with a
`Proof` header by one of them — the same bar as `accounts`, freshness
not required. Response `200 { "account": "…" }`, or `404 not_found`
when no account holds it (a suspended copy does not count). Nothing
else about the account is revealed.

#### 5.2.2 Login — `POST /api/v1/login`

Defined in §4.2.

#### 5.2.3 Login keys — `/api/v1/login-keys`

Enrolment happens at login (§4.2); there is no separate call.

**`GET /api/v1/login-keys`** — The account's login keys: `id`, `kid`,
`label`, `holder?`, `enrolled_at`, `expires_at`, `revoked`, `current`
(`true` on the key this session is bound to). Revoked ones stay
listed.

**`POST /api/v1/login-keys/rename`** — Relabels a device. Request
`{ "id", "label" }` (label per §3). Response `204`; an unknown or
foreign id is `404 not_found`.

**`POST /api/v1/login-keys/revoke`** — Logs a device out. Request
`{ "id" }` or `{ "kid" }`. Marks the key revoked, ends its sessions,
and retires the certs attached under it (§5.5) — and, for records
older than the link, the certs on any holder those carry — so a device
that is signed out can neither manage the account nor sign in at a
site with the certs it holds. Response `200 { "unrevocable": [ "<issuer
domain>", … ] }`, the issuers whose bits it could not set (as
`holders/forget`); the wallet MUST revoke there. A second revoke is a
no-op `200`. The device's next `stored_key` login answers
`login_required` (§4.2); passing the page re-enrols the key, but the
retired certs stay retired — the device signs in at its issuers again.

#### 5.2.4 Attach — `POST /api/v1/account/attach`

Records device certs for one identity on the session's account, and
is the only way a key becomes recorded.

| Field | Meaning |
|---|---|
| `Proof` header | REQUIRED. Signed by the session's login key (§4.4). |
| `identity` | REQUIRED. The identity this call concerns. |
| `certs` | REQUIRED, 1–2 entries. `[{ "cert": "<JWS>", "proof": "<JWS>" }]`: the identity's auth cert, config cert, or both, each with a possession proof (§4.4) signed by its own key; every cert MUST name `identity` and both MUST carry one holder (`422 invalid_cert/holder_mismatch`). A cert naming further identities is recorded for those only where they are already on the account and its issuer is accepted for them; a bare `*` glob is refused (`422 invalid_cert/glob_identity`). |
| `confirm_takeover` | OPTIONAL, default `false`. The user's explicit choice to take the identity away from the account that holds it. |

Checks, in order: every cert against the validity bar
(`422 invalid_cert/<reason>`) and the holder rule; a key already
retired here (`422 invalid_cert/cert_revoked` — a retired record is
never revived); then the case. Where a case needs them, freshness
(`422 invalid_cert/cert_not_fresh`) is checked before anything is
filed.

- *Active on this account* → recorded. Idempotent on pubkey; a
  re-attached cert keeps its record and holder label.
- *Suspended on this account* → **restored** (§4.1): the identity
  leaves wherever it is active and returns. Fresh certs required.
- *Held by no account* → joins; a config cert among the carried
  certs (`config_required`). Fresh certs required.
- *Held by another account* → **transferred**: leaves there (§4.1) and
  joins here; a carried config cert, with `confirm_takeover`, else
  `409 conflict/identity_held`. Fresh certs required.

Response `200 { "recorded": [ <cert ids> ] }`. The session is
unchanged. Each cert is recorded under the session's login key — that
is what makes them one device (§2) — and the certs' holder lands on
the key when it has none yet (§4.2).

#### 5.2.5 Detach — `POST /api/v1/account/detach`

Removes an identity from the account. Request: `{ "identity": "…" }`;
`identity` MUST be active on the account (`404 not_found`).
Effects: those of an identity leaving an account (§4.1).
Response `204`. The last identity cannot be detached
(`409 conflict/last_identity`): use `delete`. Derived agent identities
go with their parent, never a refusal.

#### 5.2.6 Delete — `POST /api/v1/account/delete`

Deletes the account at this registry: every identity leaves (§4.1,
records on hold), and the account is dropped after the hold. Request
`{}`. Response `204`. Status bits already set stay set
forever; indexes are never reused (§8). This is the ability to leave a
registry; it does not touch the identities at their issuers. Exporting
warrants and holders for use at another registry is a v2 concern.

### 5.3 Consent inbox

Where agent requests wait for the user's decision. A requester (an
agent, a site, a page) files a request through the core §7.5 lanes;
the wallet lists it here, shows it to the user, signs the warrants,
and answers.

**`GET /api/v1/requests`** — Lists the account's open requests and
notices.

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
- `"notice"` — the registry tells the user an identity changed
  hands (§4.1); nothing to answer.

Which fields an item carries depends on its kind; a ✓ below means
present:

| Field | agent | connection | authoring | notice |
|---|---|---|---|---|
| `code` — the capability code | ✓ | ✓ | ✓ | ✓ |
| `grantor` — the identity to sign as; `"*"` lets the approver choose | ✓ | ✓ | ✓ | |
| `grantee` — the agent identity asking | ✓ | | ✓ | |
| `holder` — the holder id the grant binds to | ✓ | | ✓ | |
| `grants` — `[{ audience, scopes, status_idx?, grantee? }]`, one warrant per entry, in order; `grantee` absent means the request's | ✓ | ✓ | ✓ | |
| `label`, `display_name?`, `message?`, `client_host?`, `client_name?`, `agent_created_at?`, `known` (the grantee already holds a warrant here) | ✓ | ✓ | ✓ | |
| `binding_id` — the connection's broker-minted binding (core §7.5) | | ✓ | | |
| `notice` — `{ identity, reason, at }`; `reason` `"left"` (transferred, taken over, or detached) or `"returned"`; no response, expires after the hold | | | | ✓ |
| `external`, `created_at`, `expires_at` | ✓ | ✓ | ✓ | ✓ |

`expires_at` mirrors the filing lane's `expires_in` (core §7.5). A
wallet SHOULD render a request from a grantee it has never met
deny-first.

**`POST /api/v1/requests/claim`** — Claims a pending agent,
connection, or authoring request and allocates a status index into
each of its grants that lacks one, so every warrant the wallet signs
carries a ref (core §5). Request: `{ "code": … }`. Response `200`: the
request item as `GET requests` shows it. The request's
core §7.5 audience proof MUST validate at claim time (a fresh fetch is
RECOMMENDED); otherwise `422 invalid_warrant/audience_unproven`.
Idempotent per account; a code that is unknown, expired, or claimed by
another account answers `404 not_found`.

**`POST /api/v1/requests/respond`** — Approves or denies a request.

| Field | Meaning |
|---|---|
| `code` | REQUIRED. Unknown, expired, already answered, or a notice ⇒ `404 not_found`. |
| `approve` | REQUIRED. When `false`, the other fields are ignored. |
| `warrants` | On approve: `["<JWS>", …]`, one client-signed warrant per grant, in order; all or nothing (`422 invalid_warrant/warrant_count_mismatch`). |
| `config_cert` | On approve: the config cert whose key signed them. MUST be an unretired cert of the account (`422 invalid_warrant/config_cert_not_recorded`). |
| `grantor` | OPTIONAL, default the request's `grantor`. Must equal it when pinned (`grantor_pinned_mismatch`); when the pin is `"*"`, any active identity on the account the `config_cert` authorizes. |

Validation follows §7.1's `invalid_warrant` reasons
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
revocation bits on the registry's status list. Every record carries a
status ref this registry allocated, so every record is revocable
here. A revoke is reflected in the published list within the list's
own cache lifetime; `revoked` in `GET warrants` reflects the
registry's state at once and MAY lead the list. Records are keyed by
`(account, grantor, grantee, audience, scopes-as-set)`. A registry
MAY drop records whose warrants have expired.

**`GET /api/v1/warrants`** — Lists the account's registered warrants.
Each item: `id`, `grantor`, `grantee`, `audience`, `scopes`,
`warrant` (JWS), `status` (`{ uri, idx }`), `revoked` (the bit),
`holder?` (matcher string), `config_cert?` (JWS), `binding_id?`,
`client_host?`, `client_name?`, `requester_origin?`, `signed_at`,
`expires_at`. Records of a suspended identity (§4.1) are listed with
`revoked: true`.

**`POST /api/v1/warrants/register`** — Records a warrant the wallet
signed outside the inbox flow (for example a login warrant). Request:
`{ "warrant": "<JWS>", "config_cert": "<JWS>" }`. Response `200`:
`{ "id" }`. The warrant MUST verify against the
config-cert key; the cert MUST be `purpose: authorization`, authorize
the grantor, and be an unretired cert of the account; the grantor
MUST be an active account identity; the warrant's `status` MUST be
the ref `allocate_status` holds for the record key
(`status_ref_mismatch`) — `422 invalid_warrant/<reason>` per §7.1.
Registering never clears a set bit: a revoked warrant stays revoked,
and re-registering the same record replaces its `warrant`,
`signed_at`, and `expires_at`.

**`POST /api/v1/warrants/revoke`** — Revokes a warrant by setting its
status bit; sticky; a second revoke is a `204`. Request:
`{ "id": 42 }`. Response `204`. After a revoke, the record's key
allocates a fresh index on the next `allocate_status` or `claim`, so a
later grant to the same agent never revives the old bytes.

**`POST /api/v1/warrants/allocate_status`** — Allocates a status ref
before the wallet signs, so login warrants carry per-site revocation
bits. Request: `{ "grantee", "audience", "scopes" }` (`grantee` is the
identity that will present the warrant; for a login warrant, the
wallet's own). Response `200`: `{ "uri", "idx" }`, stable
for the record key until that record is revoked. An index once
allocated is never reused for the lifetime of the list URI (§8).

### 5.5 Certs

The certs recorded on the account, one record per cert. Certs are
recorded by `attach` (§5.2); there is no separate recording call.
Retired certs stay listed.

**`GET /api/v1/certs`** — Lists the account's recorded certs: `id`,
`kid`, `identities` (those it was recorded for), `purpose`, `holder`,
`login_key` (the key it was attached under, `null` for issuer- or
agent-recorded rows), `pubkey`, `iss`, `issued_at`, `expires_at`,
`revoked` (retired here, or the issuer's bit where this registry reads
it), `status?` (`{ uri, idx }`).

**`POST /api/v1/certs/revoke`** — Revokes a cert. Request:
`{ "id": 7 }` or `{ "kid": "…" }` (not both). Response `200`:
`{ "revoked": bool }`. When this registry is the cert's
revocation authority (`iss` is its domain) it sets the bit, sticky,
and answers `true`. Either way the cert is **retired** here: excluded
from holder matching and never recorded again. For a foreign issuer the registry cannot set
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
`identities`.

**`POST /api/v1/holders/rename`** — Relabels a holder. Request:
`{ "holder_id", "label" }`. Response `204`.

**`POST /api/v1/holders/forget`** — Retires a holder's certs (setting
bits where it can), revokes the login keys those certs were attached
under or that recorded this holder (§5.2.3), then deletes it: the way
to remove an agent or service, or a device by its holder. Request: `{ "holder_id" }`. Response `200`:
`{ "unrevocable": [ "<issuer domain>", … ] }`, the issuers whose bits
it could not set; the wallet MUST revoke there. Refused for external
holders (`409 conflict/external_holder`).

**`POST /api/v1/namespaces/rename`** — Relabels a namespace. Request:
`{ "name", "label" }`. Response `204`.

Labels per §3. Holders are addressable only when on the account
(`404 not_found`, no existence leaks).

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
| 401 | `invalid_session` | Token missing, unknown, expired, or ended; its login key expired or revoked; the `Proof` key is not the session's key. Carries `WWW-Authenticate: Bearer`. |
| 422 | `invalid_cert` | A carried cert fails the validity bar or a membership rule (`accounts`, `accounts/lookup`, `attach`). |
| 401 | `invalid_proof` | A request or possession proof fails, on any call: missing, wrong `typ`, bad signature, `htm`/`htu` mismatch, stale `iat`, replayed `jti`, `bh` mismatch, or proofs in one request with differing `jti`. |
| 403 | `forbidden` | A login is needed or rejected (§7.1). |
| 404 | `not_found` | Owner-scoped lookup misses — including "exists but isn't yours" — and requests that are unknown, expired, or answered. |
| 409 | `conflict` | State refusals. |
| 422 | `invalid_warrant` | Respond, claim, register: client-signed warrants (or the claim precondition) fail the §5.3/§5.4 bar. |
| 429 | `slow_down` | Rate limits; SHOULD carry `Retry-After`. |

`error_description` is diagnostic and MUST NOT be parsed; machine
reasons ride the OPTIONAL `reason` field, and a reason MAY define
further top-level fields (`login_required` does, §4.2). When a token
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
| `config_cert_not_recorded` | Not an unretired cert of the account (§5.3, §5.4). |
| `grantor_not_authorized` | Config cert was not recorded for the grantor. |
| `grantor_not_owned` | Grantor is not an active account identity (§4.1). |
| `grantor_pinned_mismatch` | Differs from the request's pinned grantor. |
| `warrant_invalid` | Warrant fails to parse or verify against the config-cert key. |
| `audience_mismatch` / `grantor_mismatch` / `grantee_mismatch` | Warrant claim differs from grant/request. |
| `not_self_grant` / `binding_mismatch` | Connection record is not a self-grant, or does not embed the request's `binding_id` (§5.3). |
| `not_holder_bound` | No holder matcher where one is required. |
| `wildcard_holder` | Bare `*` matcher. |
| `holder_mismatch` | Matcher does not match the grantee's holder. |
| `status_ref_missing` / `status_ref_mismatch` | The warrant's `status` is absent, or differs from the ref this registry allocated for the grant or record key (§5.4). |
| `audience_unproven` | Claim: the core §7.5 audience proof does not validate. |

With `forbidden` (`403`):

| Reason | Meaning |
|---|---|
| `login_required` | The registry will not open a session headlessly: `login_page` without a token, or `stored_key` with a key that is unknown, expired, or revoked (§4.2); body carries `url`. |
| `login_rejected` | `login_page` with a bad or spent token, or the page refused (§4.2). |

With `invalid_cert` — the **validity bar** (`422`), in check order:

| Reason | Meaning |
|---|---|
| `cert_malformed` | Fails to parse as a device cert. |
| `wrong_purpose` | Purpose is neither `authentication` nor `authorization`. |
| `cert_expired` | Past `exp`. |
| `issuer_not_accepted` | For any identity the cert is recorded for: the issuer is neither that domain's DNSSEC-published IdP nor in the registry operator's accepted-fallback set (core §8.1; default: the registry's own domain). |
| `signature_invalid` | Does not verify under the resolved issuer key. |
| `cert_revoked` | The cert carries a status ref and it checks revoked or cannot be fetched (fail-closed), or the key was retired here; a cert with no ref passes. |

And the **membership rules** (`422`, `accounts` and `attach`):

| Reason | Meaning |
|---|---|
| `cert_not_fresh` | A cert creating an account or moving an identity was issued more than 300 s ago (§5.2.1, §5.2.4). |
| `config_required` | Creating an account, or moving an identity, with no config cert (§5.2.1, §5.2.4). |
| `glob_identity` | The cert's `identities` contain a bare `*` (§5.2.4). |
| `holder_mismatch` | The two certs carry different holders (§5.2.4). |

With `conflict` (`409`):

| Reason | Meaning |
|---|---|
| `external_holder` | `holders/forget` on another account's admitted holder (§5.6). |
| `identity_held` | `accounts` or a transferring `attach` for an identity another account holds, without `confirm_takeover` (§5.2.1, §5.2.4). |
| `last_identity` | Detaching the only identity (§5.2.5). |

## 8. Versioning and conformance

`/api/v1/` is the compatibility contract: additive changes only;
breaking changes get `/api/v2/`. The proof `typ` is versioned
independently, rejected fail-closed on mismatch. Beyond the rules of
§4 and §5, a conformant registry upholds:

1. No anonymous operations. Discovery (§5.1) is public; every other
   call is proven by a device-cert key, mutations signed down to their
   body bytes.
2. Login is the account's boundary. A key joins an account only under
   a session on it, and only a login opens one; from outside an account
   nothing is observable but that an address is in use. Whoever takes
   an identity inherits nothing.
3. The registry never signs or alters warrants; approval carries
   warrants signed by the account's config-cert key.
4. DNSSEC is the sole root of trust for identity keys; no Web-PKI path
   to a key.
5. A status index, once allocated, is never reused for the lifetime of
   its list URI; bits of dropped records stay set.
