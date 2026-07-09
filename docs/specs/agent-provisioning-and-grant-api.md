# BrowserID Agent Provisioning & Grant Exchange — REST API Specification

**Version:** 0.2 (draft)
**Date:** 2026-07-09
**Status:** Published for federation. v0.2 replaces v0.1's bearer API keys
with a user-signed **delegation chain** plus per-request **broker
endorsement** (design: `docs/plans/2026-07-09-agent-delegation-chain-design.md`).
The `browserid-ng` broker is the reference implementation; `browserid-agent`
and `browserid-rp` are reference clients for the two sides.

## 1. Purpose and scope

This document specifies the HTTP surfaces that make BrowserID usable by
software agents without a browser:

1. **Provisioning protocol** (§4) — how an agent holding a **provisioning
   credential** (a private key whose public half was delegated by a user's
   certified identity key) obtains and renews a certified identity from an
   IdP, with a broker co-signing each request per policy.
2. **Grant exchange** (§5) — how an agent authenticates to an API relying
   party by swapping an ordinary backed assertion for the RP's own bearer
   token, including in-band (`WWW-Authenticate`) and out-of-band (RFC 8414)
   discovery.

Everything downstream of provisioning is standard BrowserID: the agent's
certificate, assertions, and chain verification are unchanged, and an RP
cannot tell an agent-held identity from any other. **Agent-ness is
issuer-side metadata, never a protocol-visible type.**

Out of scope: browser session establishment at RPs, and escrow/stake trust
models. The broker's key-management UI is described non-normatively (§4.6).

## 2. Terminology

- **IdP** — a BrowserID identity provider implementing §4. It is
  authoritative for identities under its own domain.
- **Broker** — a fallback IdP (e.g. browserid.me) that additionally
  registers provisioning certificates, applies account-level policy, and
  endorses provisioning requests. A broker is also an IdP for its own
  domain.
- **Agent** — a headless client holding the provisioning private key and its
  own (separate) identity keypair.
- **Delegator / parent identity** — the user identity (`a@b.c`) whose
  certified key signed the delegation. Every agent identity MUST chain to
  one.
- **U_cert** — the delegator's ordinary identity certificate (IdP-signed,
  binds `U_pub` to `a@b.c`).
- **P_cert** — the provisioning certificate: signed by `U_priv`, binds the
  provisioning public key `P_pub` to the delegation.
- **Delegation bundle** — `U_cert~P_cert` (the `~` framing of backed
  assertions).
- **Request bundle** — `U_cert~P_cert~R` where `R` is a provisioning
  request signed by `P_priv`.
- **Endorsement (E)** — the broker's short-lived signature over a specific
  request bundle.
- **Agent identity** — `<name>@<idp-domain>`, certified by the IdP for the
  agent's own key `A_pub`.

Key words MUST/SHOULD/MAY are RFC 2119.

## 3. Trust model (normative summary)

- **Authorization is user-signed.** An IdP MUST NOT mint an agent identity
  without a valid chain terminating in a `P_cert` signed by the delegator's
  certified key. A broker endorsement alone authorizes nothing.
- **Policy is broker-signed.** An IdP MUST also require a fresh endorsement
  from a broker it explicitly trusts (its *accepted brokers* set is local
  configuration). The endorsement states the request is within account-level
  policy (sybil/quota/rate), which only the broker can see globally.
- **Identity-domain rule.** The agent's identity domain is the domain of the
  IdP that roots the delegator's identity. Consequently the `U_cert` an IdP
  verifies is always its own issuance, and for delegators rooted at the
  broker itself, endorser and issuer are the same party (one code path, two
  roles).
- **Signing-time semantics.** `U_cert` is short-lived; `P_cert` is
  long-lived. Verifiers MUST require `P_cert.iat` to fall within `U_cert`'s
  validity window and MUST NOT require `U_cert` to be currently unexpired.
  An IdP MAY additionally consult its own issuance records for `U_pub`.
- **Revocation is endorsement-gated.** Every mint — including routine
  re-mints — requires a fresh endorsement, and agent certificates MUST be
  short-lived (reference: 24 h, 1 h ephemeral). Revoking a provisioning
  certificate at the broker therefore takes effect within one certificate
  TTL. IdPs MAY additionally revoke identities locally (§4.5).
- **Scope of the provisioning credential.** A request bundle MUST only
  enable operations on *agent* identities delegated by its own chain. It
  MUST NOT permit reading account data, altering credentials, or acting on
  the delegator's (or anyone's) human identities. `P_priv` never transits
  the wire; only signatures do.
- **Quota is layered.** The broker enforces account-global policy at
  endorsement time; IdPs SHOULD additionally enforce a per-delegator quota
  of active agent identities (reference default: 5).

## 4. Provisioning protocol

### 4.1 Claim formats

All three are Ed25519 JWS with an explicit `typ` claim for domain
separation. Verifiers MUST reject a token whose `typ` does not match the
expected value. None of these shapes is parseable as an identity certificate
(no `principal`) or an assertion (no `aud` on `P_cert`/`R`).

**Provisioning certificate (`P_cert`)** — signed by the delegator's identity
key:

```json
{
  "typ": "browserid-provisioning-cert-v1",
  "iss": "a@b.c",
  "iat": 1783600000,
  "exp": 1791376000,
  "public-key": { "algorithm": "Ed25519", "publicKey": "<P_pub base64url>" }
}
```

`iss` MUST equal the `principal.email` of the accompanying `U_cert`.
Reference validity: 90 days.

**Provisioning request (`R`)** — signed by `P_priv`:

```json
{
  "typ": "browserid-provisioning-request-v1",
  "iat": 1783600000,
  "exp": 1783600600,
  "action": "mint",
  "domain": "mingo.place",
  "name": "attestor2",
  "agent-key": { "algorithm": "Ed25519", "publicKey": "<A_pub base64url>" },
  "ephemeral": false
}
```

- `action` ∈ `mint` | `list` | `revoke`. `name` is required for
  `mint`/`revoke`; `agent-key` (and optional `ephemeral`) for `mint`.
- `domain` MUST equal the target IdP's domain (audience pinning).
- Requests MUST be short-lived (≤ 10 min recommended).

**Endorsement (`E`)** — signed by the broker's published key:

```json
{
  "typ": "browserid-provisioning-endorsement-v1",
  "iss": "browserid.me",
  "aud": "mingo.place",
  "sub": "sha256:<hex of the exact request-bundle string>",
  "delegator": "a@b.c",
  "iat": 1783600000,
  "exp": 1783600600
}
```

`sub` binds the endorsement to one specific request bundle. `delegator` is
the identity the broker verified from the chain. Endorsements MUST be
short-lived (≤ 10 min recommended).

### 4.2 Broker: `POST /provision/endorse`

Request: `{ "request_bundle": "<U_cert~P_cert~R>" }`. No other
authentication — the bundle is the credential.

The broker MUST: verify the request signature (`R` under `P_cert`'s key) and
that the request is unexpired; require the `P_cert` to be **registered and
unrevoked** in its registry (§4.6) — the registry established the
`U_cert`→`P_cert` delegation at registration time, so the broker need not
re-verify `U_cert` here; apply account-level policy; then return
`200 { "success": true, "endorsement": "<E JWS>" }` with `aud` = `R.domain`.
(The user-signed authorization is still verified end to end — the target IdP
verifies the whole chain at mint, §4.3 — so a broker endorsement never
substitutes for it.)

Errors (shape `{"success": false, "reason": "…"}`):

| Status | Meaning |
|---|---|
| 400 | Malformed bundle / bad chain / expired request |
| 403 | Chain valid but not registered, revoked, or refused by policy |
| 429 | Endorsement rate limit |

### 4.3 IdP: `POST /provision/mint`

Request:

```json
{ "request_bundle": "<U_cert~P_cert~R with action=mint>",
  "endorsement": "<E JWS>" }
```

The IdP MUST verify, in addition to §3's chain rules: `R.domain` and
`E.aud` equal its own domain; `E` is signed by an accepted broker, fresh,
and `E.sub` matches the hash of the exact `request_bundle` string; the
`U_cert` is its own issuance for the delegator.

Semantics (unchanged from v0.1): names share one `<local>@<domain>`
namespace with human identities and MUST be validated (including any
reserved-name policy); minting is **idempotent** for an existing active
identity of the same delegator (returns a fresh certificate for the
presented `agent-key`, which MAY rotate freely); revoked names are never
recycled; new identities count against the delegator's quota.

Response: `{ "success": true, "email": "attestor2@mingo.place",
"cert": "<JWS>" }`.

| Status | Meaning |
|---|---|
| 400 | Malformed / bad chain / bad `typ` / expired |
| 401 | Chain verifies but endorsement missing, stale, wrong `aud`, hash mismatch, or from an unaccepted broker |
| 403 | Identity exists but is revoked |
| 404 | Provisioning disabled (indistinguishable from unknown routes) |
| 409 | Name taken by another delegator or a human identity |
| 429 | Per-delegator quota exceeded |

### 4.4 IdP: `POST /provision/list`

`{ "request_bundle": "<… action=list>", "endorsement": "<E>" }` → the
delegator's agent identities:

```json
{ "success": true, "identities": [
  { "email": "attestor2@mingo.place", "parent_email": "a@b.c",
    "active": true, "created_at": "2026-07-09T…Z" } ] }
```

Visibility rule: a request chain only ever sees identities delegated by its
own delegator; everything else — including human identities — is
indistinguishable from nonexistent (404 on §4.5, absent here).

### 4.5 IdP: `POST /provision/revoke`

`{ "request_bundle": "<… action=revoke, name=…>", "endorsement": "<E>" }` →
`{ "success": true }`. Disables the identity: further mints fail (403), the
name is never recycled, outstanding certificates age out within their TTL.

### 4.6 Broker registry & key management (non-normative)

How a user creates and manages provisioning certificates is broker-local.
The reference broker: a signed-in user picks an identity; the page generates
the P keypair locally, signs `P_cert` with the identity key held in
broker-origin storage (a typed-signing operation), registers
`{delegation bundle, label}` with the account (session + CSRF), and receives
the **agent credential** exactly once:

```json
{ "secret_key": "<P_priv base64url>",
  "delegation": "<U_cert~P_cert>",
  "broker": "https://browserid.me",
  "idp": "https://mingo.place" }
```

`P_priv` is never sent to any server. The registry stores only public data;
listing shows label, delegator, creation and last-endorsed times; revocation
flips one row and starves future endorsements. Interoperability requires
only that the resulting delegation verifies per §4.1 and that the broker
endorses per §4.2.

## 5. Grant exchange (RP side)

*(Unchanged from v0.1.)*

An RP opts in with one endpoint: exchange a verified assertion for the RP's
own bearer token (RFC 7521 assertion-grant shape). The RP learns exactly
what BrowserID always tells it: an email.

### 5.1 Grant type

```
urn:x-browserid:grant-type:assertion
```

### 5.2 In-band discovery: `WWW-Authenticate` challenge

An unauthenticated request to a protected resource MUST receive `401` with:

```
WWW-Authenticate: BrowserID realm="api",
    audience="https://api.example.com",
    token_endpoint="https://api.example.com/token"
```

`audience` (REQUIRED) — the exact audience assertions must be signed for;
the RP names it. `token_endpoint` (REQUIRED) — absolute URL. `realm`
OPTIONAL; unknown parameters MUST be ignored.

### 5.3 Token endpoint

`POST <token_endpoint>` with `application/x-www-form-urlencoded`:

```
grant_type=urn:x-browserid:grant-type:assertion
assertion=<backed assertion (cert~assertion)>
```

The RP MUST verify audience, expiry, the signature chain, issuer == identity
domain, and that the issuer is trusted (pinned key or fetched from
`/.well-known/browserid`). Success — `200`, OAuth-shaped:

```json
{ "access_token": "…", "token_type": "Bearer", "expires_in": 3600, "email": "…" }
```

Failure — `400` with `{ "error": "unsupported_grant_type" | "invalid_grant",
"error_description": "…" }`.

### 5.4 Out-of-band discovery: RFC 8414

RPs SHOULD serve `/.well-known/oauth-authorization-server`:

```json
{
  "issuer": "https://api.example.com",
  "token_endpoint": "https://api.example.com/token",
  "grant_types_supported": ["urn:x-browserid:grant-type:assertion"],
  "token_endpoint_auth_methods_supported": ["none"],
  "response_types_supported": []
}
```

## 6. Security considerations

- **Transport:** all endpoints MUST be HTTPS in production.
- **Domain separation:** the three `typ` values in §4.1 MUST be enforced;
  `U_priv` signing a `P_cert` must never be replayable as a certificate or
  assertion (structurally guaranteed, belt-and-suspenders via `typ`).
- **`P_priv` leak:** the attacker can request endorsements until the user
  revokes; abuse is attributable to `P_pub` in broker logs (requests are
  signed, unlike bearer secrets). Blast radius stays confined to the
  delegator's *agent* identities.
- **Broker compromise:** can endorse rogue requests but cannot fabricate a
  user authorization — the IdP independently verifies the user-signed chain.
- **Audience pinning:** `R.domain` + `E.aud` make a bundle for one IdP
  useless at another; `E.sub` prevents endorsement reuse across requests.
- **Enumeration:** §4.4/§4.5 visibility rules prevent a provisioning
  credential from probing anything outside its own delegation.
- **Attribution chains:** an agent identity MUST NOT serve as a delegator
  (no unattributable agent→agent trees).

## 7. Conformance

An **IdP** conforms if it implements §4.3–§4.5 under §3's rules. A
**broker** conforms if it additionally implements §4.2 (+ a registry). An
**RP** conforms if it implements §5.2–§5.3 (§5.4 recommended). Reference
implementations in this repository and the mingo repository:

| Role | Reference |
|---|---|
| Broker + IdP | `browserid-broker` with `AGENT_PROVISIONING=1` |
| IdP (federated) | `mingo-idp` (mingo repo) |
| Agent | `browserid-agent` crate |
| RP | `browserid-rp` crate |
| Chain formats | `browserid-core::provisioning` |

Design rationale: `docs/plans/2026-07-09-agent-delegation-chain-design.md`
(v2), `docs/plans/2026-07-08-agent-native-browserid-design.md` (v1,
superseded in §4).
