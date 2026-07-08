# BrowserID Agent Provisioning & Grant Exchange — REST API Specification

**Version:** 0.1 (draft)
**Date:** 2026-07-08
**Status:** Published for federation (l8lw Phase 3). The `browserid-ng` broker
(with `AGENT_PROVISIONING=1`) is the reference implementation; the
`browserid-agent` and `browserid-rp` crates are reference clients for the two
sides.

## 1. Purpose and scope

This document specifies the two HTTP surfaces that make BrowserID usable by
software agents without a browser:

1. **Provisioning API** (§4) — how an agent holding an **API key** obtains and
   renews a certified identity from an IdP. Any BrowserID IdP may implement
   this; nothing in it is specific to one deployment.
2. **Grant exchange** (§5) — how an agent authenticates to an API relying
   party by swapping an ordinary backed assertion for the RP's own bearer
   token, including in-band (`WWW-Authenticate`) and out-of-band (RFC 8414)
   discovery.

Everything between those two surfaces is standard BrowserID: the certificate,
the assertion, and chain verification are unchanged, and an RP cannot tell an
agent-held identity from any other. **Agent-ness is issuer-side metadata,
never a protocol-visible type.** This spec deliberately does not define an
`agent.*` identity syntax, a delegation claim, or RP-visible scopes.

Out of scope: how a human obtains an API key from their IdP (IdP-local
policy, §4.1), browser session establishment at RPs, and escrow/stake trust
models.

## 2. Terminology

- **IdP** — a BrowserID identity provider implementing the provisioning API.
  It is authoritative for identities under its own domain.
- **Agent** — a headless client that generates and holds its own keypair.
- **API key** — a long-lived bearer secret, minted by an authenticated human
  at the IdP, that authorizes certificate minting for agent identities on
  that human's account. Wire format: the opaque string SHOULD begin with
  `bidk_` so leaked keys are greppable by secret scanners.
- **Attribution root** (`parent_email`) — the human identity an agent
  identity chains to. Every agent identity MUST have one.
- **Agent identity** — an email-shaped identity `<name>@<idp-domain>` whose
  certificates are minted via the provisioning API.
- **Backed assertion** — standard BrowserID `cert~assertion`.
- **RP** — an HTTP API accepting BrowserID via grant exchange (§5).

Key words MUST/SHOULD/MAY are RFC 2119.

## 3. Trust model (normative summary)

- **Attribution replaces inbox friction.** Headless issuance removes SMTP
  verification as the identity-creation rate limit, so IdPs MUST enforce a
  per-account quota of active agent identities (reference default: 5) and
  SHOULD rate-limit provisioning per API key.
- **The API key is the standing credential.** The agent keypair MAY rotate at
  any re-mint; possession of a valid API key is what authorizes minting.
  IdPs MUST store only a digest of the key (reference: SHA-256) and MUST
  return the secret exactly once at mint time.
- **Revocation is soft.** Revoking a key or identity stops future mints;
  outstanding certificates age out within their TTL. Certificate lifetime
  MUST therefore be short (reference: 24 h, 1 h ephemeral). Hard revocation
  (verifier-consulted lists) is a future extension.
- **Scope of an API key.** A key MUST only authorize operations on *agent*
  identities of its own account. It MUST NOT read account data, alter
  credentials, or mint certificates for the account's human identities.
  A leaked key's blast radius is impersonating that account's agents until
  revocation + TTL.
- **Domain-level governance.** Operators MAY run a dedicated agent IdP
  domain (e.g. `agents.example.com`) to rate-limit, monitor, or apply policy
  to an entire agent population, and RPs MAY apply per-issuer-domain policy.
  Once federated, agent identities are NOT guaranteed to be identifiable by
  domain — RP-side agent detection is explicitly a non-goal.

## 4. Provisioning API

All endpoints are rooted at the IdP origin. Authentication for every endpoint
in this section: `Authorization: Bearer <api-key>`. Requests and responses
are JSON (`Content-Type: application/json`). Every success response includes
`"success": true`; every error body includes `"success": false` and a
`"reason"` string.

Common error status codes:

| Status | Meaning |
|---|---|
| 401 | Missing, malformed, unknown, or revoked API key |
| 403 | Identity exists but is revoked (re-mint/re-create refused) |
| 404 | Identity unknown, not owned by this account, not an agent identity — or the IdP has provisioning disabled. The three cases MUST be indistinguishable. |
| 409 | Requested name is taken by another account |
| 429 | Per-account quota (or rate limit) exceeded |

### 4.1 API key issuance (non-normative)

How a human mints, lists, and revokes API keys is IdP-local (the reference
implementation uses session+CSRF-gated `/wsapi/agent_keys*` endpoints and a
browser UI). Interoperability only requires that the resulting secret works
as the Bearer credential below, that it is shown once, and that each key
records an attribution root chosen from the account's verified human
identities. An agent identity MUST NOT be an attribution root.

### 4.2 `POST /agent/identities` — mint an identity

Request:

```json
{
  "pubkey": { "algorithm": "Ed25519", "publicKey": "<base64url raw key>" },
  "name": "attestor"          // optional; server generates when omitted
}
```

- `name` is the local-part: 1–32 characters of `[a-z0-9-]`, no leading or
  trailing `-`. Servers MUST lowercase before validating and MUST validate.
- The minted identity is `<name>@<idp-domain>`, where `<idp-domain>` is
  exactly the certificate issuer domain (chain verification requires
  issuer == email domain).
- The server binds the identity to the key's account, records the key's
  attribution root as its parent, marks it verified, and returns a
  certificate for the presented pubkey.
- **Idempotent re-provision:** if `name` already exists on the same account
  as an active agent identity, the server MUST treat the call as a re-mint
  for the presented pubkey (agents restart; they must not need
  create-vs-renew logic). If it exists but is revoked → 403. If another
  account owns it → 409.
- Quota: creating a *new* identity when the account already has ≥ quota
  active agent identities → 429.

Response:

```json
{ "success": true, "email": "attestor@agents.example.com", "cert": "<JWS>" }
```

### 4.3 `POST /agent/cert` — re-mint a certificate

Request:

```json
{
  "email": "attestor@agents.example.com",
  "pubkey": { "algorithm": "Ed25519", "publicKey": "<base64url raw key>" },
  "ephemeral": false           // optional; true → short-lived cert
}
```

The presented pubkey is what gets certified — keypair rotation is free. The
identity MUST be an active agent identity of the key's account (else 404 per
the visibility rule, or 403 if revoked). Certificate validity: reference
24 h normal, 1 h ephemeral; implementations SHOULD NOT exceed 24 h.

Because the standing credential is re-checked live at every mint, agent
identities are exempt from any staleness window an IdP applies to
SMTP-verified emails.

Response: `{ "success": true, "cert": "<JWS>" }`

### 4.4 `GET /agent/identities` — list

Returns all agent identities of the key's account:

```json
{
  "success": true,
  "identities": [
    {
      "email": "attestor@agents.example.com",
      "parent_email": "human@example.com",
      "active": true,
      "verified_at": "2026-07-08T19:05:30Z"
    }
  ]
}
```

### 4.5 `POST /agent/identities/revoke` — revoke an identity

Request: `{ "email": "attestor@agents.example.com" }` →
`{ "success": true }`.

After revocation, re-mints and re-creates of that name on this account MUST
fail (403); the name MUST NOT be silently revivable. Outstanding certificates
age out within their TTL.

## 5. Grant exchange (RP side)

An RP opts in with one endpoint: exchange a verified assertion for the RP's
own bearer token (RFC 7521 assertion-grant shape). The RP's session machinery
past that point is untouched, and the RP learns exactly what BrowserID always
tells it: an email.

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

- `audience` (REQUIRED) — the exact audience assertions must be signed for.
  The RP names it; agents MUST NOT guess. SHOULD be the API origin, MAY be a
  stable logical identifier.
- `token_endpoint` (REQUIRED) — absolute URL of the exchange endpoint.
- `realm` (OPTIONAL). Unknown parameters MUST be ignored.

### 5.3 Token endpoint

`POST <token_endpoint>` with `application/x-www-form-urlencoded`:

```
grant_type=urn:x-browserid:grant-type:assertion
assertion=<backed assertion (cert~assertion)>
```

The RP MUST verify: assertion audience equals its advertised audience;
assertion and certificate are unexpired and correctly signed; the certificate
issuer equals the identity's domain; and the issuer is one the RP trusts
(pinned key, or fetched from the issuer's `/.well-known/browserid`).

Success — `200`, OAuth-shaped:

```json
{ "access_token": "…", "token_type": "Bearer", "expires_in": 3600, "email": "…" }
```

(`email` is an optional extra member.) Failure — `400` with
`{ "error": "unsupported_grant_type" | "invalid_grant", "error_description": "…" }`.

### 5.4 Out-of-band discovery: RFC 8414

RPs SHOULD additionally serve `/.well-known/oauth-authorization-server`:

```json
{
  "issuer": "https://api.example.com",
  "token_endpoint": "https://api.example.com/token",
  "grant_types_supported": ["urn:x-browserid:grant-type:assertion"],
  "token_endpoint_auth_methods_supported": ["none"],
  "response_types_supported": []
}
```

No new `.well-known` name is defined. (The IdP-side
`/.well-known/browserid` is a different, pre-existing document.)

## 6. Security considerations

- **Transport:** every endpoint in this spec MUST be served over HTTPS in
  production; API keys and assertions are bearer material.
- **Key storage:** IdPs MUST NOT store API-key secrets recoverably. A plain
  cryptographic digest is sufficient — the secret is high-entropy, so a slow
  KDF adds nothing.
- **Enumeration:** the 404 visibility rule (§4) prevents an API key from
  probing whether an email exists outside its own agent namespace.
- **Assertion lifetime at the token endpoint:** assertions are short-lived
  by construction; RPs MAY additionally replay-protect the token endpoint
  but the exchanged token's own lifetime is the primary control.
- **Attribution chains:** an agent identity MUST NOT serve as an attribution
  root, preventing unattributable agent→agent trees from one leaked key.

## 7. Conformance

An **IdP** conforms if it implements §4.2–§4.5 with the §3 requirements. An
**RP** conforms if it implements §5.2–§5.3 (§5.4 recommended). Reference
implementations in this repository:

| Role | Reference |
|---|---|
| IdP | `browserid-broker` with `AGENT_PROVISIONING=1` (`src/routes/agent.rs`) |
| Agent | `browserid-agent` crate (`provision`, `assertion_for`, `token_for`) |
| RP | `browserid-rp` crate (`Verifier`, `exchange`, `oauth_metadata`) + the axum reference in `browserid-agent/tests/rp_flow_test.rs` |
| Wire contract | `browserid-core::rp_auth` |

Design rationale: `docs/plans/2026-07-08-agent-native-browserid-design.md`.
