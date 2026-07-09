# Design — Delegation-chain agent provisioning (v2)

**Date:** 2026-07-09
**Status:** Design agreed (2026-07-09 discussion); supersedes the bearer-key
scheme in `2026-07-08-agent-native-browserid-design.md` §"Provisioning flow"
**Bean:** `browserid-ng-tdxf` (upstream), `mingo-ua8w` (downstream rework)

## Why v2

The shipped v1 made API keys **IdP-local bearer secrets**: each IdP mints,
stores (hashed), and validates its own `bidk_` keys, so a user managing agents
across browserid.me and mingo.place has two dashboards, two revocation points,
and the broker is out of the loop for other IdPs' keys. v2 centralizes key
management at browserid.me **without** centralizing trust:

- **Authorization is user-signed, not broker-asserted.** The user's own
  certified identity key signs the delegation. The broker signs a *separate*
  policy claim. An IdP can archive the dual-signed request as durable proof of
  who authorized what.
- **Trust terminates at the parent identity's root IdP** — for a
  primary-rooted identity the primary IdP verifies its own issuance and mints;
  the broker cannot fabricate an authorization.
- **The secret never transits.** The "API key" is a private key; requests are
  signed. Nothing bearer-shaped rides in headers, and the broker never holds
  the secret (v1 stored a hash; v2 stores only the public half).
- **Sybil policy lives where the visibility is.** The broker sees the user
  across all their identities and endorses (or refuses) every provisioning
  request; per-IdP quotas remain as defense in depth.

## The chain

```
IdP key                  signs  user identity cert   U_cert:  U_pub ↔ a@b.c            (exists today)
user identity key U_priv signs  provisioning cert    P_cert:  P_pub, iss=a@b.c, exp    (NEW — the delegation)
provisioning key  P_priv signs  provisioning request R:       action, name, A_pub, …   (NEW — per operation)
broker key               signs  endorsement          E:       sha256(bundle), aud, exp (NEW — per operation)
target IdP verifies (U_cert, P_cert, R, E)  →  mints agent cert: A_pub ↔ name@idp-domain
```

The **delegation bundle** travels as `U_cert~P_cert` (same `~` framing as
backed assertions); a **request bundle** is `U_cert~P_cert~R`. `browserid-core`
already verifies multi-cert chains (`BackedAssertion::with_chain` walks
root-by-domain-key, then each cert by its predecessor's key); v2 adds the
typed claim structs and a dedicated verifier — it does NOT reuse the assertion
verifier, to keep domain separation strict.

### Claim formats (all Ed25519 JWS, like certs/assertions)

**Provisioning certificate** — signed by `U_priv`:

```json
{
  "typ": "browserid-provisioning-cert-v1",   // REQUIRED domain separator
  "iss": "a@b.c",                            // the delegating identity (email form)
  "iat": …, "exp": …,                        // long-lived (default 90 days)
  "public-key": { "algorithm": "Ed25519", "publicKey": "<P_pub>" }
}
```

Structurally unparseable as an identity cert (no `principal`, email-form
`iss`) or assertion (no `aud`), plus the explicit `typ` — `U_priv` signing
this can never be replayed as either.

**Provisioning request** — signed by `P_priv`, short-lived (10 min):

```json
{
  "typ": "browserid-provisioning-request-v1",
  "iat": …, "exp": …,
  "action": "mint" | "list" | "revoke",
  "domain": "mingo.place",                   // target IdP domain
  "name": "attestor2",                       // local part (mint/revoke)
  "agent-key": { "algorithm": "Ed25519", "publicKey": "<A_pub>" }   // mint only
}
```

**Endorsement** — signed by the broker key, short-lived (10 min):

```json
{
  "typ": "browserid-provisioning-endorsement-v1",
  "iss": "browserid.me",
  "aud": "mingo.place",                      // the target IdP
  "sub": "sha256:<hex of the full request bundle string>",
  "delegator": "a@b.c",                      // restated after chain verification
  "iat": …, "exp": …
}
```

The hash binding means the endorsement approves *exactly one* request — no
mix-and-match.

## Verification (target IdP, on every request)

1. `R` signature verifies under `P_cert`'s `public-key`; `R` unexpired;
   `R.domain` == my domain.
2. `P_cert` signature verifies under `U_cert`'s `public-key`; `typ` correct;
   unexpired; `P_cert.iss` == `U_cert.principal.email`.
3. `U_cert`: **the issuer is always me** (see "identity-domain rule" below),
   so I verify my own signature — no discovery. Signing-time semantics
   (decision 1): `U_cert` may be long-expired; what's required is
   `P_cert.iat` within `U_cert`'s validity window. An IdP MAY additionally
   check its own records ("did I certify U_pub for a@b.c").
4. `E`: signature verifies under a broker key I explicitly trust (decision 4:
   IdPs name their accepted broker(s); mingo-idp already has
   `broker_domain`); `aud` == my domain; `sub` matches
   `sha256(U_cert~P_cert~R)`; unexpired. Freshness of `E` is the revocation
   gate (decision 2): every mint — including every ~24 h re-mint — needs a
   fresh endorsement, so revocation at the broker takes effect within the
   agent-cert TTL.
5. Local policy: name validity/reservations, one `<local>@<domain>`
   namespace with human handles, revoked names never recycled, per-account
   quota (all v1 logic, kept).
6. Mint the agent cert for `agent-key` (24 h / 1 h ephemeral), record
   attribution `agent → a@b.c` (which itself chains onward via cm8z parent
   metadata, e.g. `dan@mingo.place → hello@sandmill.org`).

**Identity-domain rule:** the agent's identity domain = the domain of the IdP
that roots the parent identity. `dan@mingo.place` (primary-rooted) →
`attestor2@mingo.place`, minted by mingo-idp. `hello@sandmill.org`
(fallback-rooted) → `agent-x@browserid.me`, minted by the broker. This is what
folds the fallback path into the primary path: for broker-rooted parents the
broker is simply the target IdP — endorser and issuer collapse, one code path.
Corollary: the `U_cert` an IdP verifies is always its own issuance.

## Broker (browserid.me) role

### Registry + policy (the centralization)

The broker **registers** provisioning certs created through its UI, tied to
the signed-in account: `{account, delegator_email, P_pub, bundle, label,
created_at, last_endorsed_at, revoked_at}`. Endorsement is only granted for
registered, unrevoked certs — so:

- one dashboard: list every agent key across all the user's identities;
- one revocation point: revoke → endorsements stop → agents age out ≤ 24 h;
- policy sees the whole account (decision: sybil limits are per *user*, not
  per pcert — the broker can refuse a brand-new pcert if the account's
  aggregate behavior is abusive): active-pcert cap, endorsement rate limits,
  per-account distinct-agent-name tracking.

### Endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /provision/endorse` `{request_bundle}` | none (the bundle is the credential) | Verify the full chain (for foreign-domain `U_cert`s the broker uses its existing discovery), check registry + policy, return `{endorsement}` |
| `POST /provision/mint` etc. | none (dual-signed request) | The broker's own target-IdP surface for `@browserid.me` agents (spec §4) |
| `GET /wsapi/provisioning_certs` | session | List the account's registered agent keys |
| `POST /wsapi/register_provisioning_cert` `{bundle, label, csrf}` | session + CSRF | Validate + register a cert the page just created |
| `POST /wsapi/revoke_provisioning_cert` `{id, csrf}` | session + CSRF | Revoke |

### UI (basic, on browserid.me)

An "Agent keys" section (landing page or `/agents`):

1. **Create**: pick one of the session's identities → the page ensures a
   fresh `U_cert` for it (normal dialog/provisioning machinery if storage was
   cleared — decision 5) → generates the P keypair **in-page** (WebCrypto) →
   signs `P_cert` with `U_priv` from broker-origin storage (a typed-signing
   operation per the 2026-06-24 design; the `/sign` machinery is the
   precedent) → `register_provisioning_cert` → shows/downloads the **agent
   credential** exactly once:
   ```json
   { "secret_key": "<P_priv b64url>", "delegation": "<U_cert~P_cert>",
     "broker": "https://browserid.me", "idp": "https://mingo.place" }
   ```
   `P_priv` is never sent to the server.
2. **List**: label, delegator identity, created, last used, active/revoked.
3. **Revoke**: one click; effect within 24 h everywhere.

## Agent SDK (`browserid-agent`)

Rebuilt around the credential file:

- `AgentIdentity::provision(credential, name)` → build `R` (mint), sign with
  `P_priv`, `POST {broker}/provision/endorse`, then `POST {idp}/agent/…` with
  `{request_bundle, endorsement}` → `(A_keypair, agent cert)`. The agent
  keypair stays SDK-generated and local, as in v1.
- Re-mint (`assertion_for`'s auto-refresh) runs the same two hops — decision
  2 makes the broker a once-per-24 h dependency, called by the *agent*, never
  IdP→broker.
- `list`/`revoke` are signed requests with the corresponding `action`.
- Persistence: v1's identity file plus the delegation bundle; still never the
  credential of another layer.

## What this replaces / keeps (implementation impact)

| Piece | v1 (shipped, no users) | v2 |
|---|---|---|
| broker `api_keys` table + `bidk_` hashing | delete | `provisioning_certs` registry (public data only) |
| broker `/wsapi/create_agent_key` etc. | delete | `register/list/revoke_provisioning_cert` + UI |
| broker `/agent/*` Bearer auth | replace auth layer | dual-signed request verification (shared verifier from core) |
| mingo-idp `api_keys` + `/agent_keys` | delete | (nothing — key mgmt is broker-only) |
| mingo-idp `/agent/*` | replace auth layer | dual-signed request verification + `trusted broker` config |
| namespace/quota/reserved-name/idempotency logic (both IdPs) | keep | unchanged |
| `browserid-agent` SDK | rework provision/re-mint | credential file + endorse→mint |
| `sbo id provision-agent` | rework | reads credential file (`SBO_AGENT_CREDENTIAL`), same one-shot claim |
| spec §4 | rewrite | provisioning-request protocol; §5 grant exchange unchanged |

## Confirmed design decisions (2026-07-09)

1. **Signing-time semantics** for the expired-parent-cert problem:
   `P_cert.iat` must fall within `U_cert`'s validity; the IdP may also check
   its own issuance records.
2. **Fresh endorsement per mint**, so the ~24 h agent-cert re-mint cadence is
   also the revocation cadence.
3. **Revocation at the broker** (registry) is the single user-facing switch;
   IdPs can additionally revoke identities locally.
4. **Explicit broker trust**: an IdP names the broker(s) whose endorsements
   it accepts.
5. **Lost browser state** is handled by the normal dialog re-provisioning
   flow before key creation; pure UX.

## Security notes

- Domain separation: three new `typ`-tagged claim shapes, none parseable as
  certs or assertions (and vice versa); `U_priv` signing a `P_cert` cannot be
  replayed as a login.
- `P_priv` leak: attacker can request endorsements until revocation — same
  blast radius as v1's bearer key minus wire exposure; requests are signed,
  so abuse is attributable to `P_pub` in broker logs.
- Broker compromise: can *endorse* rogue requests but cannot *authorize* them
  — a forged flow still needs a user-signed `P_cert`, and the IdP verifies
  that chain itself. (v1: broker DB compromise = silent authorization.)
- The endorsement's `aud` + request's `domain` pin the target; a bundle for
  mingo.place is useless at another IdP.
