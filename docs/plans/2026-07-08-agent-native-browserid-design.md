# Design — Agent-native browserid: headless attributed identity issuance + agent→API auth

**Date:** 2026-07-08
**Status:** Design for review (converged direction from 2026-07-08 brainstorm; bean `browserid-ng-l8lw`)
**Scope:** browserid-ng (broker + core). Downstream consumers (SBO/mingo checkpoint
attestor etc.) are tracked in the mingo repo.

## Summary

Make browserid-ng **agent-native**: let a software agent acquire and use a
browserid-backed identity **without** a human-in-the-loop email/browser ceremony,
while keeping every agent identity **attributable** to a human account.

The core observation: browserid's hostility to agents is its **browser-bound
transport** (navigator.id, dialog, jschannel/winchan, cookie sessions), *not* its
trust model. Assertion minting is already headless — `browserid_core::Assertion::create`
is pure JWS signing over a `(key, cert)` the caller holds. Once an agent has a
certified keypair it can authenticate to any RP forever with zero browser
involvement. The entire problem therefore collapses to **one step: cert
acquisition** — today `/wsapi/cert_key` requires a browser-obtained session
cookie (`routes/cert.rs`). We give cert acquisition a REST path gated by a
credential an agent can hold: a **per-user, browser-minted API key**.

Three principles constrain the design:

1. **Attribution-first, not escrow-first.** Agent trust bootstraps by chaining
   every agent identity to a human/account. Escrow/stake ("trust-by-bond") is a
   deliberately deferred, separate future product.
2. **Sybil resistance = attribution.** SMTP verification was browserid's implicit
   rate-limiter on identity creation. Headless issuance removes it, so the new
   limit is the parent it chains to: a **per-user quota** (default small,
   raiseable) replaces the inbox as the cost of an identity.
3. **RPs stay unaware.** An agent presents a bog-standard cert; the RP verifies
   it as normal browserid and learns "an email." No delegation-awareness, no
   scope enforcement at the RP, no mandated `agent.*`/`+`/subdomain syntax.
   Agent-ness is metadata the *issuer* and the *human* care about (revocation,
   audit, quota) — never a protocol-visible type.

## What exists today (grounding)

- **Cert issuance is session-gated:** `browserid-broker/src/routes/cert.rs`
  `cert_key` — cookie session → email-ownership check → 90-day verification
  window → `Certificate::create` (24h validity, 1h ephemeral).
- **Assertion signing is already headless:** `browserid-core/src/assertion.rs`
  (`Assertion::create` / `BackedAssertion`) — pure Rust, no browser.
- **Keys are plain Ed25519:** `browserid-core/src/keys.rs` `KeyPair::generate` —
  an agent can generate and hold its own key trivially.
- **Subordinate-identity machinery (cm8z) already models attribution:**
  `emails.parent_email` (sqlite migration v3, `store/models.rs::Email`) records
  which identity in the same account controls a derived identity, and
  `set_parent_email` maintains it. An agent identity **is** a subordinate email
  whose parent is the human's email — no new attribution concept needed.
- **The admin prototype:** `POST /admin/create_account` (`routes/account.rs`,
  `ADMIN_TOKEN`-gated) and the mingo primary-IdP's `/admin/provision` already
  prototype the headless mint. The concrete step is replacing the shared admin
  token with **per-user, revocable API keys + quota**.
- **The verifier is transport-neutral already:** `/verify` (`routes/verify.rs`)
  accepts any backed assertion over HTTP.

### What is deliberately *not* ported to agents

- **RP login dialog / postMessage delivery** — the agent replaces the browser as
  the thing producing `cert~assertion` and hands it to the RP over normal HTTP.
- **Keygen inside the broker origin (non-extractable CryptoKey isolation)** —
  wrong for an agent; the agent *wants* custody of its own key. This also means
  the hardest parts of the typed-signing design
  (`2026-06-24-typed-signing-extension-design.md` — origin allowlists, per-app
  consent, non-extractable custody) simply don't apply to an own-key agent:
  signing a typed payload is just "sign these bytes." The browser/SBO custody
  work (bean `browserid-ng-e2fi`) is orthogonal and unaffected.

## Provisioning flow (the durable, headless path)

1. **Human signs into the broker (browser)** — the one human-in-loop moment;
   roots attribution.
2. **Human mints an API key** (browser UI, session + CSRF gated). The key
   materializes the parent→agent link as a revocable DB row and **is the
   standing re-mint credential**. Custody of it is an ordinary
   secret-management problem (env var, secret store), revocable at the IdP —
   not a novel crypto problem.
3. **Agent generates its own Ed25519 keypair locally** (`KeyPair::generate`).
4. **Agent POSTs** `{pubkey, desired_name?}` with `Authorization: Bearer <api_key>`
   → broker verifies the key, enforces quota, mints/looks up the agent identity
   (a subordinate email under the broker's domain, `parent_email` = the human's
   chosen email), issues a cert binding *that pubkey*, returns it.
5. **Agent signs assertions (and typed payloads) locally, indefinitely**,
   re-minting via the same API key when the 24h cert expires.
   - **Soft revocation** = revoke the API key or the identity; re-mint stops and
     the agent ages out within the cert TTL (≤24h).
   - **Hard revocation** (immediate; revocation list consulted by the verifier)
     is deferred — TTL-bounded soft revocation is acceptable for v1.

## API design

### Browser-side: API-key management (session + CSRF gated, `/wsapi/*`)

| Endpoint | Method | Behavior |
|---|---|---|
| `/wsapi/agent_keys` | GET | List the session user's API keys (id, name, created_at, last_used_at, revoked) — never the secret. |
| `/wsapi/create_agent_key` | POST `{name, parent_email}` | Mint a key attributed to `parent_email` (must be a verified email on the account). Returns the secret **once**. |
| `/wsapi/revoke_agent_key` | POST `{id}` | Soft-revoke; all future agent calls with it fail. |

Key format: `bidk_<32 bytes base64url from OS RNG>` (prefix makes leaked-key
scanning/greppability easy). Stored **hashed** (SHA-256 — the secret is
high-entropy so a slow KDF buys nothing; hashing just makes a DB leak useless).
Lookup is by hash.

### Agent-side: REST provisioning (`Authorization: Bearer <api_key>`, `/agent/*`)

| Endpoint | Method | Behavior |
|---|---|---|
| `/agent/identities` | POST `{pubkey: {algorithm, publicKey}, name?}` | Create an agent identity `<name>@<broker domain>` (server-generated name if omitted; must be new or already owned by this key's account). Sets `parent_email` to the key's attribution email, marks it verified. Enforces per-user quota. Returns `{email, cert}`. |
| `/agent/identities` | GET | List agent identities minted under this key's account. |
| `/agent/cert` | POST `{email, pubkey, ephemeral?}` | **Re-mint**: issue a fresh cert for an existing agent identity owned by this account. Same validity rules as `cert_key` (24h / 1h ephemeral). The pubkey may rotate — whatever key the agent presents is what gets certified (the API key is the root credential, not the agent keypair). |
| `/agent/identities/revoke` | POST `{email}` | Disable the identity: further re-mints fail; existing certs age out. |

Design notes:

- **Reuse, don't fork, cert issuance.** `/agent/cert` and `/wsapi/cert_key`
  share one issuance function (email-ownership check → verification window →
  `Certificate::create`); only the *authentication* differs (bearer key vs
  cookie session). This is the "one code path" that later becomes the
  federation spec's reference implementation.
- **POST create is idempotent-ish:** posting the same `{name, pubkey}` again
  returns a fresh cert for the same identity rather than erroring — agents
  restart and shouldn't need separate create-vs-remint logic for the common case.
- **Quota:** `max_agent_identities_per_user` in `config.rs` (default **5**,
  range 3–10 per the brainstorm; raiseable later by payment / linked accounts /
  trust). Counted as non-revoked emails with `email_type = 'agent'` on the
  account. 429/`quota_exceeded` on breach.
- **Rate limiting:** per-key rate limit on `/agent/*` (coarse, in-memory token
  bucket is fine for v1); the separate *domain* (below) is the population-level
  governance lever.

### Data model (sqlite migration v4)

```sql
CREATE TABLE api_keys (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash      TEXT NOT NULL UNIQUE,      -- SHA-256(secret), hex
    name          TEXT NOT NULL,             -- human label ("ci-bot")
    parent_email  TEXT NOT NULL,             -- attribution root for identities minted with this key
    created_at    TEXT NOT NULL,
    last_used_at  TEXT,
    revoked_at    TEXT                        -- NULL = active
);
CREATE INDEX idx_api_keys_user ON api_keys(user_id);
```

Plus one `emails` change: extend `email_type` values with `'agent'`
(`EmailType::Agent`). Agent identities reuse the existing row shape:
`verified = 1`, `verified_at = mint time`, `parent_email` = attribution email
(cm8z machinery as-is). Revoking an agent identity clears `verified` (re-mint
then fails the existing verified check in issuance — no new code path).

The `UserStore` trait grows: `create_api_key`, `get_api_key_by_hash`,
`list_api_keys`, `revoke_api_key`, `touch_api_key`, `count_agent_identities`.

## Deployment: `agents.browserid.me` (Option 1 — ship first)

A **dedicated agent IdP** is a *deployment* of this same broker with
`domain = agents.browserid.me`, not a fork. A separate domain (rather than
per-identity syntax) is a governance lever: rate-limit / monitor / set policy on
the whole agent population, and RPs can choose how much to trust `@agents.*` —
without forcing any identity into an `agent.*` shape. Nothing in the code knows
it is "the agent deployment"; the same binary with agent provisioning enabled
serves both roles.

Config: `agent_provisioning_enabled` (bool, default off) gates the `/agent/*`
routes and the key-management UI, so existing broker deployments are unchanged.

## Agent SDK (Phase 1, alongside the broker work)

A thin headless client — mostly wiring of existing `browserid-core` pieces:

```
browserid_core (exists)        agent SDK (new, small)
──────────────────────         ─────────────────────────────────────────
KeyPair::generate              hold/load keypair (file or caller-provided)
Certificate                    POST /agent/identities | /agent/cert (reqwest)
Assertion::create              mint_assertion(audience) with auto re-mint
                               when the cached cert is expired
```

Deliverable shape: a `browserid-agent` crate (or a module in `browserid-core`
behind a `client` feature) exposing roughly
`AgentIdentity::provision(idp_url, api_key, name?) -> Self` and
`self.assertion_for(audience) -> String`. Typed-payload signing ("sign these
bytes with the certified key") comes for free since the key is local.

## RP-side: agent → HTTP API auth (Phase 2 — the one unavoidable opt-in)

"Act as me on a *website*" stays **out of scope**: browserid intentionally does
not specify session establishment, so there is nothing to leverage to automate a
cookie'd login. The cases split:

- **Browser-driving agent** (computer-use) — uses the existing dialog, unchanged.
- **API-client agent** — the sweet spot, below.
- **Headless website-session** — the general scrape-vs-API gap; out of scope.
  (Smaller than it feels: most "websites" are an SPA over a JSON API, and an
  agent holding a browserid-grant token for that API uses the real backend.)

For API RPs, prefer **assertion-as-grant → token exchange** over a per-request
assertion header: the agent presents an assertion once to the RP's `/token`
endpoint; the RP verifies it (verify library or hosted `/verify`) and mints its
**own** bearer token. The RP's entire session machinery stays as-is — only the
front-door credential changes. This maps onto OAuth 2 token exchange (RFC 8693);
for RPs already running OAuth it shrinks to **registering one grant type**.

This is the one place RP-unawareness ends — a non-browser client needs a
non-browser auth path — but the opt-in is small: a verify library + a `/token`
endpoint. Still no delegation-awareness; the RP learns "an email."

### Discovery of the RP auth API

- **Primary (in-band): `WWW-Authenticate` / RFC 7235.** Agent hits an unknown
  API cold → `401` with
  `WWW-Authenticate: BrowserID realm="…", audience="https://api.example.com", token_endpoint="https://api.example.com/token"`.
  Self-describing, zero pre-config; the RP names its own audience so the agent
  never guesses `aud`.
- **Complement (out-of-band): reuse OAuth metadata, don't invent one.**
  Advertise via `.well-known/oauth-authorization-server` (RFC 8414) with a
  registered browserid grant type — *not* a new `.well-known/browserid-rp`.
  (Distinct from the existing IdP-side `.well-known/browserid`.)
- **Audience string:** lean **API origin**, with the `WWW-Authenticate`
  challenge free to override to a stable logical id.

## Federation (Phase 3 — later)

Write the provisioning (`/agent/*`) and grant-exchange endpoints up as a **REST
spec** any IdP can implement; browserid brokers agents minting from other IdPs.
Option 1 (`agents.browserid.me`) is the reference implementation of that spec —
one code path that starts centralized and decentralizes without a rewrite. Once
federated, agent identities are *not* guaranteed identifiable via `agents.*`;
that's fine — agent-ness was never protocol-visible.

## Security considerations

- **API key = standing credential.** Mitigations: shown once at mint; stored
  hashed; `bidk_` prefix for secret-scanning; per-key `last_used_at` for audit;
  one-click revocation; scoped to *minting certs for agent identities* only — it
  can never read account data, change passwords, or mint certs for the human's
  own (non-agent) emails.
- **Quota is the sybil defense.** Per-user identity quota + per-key rate limits
  replace SMTP friction. The dedicated domain adds population-level throttles.
- **Blast radius of key leak:** attacker can mint certs for that account's
  *agent* identities (impersonating the agent) until revocation — but cannot
  touch the human's identities. Certs age out ≤24h after revocation.
- **CSRF:** the browser-side key-management endpoints must enforce the session
  CSRF token (note: bean `browserid-ng-y2ho` — CSRF enforcement is currently
  missing broker-wide; key minting must not ship before/without it on these
  routes).
- **No RP-visible agent marker** is a *feature*, not an oversight (framing §3).
  RPs that want to policy on agents can policy on the issuing domain.

## Phasing

1. **Phase 1a — broker:** migration v4, `EmailType::Agent`, store methods,
   `/wsapi/*` key management (+ minimal landing-page UI), `/agent/*`
   provisioning/re-mint/revoke, quota + rate limit, config gate. Tests: full
   headless mint→assert→`/verify` round-trip.
2. **Phase 1b — agent SDK:** `browserid-agent` client (provision, cache, auto
   re-mint, assertion + raw typed signing).
3. **Phase 2 — RP side:** verify library ergonomics + `/token` grant-exchange
   reference + `WWW-Authenticate` challenge + RFC 8414 metadata.
4. **Phase 3 — federation:** publish the REST spec; `agents.browserid.me` as
   reference implementation.
5. **Later (separate product):** escrow / trust-by-bond.

## Design lineage

- `2026-06-24-typed-signing-extension-design.md` — this design *simplifies* it
  for own-key agents (custody/consent machinery was only needed because the key
  lived in a shared broker origin).
- cm8z subordinate identities (`parent_email`, migration v3) — reused verbatim
  as the attribution model.
- mingo primary-IdP `/admin/provision` prototype — generalized here from a
  shared admin token to per-user revocable keys + quota.
