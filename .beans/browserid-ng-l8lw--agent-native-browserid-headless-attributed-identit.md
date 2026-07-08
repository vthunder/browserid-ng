---
# browserid-ng-l8lw
title: 'Agent-native browserid: headless attributed identity issuance + agent→API auth'
status: in-progress
type: feature
priority: high
created_at: 2026-07-08T00:07:30Z
updated_at: 2026-07-08T21:45:51Z
---

Make browserid-ng agent-native: let agents acquire and use a browserid-backed
identity **without** a human-in-the-loop email/browser ceremony. Converged
direction from a 2026-07-08 brainstorm. (Downstream consumer: SBO/mingo agents such
as the checkpoint attestor will use this once deployed — tracked separately in the
mingo repo.)

## Core framing

- **Attribution-first, not escrow-first.** Bootstrap agent trust by making every
  agent identity attributable to a human/account. (Escrow/stake — trust-by-bond — is
  a deliberately deferred, separate future product.)
- **Sybil resistance = attribution.** SMTP email verification was browserid's
  implicit rate-limiter on identity creation. Headless issuance removes it, so the
  new cost/limit is the parent it chains to. Per-user quota (3–10 agents, raiseable
  by paying / linking more accounts / higher trust) replaces the inbox as the limit.
- **RPs stay unaware.** An agent presents a bog-standard cert; the RP verifies it as
  normal browserid and just learns "an email." No delegation-awareness, no scope
  enforcement at the RP. Agent-ness is metadata the *issuer* and *human* care about
  (revocation, audit, quota), never a protocol-visible type. No mandated `agent.*`/
  `+`/subdomain syntax on identities.

## The key technical insight (transport, not trust)

browserid's real hostility to agents is its **browser-bound transport**
(`navigator.id`, dialog, `jschannel`/`winchan`, cookie sessions), not its trust
model. Enumerated, almost all of it is **RP-side** and irrelevant to an agent, or
should be *deleted* rather than ported:

- RP login dialog / `~`-delivery → the agent **replaces the browser** as the thing
  producing `cert~assertion`; hands it to the RP over normal HTTP. Not ported.
- Keygen-in-broker-origin (non-extractable `CryptoKey` isolation) → **wrong for an
  agent**; the agent *wants* to hold its own key. Deleted, not ported.
- **Assertion minting is already headless** (`browserid-core::Assertion::create` is
  pure JWS signing). Once an agent holds `(key, cert)` it authenticates to RPs
  forever with zero browser involvement.

=> The entire problem collapses to **one step: cert acquisition.** Today `cert_key`
needs a browser-obtained session cookie. Give it a REST path gated by a credential an
agent can hold (an API key).

Bonus: an agent that holds its own key **deletes the hardest part of the
typed-signing / SBO-envelope design** (`docs/plans/2026-06-24-typed-signing-extension-design.md`)
— origin allowlists, per-app consent, non-extractable custody were all needed only
because the key lived in a shared broker origin. For an own-key agent, signing a
typed payload is just "sign these bytes."

## Provisioning flow (the durable, headless path)

1. User signs into browserid (browser) — the **one** human-in-loop moment; roots
   attribution.
2. User mints an **API key** — materializes the parent→agent link as a revocable DB
   row. The API key **is the standing re-mint credential** (resolves headless
   durability; custody is now an ordinary secret-management problem, revocable at the
   IdP, not a novel crypto problem).
3. Agent generates its **own keypair** locally.
4. Agent `POST`s `{api_key, pubkey, desired_name?}` → IdP verifies key, mints a cert
   binding *that pubkey*, records `attributed_to = <user>`, returns cert.
5. Agent signs assertions (and typed payloads) locally, indefinitely; re-mints via
   the same API key when the 24h cert expires. Revocation = stop re-minting (soft,
   automatic via TTL) or IdP revocation list (hard, immediate).

Prior art to generalize: the mingo primary-IdP already prototypes this endpoint
(`/admin/provision` + `/cert_key` + `/session/from-assertion`) — just admin-token
gated. The concrete step is: replace the admin token with **per-user,
browser-minted API keys + per-user quota.**

## Two options — same code path

- **Option 1 (ship first): dedicated agent IdP, `agents.browserid.me`.** REST-wrap
  `cert_key`, API-key gated. A separate *domain* (not per-identity syntax) is a
  governance lever: rate-limit / monitor / set policy on the whole agent population,
  and RPs can choose how much to trust `@agents.*`, without forcing any identity into
  an `agent.*` shape.
- **Option 2 (later): federation.** Write the provisioning + grant endpoints up as a
  **REST spec** any IdP can implement; browserid brokers agents minting from other
  IdPs. Option 1 is the reference implementation of Option 2's spec — one code path,
  starts centralized, decentralizes without a rewrite. Once federated, agent
  identities will *not* be guaranteed identifiable via `agents.*` — and that's fine.

## RP-side: agent → HTTP API auth (the one unavoidable opt-in)

"Act as me on a website" is explicitly **out of scope** — browserid intentionally
omits how a session is established, so there's nothing to leverage to automate a
cookie'd website login. The case splits three ways; only one is truly ill-fitting:
- **browser-driver agent** (computer-use) — uses the *existing* dialog unchanged.
- **API-client agent** — the sweet spot (below).
- **headless-website-session** — ill-fitting for everyone (the general scrape-vs-API
  gap). Out of scope.

For API RPs, prefer **assertion-as-grant → token exchange** (over per-request
assertion header): agent presents an assertion once to `/token`, RP mints its **own**
bearer token; the RP's entire session machinery stays as-is — we only swap the
front-door credential. Maps onto OAuth token-exchange (RFC 8693). Because most
"websites" are an SPA over a JSON API, an agent that gets a browserid-grant token
from that API uses the real backend without driving a browser — so the punt is
smaller than it feels (lose legacy server-rendered cookie sites, keep anything with
an API).

This is the **one place RP-unawareness ends** — a non-browser client needs a
non-browser auth path, so an API RP must opt into *one* small thing: a verify library
+ a `/token` endpoint. Not delegation-awareness (RP still just learns "an email").
For RPs already doing OAuth it shrinks to **registering one grant type** on machinery
they already run.

## Discovery of the RP auth API

- **Primary (in-band): `WWW-Authenticate` / RFC 7235.** Agent hits unknown API cold →
  `401 WWW-Authenticate: BrowserID realm=..., audience="https://api.example.com",
  token_endpoint="https://api.example.com/token"`. Self-describing, zero pre-config:
  tells the agent the service speaks browserid, the exact `audience` to sign for, and
  where to exchange. RP names its own audience (avoids the agent guessing `aud`).
- **Complement (out-of-band): reuse OAuth, don't invent one.** Advertise via
  `.well-known/oauth-authorization-server` (RFC 8414) with a registered browserid
  grant type — NOT a new `.well-known/browserid-rp`. (Distinct from browserid's
  existing IdP-side `.well-known/browserid`; this is the RP-as-consumer side.)
- Audience string: lean **API origin**, with the `WWW-Authenticate` challenge free to
  override to a stable logical id.

## Deliverables

| Layer | Ships |
|---|---|
| `agents.browserid.me` IdP | REST provisioning (`POST /agent/identities`, re-mint, revoke), API-key gated, per-user quota (3–10, raiseable) |
| Agent SDK | `browserid-core` headless: hold key → REST for cert → sign assertions/typed payloads locally |
| RP-side (opt-in) | verify library + `/token` grant-exchange endpoint; `WWW-Authenticate` challenge + OAuth `.well-known` |
| Federation (later) | provisioning + grant endpoints as a spec; `agents.browserid.me` = reference impl |
| Escrow model (later) | trust-by-bond, separate future product |

## Phasing / TODO

- [x] Write design doc in `docs/plans/` capturing this converged direction — `docs/plans/2026-07-08-agent-native-browserid-design.md`
- [x] Phase 1: broker REST provisioning — per-user API keys + quota (`/wsapi/agent_keys` mgmt + `/agent/*` endpoints; enable with `AGENT_PROVISIONING=1`). Deploying the dedicated `agents.browserid.me` instance is ops, tracked outside this repo.
- [x] Phase 1: headless agent SDK — new `browserid-agent` crate (`AgentIdentity::provision` → `assertion_for` with auto re-mint, raw `sign()` for typed payloads, save/load persistence that never stores the API key)
- [x] Phase 2: RP-side — `browserid-rp` crate (Verifier w/ pinned or well-known-fetched issuer keys, TokenStore, `exchange()` w/ OAuth error codes, RFC 8414 metadata), `browserid_core::rp_auth` wire contract (`WWW-Authenticate: BrowserID` challenge + RFC 7521-shaped grant `urn:x-browserid:grant-type:assertion`), and SDK `token_for()` doing cold discovery → assertion → token exchange
- [ ] Phase 3: federation — publish provisioning + grant endpoints as a REST spec
- [ ] Later (separate product): escrow / trust-by-bond model

## Notes

- Design lineage: `docs/plans/2026-06-24-typed-signing-extension-design.md` (this
  simplifies it for own-key agents).
- Downstream consumer work (wiring the SBO checkpoint attestor + supporting
  non-mingo.place `@agents.browserid.me` identities on-chain) is tracked in the mingo
  repo, not here.
