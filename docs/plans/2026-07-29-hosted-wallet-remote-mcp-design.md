<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Hosted wallet — a remote MCP server for agents that can't run code

**Date:** 2026-07-29
**Status:** Draft design
**Bean:** browserid-ng-83ab

## 1. Problem

The wallet (`@browserid-ng/wallet`) is a **local stdio MCP server**: the MCP
client launches it via `npx`, and the agent's device key lives in
`~/.browserid/` on the user's machine. That works for Claude Code, Cursor, and
Claude Desktop — clients that can execute a local process.

It excludes every agent that **cannot run code**: claude.ai web, mobile, and
any hosted agent whose only extension point is a **remote MCP connector**
(streamable-HTTP + OAuth). Today those agents have no path to a browserid
identity at all.

This doc designs a **hosted wallet**: the same wallet tool surface, exposed as
a remote MCP server, with the agent's credentials custodied server-side.

## 2. Why the protocol already permits this

Three existing design decisions carry the load:

1. **An agent is a device** (spec §4, device-cert model). Nothing requires the
   device to be the user's machine. A hosted wallet is one more device that
   happens to run in a datacenter; issuance, minting, and presentation are
   unchanged.
2. **The purpose split bounds custody.** The hosted wallet holds only
   `authentication`-purpose material: the agent device key, its device cert,
   and issued warrants. It never holds a **config cert** — warrants are still
   signed client-side in the *user's* browser at the consent page. A fully
   compromised wallet host **cannot mint new grants**: it can act as the agent
   only at audiences the user already warranted, attributably
   (`subject: agent`), until revoked. That is exactly the blast radius spec
   §8 already accepts for a leaked agent device key — custody changes the
   probability of that event, not its shape.
3. **Human-in-the-loop moments are URL-shaped.** Pairing approval and consent
   both hand the user a `verification_uri` they open in their own browser and
   confirm at browserid.me. That ceremony is identical from claude.ai — the
   tool result carries the link; no part of the trust ceremony runs on the
   wallet host or in the model.

**The invariant that must survive:** no single party can fabricate a user
authorization. It does: the broker signs certs but never warrants; the wallet
signs (with agent device keys) access requests and warrant requests but holds
no config certs and no IdP key. Warrant forgery still requires the user's
config cert, which stays in the user's browser.

## 3. Non-goals

- Replacing the local wallet. Local remains the recommended tier — the key
  never leaves the machine. Hosted is the tier for agents that can't run code.
- Custodying **user** (human) identities or config certs. Hosted custody is
  for `agent`-subject authentication credentials only.
- A general-purpose key escrow / recovery service. Losing a hosted agent key
  is recoverable the same way as losing a laptop: revoke, re-provision.

## 4. Architecture

```
claude.ai (web/mobile)                    wallet.browserid.me                browserid.me
┌────────────────────┐   streamable-HTTP  ┌─────────────────────┐           ┌─────────────────┐
│  custom connector  │ ─────MCP+OAuth───▶ │  hosted wallet       │           │ broker / IdP    │
│  (per user acct)   │                    │  - MCP server        │──mint────▶│ mint API        │
└────────────────────┘                    │  - tenant store      │──pair────▶│ /agent-provision│
        │                                 │  - per-tenant agent  │──consent─▶│ /warrant/*      │
        │  user opens APPROVE_URLs        │    device keys (enc) │           │ consent page:   │
        └────────────────────────────────────────────────────────┼──────────▶│ user's config   │
                                          └─────────────────────┘           │ cert signs W    │
                                                                             └─────────────────┘
```

- **Separate service, separate keys, separate host** (`wallet.browserid.me`,
  its own dokku app, own database, own secrets). Even under one operator,
  broker compromise alone yields no agent device keys, and wallet compromise
  alone yields no warrant-signing or issuance capability.
- The wallet service is a **standard MCP streamable-HTTP server** with the
  OAuth profile required by the MCP authorization spec (§6).
- Internally it reuses `@browserid-ng/agent` (`DeviceAgent`) — the same
  provisioning, minting, and presentation code the local wallet runs, already
  exercised end-to-end. The hosted wallet is a thin multi-tenant shell around
  it: Node, `@modelcontextprotocol/sdk` streamable-HTTP transport.

## 5. Tenancy model

- **A wallet account is a browserid identity.** The OAuth authorization page
  at wallet.browserid.me is itself a browserid RP: the user signs in
  passwordlessly with their existing identity (dogfood). The verified email is
  the tenant key.
- **One default agent identity per wallet account.** The first `provision`
  call creates it (normal pairing flow: user opens the approval link, confirms
  the key fingerprint — the key is generated *on the wallet service*, and the
  fingerprint shown at approval is that key's, so the ceremony is honest about
  where the key lives). All of the user's claude.ai chats share it — which is
  correct: they are all "the user's claude.ai agent," and per-session freshness
  is already provided by short-lived access certs.
- **Room for named agents later** (`AGENT_NAME` equivalent): the store keys
  agents by `(account, name)` with `name = "default"` for the MVP. Not exposed
  in the MVP tool surface.
- Concurrent sessions of the same user are safe: mint operations are
  independent; grant storage is last-writer-wins per audience (same semantics
  as the local wallet's file store).

## 6. Connector authentication (OAuth)

Per the MCP authorization spec (2026-07-28 RC), the wallet service acts as an
**OAuth 2.1 resource server**; claude.ai obtains tokens via
authorization-code + **PKCE (S256 only** — `plain` is banned by the spec**)**.
Concretely:

- **Discovery:** `/.well-known/oauth-protected-resource` (RFC 9728, MUST for
  the RS) names the authorization server;
  `/.well-known/oauth-authorization-server` (RFC 8414) advertises its
  endpoints. MVP: the wallet service embeds its own minimal AS rather than
  delegating (the spec explicitly allows co-located AS+RS) — the AS is one
  authorize page + token endpoint, and the authorize page's login step **is**
  browserid sign-in.
- **Client registration:** support **Client ID Metadata Documents**
  (draft-ietf-oauth-client-id-metadata-document — the current spec's
  preferred path) and **dynamic client registration** (RFC 7591 — now
  optional/deprecated but what deployed clients use), plus pre-registered
  client IDs (claude.ai's "Advanced settings"). Registered clients carry no
  trust — all authorization is per-user at the authorize page.
- **Token binding:** resource indicators (RFC 8707) — tokens are
  audience-bound to `https://wallet.browserid.me` and the RS rejects tokens
  minted for any other resource. The AS also implements RFC 9207 (`iss` in
  the authorization response) against mix-up attacks.
- **Token lifetimes:** access tokens short-lived (1 h), opaque, hashed at
  rest; refresh tokens rotating, ~30 d, revocable from the wallet account
  page. claude.ai stores tokens per user per connector and refreshes
  automatically (proactively near expiry and reactively on 401), so hourly
  expiry costs no UX. A stolen token yields tool-surface access only — the
  same blast radius as the agent key itself (mint + present at warranted
  audiences), still warrant-bounded and revocable.
- **Scope step-up:** claude.ai honors `403` + `WWW-Authenticate` listing
  required scopes by re-authorizing. MVP uses a single `wallet` scope; the
  step-up path is the seam for finer scopes later (e.g. a read-only
  `wallet:inspect`).
- **No authless mode.** claude.ai supports header-based authless connectors
  (beta), but the OAuth tenant binding is the whole point here — rejected.

## 7. Tool surface

Identical to the local wallet — `provision`, `identity`, `authorize`,
`get_assertion`, `warrants`, `drop_grant`, `forget`, plus the guestbook demo
pair — so prompts and docs transfer verbatim. Deltas:

- **`forget`** deletes the tenant's stored credential (and, unlike local,
  *can* offer server-side revocation later, since the wallet account is
  authenticated).
- Tool results keep the `APPROVE_URL:` convention; claude.ai renders URLs in
  tool output as clickable links, which is the only affordance the flow needs.
- Broker-side nothing changes: the wallet calls the same
  `/agent-provision/*` and `/warrant/*` endpoints, presents the same signed
  objects.

## 8. Key custody

- **Generation:** per-tenant Ed25519 seed generated server-side at
  `provision`, never exported, never shown. (The pairing fingerprint shown to
  the user at approval is derived from the public key, as today.)
- **At rest:** envelope encryption. Each seed is encrypted with a per-tenant
  DEK; DEKs are wrapped by a master key (KEK) that lives **outside the
  database** — an environment secret in the MVP, with a clean seam
  (`KeyWrapper` interface) to swap in a cloud KMS / HSM later. DB exfiltration
  alone yields ciphertext.
- **In use:** a sign-only internal module (`sign_access_request`,
  `sign_warrant_request`) — seeds are unwrapped transiently per operation and
  zeroized; no code path returns key material to the MCP layer. The agent
  device key signs exactly two request types; assertions are signed by
  ephemeral access keys that live only in memory for their TTL.
- **No user-password wrapping.** Considered and rejected: a password typed to
  the agent would transit the model context (logged, retained, model-visible);
  typed to a web page it's just OAuth with extra steps; and agent operation is
  headless, so a presence-gated unlock either blocks the agent or degenerates
  to server custody anyway. If a presence gate is ever wanted, the
  protocol-native lever is short warrant expiry + a wallet policy knob
  ("require a fresh browser touch every N hours before minting"), enforced
  out-of-band.

## 9. Audit log

Every mint, assertion issuance, warrant request, and admin action is recorded
per tenant: `(ts, op, audience?, jti, client_id, ip)`. Surfaced on the wallet
account page ("everything your hosted agent signed"). This is a capability the
local wallet cannot offer and should be marketed as such — custody buys
visibility.

Retention: 90 days (matches warrant reference validity). No message content,
no scopes interpretation — operational metadata only.

## 10. Threat-model delta (summary)

| Event | Outcome | Bounded by |
|---|---|---|
| Wallet DB exfiltrated | ciphertext only | KEK outside DB |
| Wallet host fully compromised | attacker mints/presents as hosted agents at **already-warranted** audiences, attributably | warrants (user-signed, client-side), 3× fail-closed revocation, audit log |
| OAuth token stolen | attacker drives the tool surface for that tenant | same bound as above; token revocable, short-lived |
| Broker compromised (unchanged) | certs forgeable for fallback identities, warrants still not | config cert client-side |
| Wallet + broker both compromised | agent impersonation at warranted audiences + cert forgery — still no warrant forgery | config cert client-side |

What custody does **not** change: warrant issuance always round-trips through
the user's browser and config cert; revocation authorities are unchanged;
`subject: agent` attribution is issuer-set and unforgeable by the wallet.

## 11. Positioning & doc changes

The README/wallet-README claim "it's local to your machine — browserid.me
never holds the key" becomes a **tier statement**:

> **Local wallet** (recommended): your agent's key never leaves your machine.
> **Hosted wallet** (for agents that can't run code — claude.ai web/mobile):
> a sign-only, audited, revocable custodied key at wallet.browserid.me —
> still scoped by warrants only you can sign, still revocable in one click.

This is the same posture every OAuth-based claude.ai connector already
implies, with a strictly better story: user-signed scoping, three independent
revocation authorities, and a full audit trail.

## 12. MVP cut

1. New top-level dir `wallet-service/` (Node, reuses `sdk/agent`; own dokku
   app `wallet.browserid.me`; SQLite).
2. OAuth AS+RS per §6 (browserid sign-in as the authorize step).
3. MCP streamable-HTTP server, local-wallet tool surface (§7).
4. Custody per §8 (env-secret KEK; `KeyWrapper` seam).
5. Audit log (§9) — write path only; account-page UI can follow.
6. e2e: Playwright flow — connect, provision, approve, guestbook sign.

Out of MVP: named multi-agent tenancy, KMS backend, audit UI, server-side
revoke from `forget`.

## 13. Open questions

- **Connector distribution:** claude.ai custom connectors are added by URL —
  Pro/Max users under Settings → Connectors (Free allows one; Team/Enterprise
  connectors are added by org owners, members authenticate individually).
  Later, an entry in Anthropic's connector directory would remove even that
  step. Requirements TBD.
- **Transport variant:** claude.ai's docs don't pin SSE vs. streamable HTTP
  for the client side; the `@modelcontextprotocol/sdk` streamable-HTTP server
  (with SSE compat) is the safe default — verify against a real connector
  early in the MVP.
- **Rate limits:** per-tenant mint/assertion ceilings (the broker already rate
  limits its side; the wallet should too, so one stolen token can't grind).
- **Elicitation:** if/when claude.ai supports MCP elicitation in remote
  connectors, approval links could become interactive prompts; the URL flow
  works regardless.
