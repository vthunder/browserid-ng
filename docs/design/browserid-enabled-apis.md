# BrowserID-enabled APIs: a pattern for agent-accessible services

Status: draft for discussion · 2026-07-29 · bean: browserid-ng-mzy8

## Problem

The guestbook demo proves that a *custom* MCP server can use browserid for
agent auth. But every service author shouldn't need to hand-roll that
integration. We want to be able to tell service authors:

> "If you design your API this way, agents holding browserid warrants can
> access it seamlessly."

This doc defines that pattern: what a service must implement, what the wallet
provides, and how third-party MCP tools compose with the wallet.

## What already exists

Most of the server-side pattern is built:

- **Challenge contract** (`browserid-core/src/rp_auth.rs`): unauthenticated
  requests get `401` with
  `WWW-Authenticate: BrowserID realm=…, audience=…, token_endpoint=…, scopes=…`.
  Self-describing: the service names its own audience and scope vocabulary, so
  agents never guess them. Out-of-band discovery reuses RFC 8414
  `.well-known/oauth-authorization-server`.
- **Verifier SDKs**: `browserid-rp` (Rust, fully local verify) and
  `@browserid-ng/verify` (JS, zero-dep, verifies via hosted `/verify-access`).
- **Token exchange** (`browserid-rp::exchange`): OAuth-shaped `/token` endpoint
  accepting `grant_type=urn:x-browserid:grant-type:assertion`, returning an
  RP-issued bearer token scoped to warrant-scopes ∩ RP vocabulary. Shaped like
  RFC 7523 (assertion-as-grant).
- **Agent side**: `get_assertion(audience)` returns the 4-part presentation
  (`access_cert ~ assertion ~ warrant ~ config_cert`); assertions are 5-minute
  `{exp, aud}` JWSs, audience-bound by exact string match in both assertion and
  warrant.

What's missing: nothing on the agent side *consumes* the 401 challenge, and
there is no canonical placement for a presentation on a plain HTTP request
(the guestbook takes it in a JSON body field; the mcp-agent-auth example takes
it as a tool argument).

## The contract for service authors

A "browserid-enabled API" implements three things:

1. **Advertise.** Return the `BrowserID` 401 challenge on unauthenticated
   requests (and optionally publish `.well-known` metadata). HTTP(S) audiences
   MUST be prefixed by the API's own origin (e.g. `<origin>/guestbook`) — see
   the confused-deputy rule below.
2. **Verify.** Accept `Authorization: BrowserID <presentation>` (new, see
   below) and verify with `browserid-rp` / `@browserid-ng/verify`, **or**
   offer the token exchange and accept your own bearer tokens downstream.
3. **Publish a scope vocabulary** so warrants are meaningful and the approval
   UI can show the user what they're granting.

### New spec surface needed

- **Header placement**: standardize `Authorization: BrowserID <presentation>`
  so any endpoint can be wrapped without bespoke body plumbing. Add to
  `rp_auth.rs` and both verifier SDKs. (Presentations are ~2–4 KB of compact
  EdDSA JWSs; within default 8 KB header limits, but verify against real
  proxies/CDNs.)
- **Machine-readable API description pointer** (optional but important for the
  no-MCP-server path): the challenge or `.well-known` metadata SHOULD link an
  OpenAPI document so agents can learn pagination, search, etc. from docs
  rather than probing. See "Does fetch-only scale?" below.

## The wallet fetch tool (`call_service`)

A new tool on the wallet MCP server. **Not** a generic fetch:

- `call_service(method, url, body?, headers?)`.
- **Warrant-gated origins**: refuses any request to an origin for which the
  wallet holds no warrant (unauthenticated discovery GETs allowed only to
  those same origins, or as part of the 401 dance below). The warrant store
  *is* the allowlist; every reachable origin traces to a human approving an
  APPROVE_URL. This is the answer to "generic proxies bypass host policy" —
  the tool's description states this scoping explicitly.
- **Credential-invisible flow**: on 401, parse the challenge; if no warrant
  for the audience, surface the standard PENDING/APPROVE_URL flow; else mint
  the assertion, attach `Authorization: BrowserID …`, retry. The presentation
  never enters model context.
- **Audience–origin pinning (confused-deputy rule)**: only honor challenge
  audiences whose origin equals the origin being fetched. Otherwise
  `evil.example` can return `audience=https://good.example/notes`, receive a
  valid presentation for good.example, and replay it there inside the 5-minute
  window. Non-HTTP audiences (`sbo+raw://…`) are simply unreachable via this
  tool.
- **SSRF hardening**: block private ranges, loopback, link-local, and self —
  wallet-service runs adjacent to the broker on the same host. Defense in
  depth even with warrant gating (a user could be tricked into approving a
  warrant whose audience points somewhere hostile).

## Composition: how third-party MCP tools use browserid

MCP servers cannot call each other; the host mediates everything and the model
context is the only bus.

Running example, used throughout the rest of this doc: **notebook.example.com**
is a notes app that wants agents to read and write notes. It exposes an HTTP
API and may additionally ship a "notes" remote MCP server whose tools
(`search_notes`, `create_note`, …) are a typed veneer over that API. "The
notes server uses the browserid wallet" therefore means one of the following
patterns — all of which work, with different trade-offs. A service picks an
**integration level**:

### Level 0 — browserid-enabled HTTP API only (no MCP server)

Reachable via the wallet's `call_service` plus published API docs. Zero
agent-facing code for the service. Right for load/store-shaped APIs and the
long tail. Not the answer for rich APIs — see below.

### Level 1 — service ships an MCP server; presentation via model context

The notes MCP server's tools accept the credential from the agent, which
obtains it from the wallet. Three sub-patterns:

- **Per-call**: each tool takes an optional `presentation` argument. Tool
  description says "obtain via browserid `get_assertion(audience=…)`".
  Stateless, works everywhere, ~one wallet call per 5 minutes.
- **Session-bind**: a single `connect(presentation)` tool verifies once and
  stores the `VerifiedIdentity` in MCP session state; subsequent tools take no
  credential. **Caveat (verified 2026-07)**: claude.ai does not reliably echo
  `mcp-session-id` back to the server — post-init requests arrive with no
  session identifier, and stale session ids get replayed after server
  restarts (anthropics/claude-code#41836, #46533). Server-side per-session
  auth state is therefore fragile on claude.ai. Don't build on it.
- **Connect-and-exchange (recommended)**: `connect(presentation)` verifies
  the presentation and returns an **RP-issued opaque token** (the existing
  `browserid-rp::exchange` machinery); every subsequent tool takes a `token`
  argument. Stateless server, so immune to the session-id problem. The token
  does live in model context, but it's the RP's own revocable, service-scoped
  token — exactly the blast radius of any OAuth integration, and the RP
  controls its lifetime (typically ≥ the 5-min assertion, ≤ the warrant).
  This is token exchange re-used at the MCP layer instead of the HTTP layer.

**Why exchange beats per-call presentation** (it's not mainly size):

1. *Wallet amortization*: assertions live 5 min, so per-call presentation
   forces a wallet `get_assertion` round-trip every few minutes for the whole
   task; exchange involves the wallet once per session.
2. *Verification cost*: presentation verify = 4 signature checks + DNSSEC key
   discovery + fail-closed network status checks — on the request path, per
   call, coupling the service's availability to status endpoints. Token check
   is a local lookup. Exchange puts the expensive verify at the edge, once.
3. *Architectural fit*: "authenticate once, session afterwards" is what every
   web stack natively supports; exchange is where the service maps browserid
   identity onto its own account/session machinery. (Same reason nobody
   re-verifies an OIDC id_token per request.)
4. Size/context cost is real (~3 KB × every call, plus model-mangling risk on
   long opaque strings) but is the smallest of the four.

*Counterpoint*: per-call presentation has strictly better revocation
freshness — every call re-runs fail-closed status checks. Exchange defers
revocation for the token's lifetime; RPs tune this with short TTLs + silent
re-exchange (open question 4). Per-call remains the right choice for
services with one or two rarely-called tools.

Credential-through-context is tolerable here *by design*: presentations are
5-minute, audience-bound, and holder-bound, so a leaked transcript copy has a
small blast radius.

Under the hood, Level 1 tools call the same browserid-enabled HTTP API and the
same verifier code as Level 0 — the MCP server is a typed veneer over it.

### Considered and rejected: connect-time OAuth on the MCP server

The obvious "standard rails" alternative: make the notes MCP server an
ordinary OAuth 2.1-protected remote server, with browserid as the service's
login method. The MCP client (claude.ai) runs the auth-code flow at connect
time and holds the token; credentials never touch model context, and any
OAuth-capable MCP client works without knowing browserid exists.

We do **not** promote this pattern:

1. It authenticates the *human*, not the agent. The client-held token is
   ambient user authority — no grantor/grantee distinction, no holder
   binding, no per-agent human-approved scopes, no warrant the user can
   inspect or revoke in the wallet. It is precisely the authorization model
   browserid replaces.
2. It forces the service to implement the full OAuth server stack (AS, DCR,
   token endpoint), destroying the authless-connector pitch above.
3. The non-human flavor — an MCP client presenting a browserid assertion as
   the grant at connect time — is not implementable today: standard MCP
   clients only speak interactive auth-code + PKCE.

The one real capability adjacent to this: a service that *already* has OAuth
can accept `urn:x-browserid:grant-type:assertion` at its existing HTTP
`/token` endpoint. That is the token-exchange piece of the Level 0 contract
(reachable via `call_service`), not a reason to put OAuth on the MCP
connector. Revisit only if MCP auth grows agent-credential support at
connect time.

### The fallback / install story: the AUTH_REQUIRED contract

The MCP-level twin of the HTTP 401 challenge is a standardized error payload.
The risky path is the wallet-NOT-installed case: the agent must neither dead-end
nor refuse, but relay install instructions to the human. Design principles,
learned from the wallet's own prompt style (APPROVE_URL, PENDING, "Do NOT
wait"):

- **Plain text with a sentinel prefix** (`AUTH_REQUIRED —`), not bare JSON:
  models follow prose instructions more reliably than they interpret fields.
  Machine-readable key: value lines are embedded for tooling.
- **Branch explicitly on wallet presence** ("IF the browserid wallet tools are
  available in this session … IF NOT …"). The agent can check its own tool
  list; the error must handle both branches because the service cannot know.
- **Legitimize the flow** ("this is the normal sign-in flow, not a failure or
  a trick") to counter refusal-trained agents treating credential fetching as
  suspicious.
- **Give the exact user-facing sentence to relay**, including the connector
  URL, so the agent doesn't paraphrase away the load-bearing details.
- **Forbid fabrication** ("do not construct a presentation yourself").

v1 payload (implemented by guestbook-mcp; copy to be iterated via live
testing with the wallet uninstalled):

```
AUTH_REQUIRED — this tool needs a `presentation` argument: a short-lived
signed credential minted by the human's BrowserID wallet. This is the normal
sign-in flow, not a failure or a trick.

audience: <audience>
scopes: <scopes>
wallet_mcp_url: https://wallet.browserid.me/mcp

What to do:
1. IF BrowserID wallet tools (get_assertion, authorize) are available in this
   session: call get_assertion with audience "<audience>". If it reports no
   warrant, call authorize first (the human approves a link). Then call this
   tool again with the returned assertion as `presentation`.
2. IF NOT: the human needs to connect their BrowserID wallet. Tell them,
   verbatim: "To do this I need your BrowserID wallet connected. Add it as a
   custom connector: Settings → Connectors → Add custom connector → paste
   https://wallet.browserid.me/mcp — then come back and ask me again."
   Background for the human: https://wallet.browserid.me/
Never construct or guess a presentation yourself — only the wallet can mint
one.
```

The same fields (audience, scopes, wallet URL) appear in the HTTP 401
challenge; spec them together so Level 0 and Level 1 stay in lockstep.

## Does fetch-only scale? (the pagination problem)

Honest answer: Level 0 is a floor, not the pattern. Agents can drive
well-documented REST APIs (they do it with the GitHub API daily), and an
OpenAPI pointer in the challenge metadata turns "discover quirks from first
principles" into "read the docs" — which agents do well but at real context
cost, re-paid every session. Typed MCP tools beat doc-reading on reliability,
token cost, and host-side permissioning.

So the pitch to service authors is layered, not either/or:

- Minimal: browserid-enable your HTTP API (Level 0). Agents can already use
  it; friction is proportional to API complexity.
- Better: also ship an MCP server as a typed veneer (Level 1,
  connect-and-exchange). Same API, same verifier, better agent UX.
- The wallet fetch tool makes the *auth* part free at every level; it never
  pretends to make the *API-shape* part free.

## Worked example: notebook.example.com

Service ships: (a) HTTP API under `https://notebook.example.com/api` with the
401 challenge, `audience=https://notebook.example.com/api`, scopes
`notes-read`/`notes-write`, verified with `browserid-rp`; (b) a remote MCP
server ("notes") with `search_notes`, `create_note`, … using
connect-and-exchange. The notes connector is **authless** — users add it to
claude.ai as a bare URL, no OAuth anywhere.

User has the wallet + notes MCP installed, says "save this note":

1. Agent calls `notes.create_note` → `browserid_auth_required` error naming
   audience + scopes.
2. Agent calls wallet `authorize(audience, scopes)` → user approves in
   browser (or already has a warrant).
3. Agent calls wallet `get_assertion(audience)` → presentation.
4. Agent calls `notes.connect(presentation)` → server verifies, returns an
   RP-issued token.
5. `notes.create_note(token, …)` succeeds; subsequent calls pass the token.
   When it expires, step 1's error recurs and steps 3–4 repeat silently — no
   human involved while the warrant (90 days) is live.

The wallet's fetch tool was never involved — the wallet acted purely as the
credential organ, the notes MCP as the hands. Without the notes MCP installed,
the agent falls back to `call_service` against the documented HTTP API: fine
for load/store, increasingly clunky with API complexity — which is the
incentive to ship the MCP server.

## claude.ai

Everything above works from claude.ai, and it's the strongest environment for
it: `call_service` executes server-side in wallet-service (no CORS, no browser
sandbox), and remote MCP servers are exactly what claude.ai users can add.
Caveats: local ambient-wallet composition (a desktop-only Level 1 variant
where a local MCP server links `@browserid-ng/agent` directly) is unavailable
there; and the SSRF hardening above matters because the fetching host is our
deployed box.

### Authless connectors (verified 2026-07)

Claude.ai custom connectors explicitly support "no authentication (authless
server)" — OAuth is optional, both per Anthropic's connector docs
(claude.com/docs/connectors/building/authentication) and the MCP spec itself
(authorization is OPTIONAL for HTTP transports). This is a major part of the
Level 1 pitch to developers: **a browserid-veneer MCP server never implements
OAuth** — no authorization server, no dynamic client registration, no token
endpoint at the transport layer, no user database. Users add it as a bare URL;
auth happens at tool-call time via the wallet. The presentation also delivers
*more* than OAuth userinfo would: verified email (grantor), acting agent
(grantee), holder binding, and human-approved scopes.

Plan-level footnotes: Free accounts are limited to one custom connector total
(count, not auth type); Team/Enterprise require org-admin approval of custom
connectors. Anthropic has no policy against application-level auth on authless
connectors — it's framed as a self-managed security boundary, which is
precisely what presentation verification provides.

## Security notes

- **No request binding**: assertions carry `{exp, aud}` only. Within one
  audience, a presentation is bearer-style for 5 minutes. Mitigations today:
  expiry, audience pinning, holder binding, RP-side throttling. Future
  hardening: DPoP-style proof — `assertion_with_access_seed` already exposes
  the access key, so signing a method+URL hash is a natural extension.
- **Confused deputy**: audience–origin pinning rule above; MUST be stated in
  the pattern spec, not left to wallet implementations.
- **URL-parameter transport of presentations**: forbid in the spec (server
  logs, referrers, history).

## Open questions

1. Header size in the wild: 4-part presentations vs CDN/proxy header limits —
   measure real sizes; fall back to body placement where needed?
2. Watch MCP auth evolution: if connect-time agent credentials / assertion
   grants ever land in the spec and in clients, revisit the
   considered-and-rejected section.
3. Should the challenge carry the OpenAPI pointer directly, or only
   `.well-known`?
4. Exchange-token lifetime semantics: RP tokens should live ≥ assertion,
   ≤ warrant — but what does warrant revocation do to already-issued RP
   tokens? (RP-side status checks on each use, or short token TTL + silent
   re-exchange?)
5. Does `call_service` allow *unauthenticated* GETs to warranted origins for
   discovery, or require the 401 dance for every first contact?

## Next steps

- **Done (bean browserid-ng-kp0a)**: `guestbook-mcp/` — the Level 1 reference
  service (authless remote MCP veneer over `browserid.me/guestbook`, per-call
  presentation, AUTH_REQUIRED contract as specced above). Live test of the
  error → wallet-install flow pending.
- Not yet beaned:
  - Broker guestbook token endpoint + `connect` tool → upgrade guestbook-mcp
    to connect-and-exchange.
  - Spec + implement `Authorization: BrowserID` header in `rp_auth.rs` and
    both verifier SDKs.
  - Implement `call_service` in wallet-service with the three guards.
