# The MCP gateway — a hobbyist→SaaS pipeline for BrowserID-authed MCP

**Date:** 2026-08-12
**Status:** design + staged plan. Strategic pivot of the MCP-distribution
thesis (`2026-08-02-mcp-distribution-design.md`): from *demos that prove
capability* to *a tool people adopt for themselves*.

**One line:** one command that publishes ANY stdio MCP server as a remote,
BrowserID-gated endpoint — you decide by email whose agents may connect,
every call is attributed, each person is individually revocable — and the
same middleware (`@browserid-ng/mcp-auth`, already shipped) scales up to
small SaaS. Tailscale's playbook: solve a personal pain in five minutes
free, then walk it into work.

## Why this, why now

We built a complete supply-side stack (mcp-auth JS+Python, the wallet,
hosted registrar/revocation, OIDC onboarding, reference servers) and proved
the *mechanism*. But every demo used a resource that exists only to demo
BrowserID — capability, not pain relief. The wall was demand, not
capability.

The demand is real and present: people run OSS MCP servers locally (stdio)
and increasingly want them **remote** — reach your home Obsidian /
filesystem / Home Assistant server from claude.ai or your phone, or share it
with a friend or a teammate. The instant an MCP server leaves localhost the
only options are: an open port; a static bearer token pasted into everyone's
config (unscoped, unattributed, revocable only by rotating it for everyone);
or "implement OAuth 2.1 + dynamic client registration" (absurd for a
hobbyist). That is exactly the shape of pain `tailscale up` made vanish.

This also retroactively fixes the GitHub-demo objection ("the server could
allowlist emails, but determined how / why?"). Here the answer is obvious:
**it's your server; the allowlist is yours.** The email gate finally has a
use case nobody needs explained.

## The pipeline (the Tailscale move)

1. **Hobbyist.** Wrap-and-share your own OSS server. Free, five minutes,
   better than a static token *even solo* (scoped tools, revoke without
   config surgery, an audit line per call) — and dramatically better the
   moment a second person connects. Onboarding a friend with a Gmail
   address is one hop via the OIDC bridge we just shipped.
2. **Small team / small SaaS.** The same thing as middleware — which *is*
   `@browserid-ng/mcp-auth`, already on npm/PyPI. The engineer who gated
   their home Obsidian server is the one who says "we could just use this"
   when their startup exposes its product to agents without wanting to build
   an OAuth AS + refresh-token vault. Same product, bigger knobs.
3. **Emergent kill switch.** Nobody has to *demo* cross-service revocation
   anymore. Once a user has three gated servers (their own, a friend's, a
   SaaS), `browserid.me/account` listing all of them and killing one agent
   everywhere is a lived experience. Each new gated server makes the wallet
   more valuable — the compounding loop the demos lacked.

## The product

`@browserid-ng/gate` — a CLI that fronts an arbitrary stdio MCP server:

```
npx @browserid-ng/gate --allow you@example.com,friend@gmail.com -- \
  npx -y @modelcontextprotocol/server-filesystem ~/notes
```

Produces a remote-ready HTTP MCP endpoint that:
- speaks MCP Streamable HTTP to hosts (Claude, Cursor, claude.ai, phone);
- runs the wrapped server as a stdio child, proxying JSON-RPC both ways;
- gates every request through `mcp-auth` (scoped, fail-closed per call);
- enforces a **grantor allowlist** (whose humans may connect);
- **auto-maps tools → scopes** (derive `tool:<name>` from the child's
  `tools/list` so approval cards render legibly with zero config);
- prints an attribution line per call (`grantee acting for grantor · tool ·
  args-digest`).

Reachability is NOT ours to build: document `tailscale funnel` /
`cloudflared` as the tunnel. Standing on Tailscale's shoulders is on-message.

The library underneath is `mcp-auth` (shipped). The CLI is a thin
generic-proxy + allowlist + scope-mapper on top, plus the one real protocol
gap below.

## Architecture: two auth lanes into one resource server

The resource server (the gated MCP endpoint) accepts a bearer and checks it
fail-closed per call — unchanged from today. What changes is how a host GETS
the bearer. Two lanes, both terminating in the same `mcp-auth` bearer store:

- **Lane A — assertion grant (exists today).** A code-capable agent with the
  wallet alongside obtains a warrant (its own attributed identity) and POSTs
  the presentation to `/token` (RFC 7521 `jwt-bearer`). This is the mingo /
  github-mcp path. Keep it for agents that want their own identity.
- **Lane B — authorization code (THE GAP, critical path).** A generic OAuth
  host (claude.ai, Cursor) that knows nothing about BrowserID does the
  ordinary redirect dance: discover the AS, register (DCR), open
  `/authorize` in a browser, approve, get a code back, exchange at `/token`.
  No wallet required. This is what makes "paste the URL into Claude and it
  just works" true — Tailscale-grade UX.

### What Lane B requires (the concrete work)

`mcp-auth`'s AS today advertises only `grant_types_supported:[jwt-bearer]`,
no `authorization_endpoint`, no registration. Lane B adds:

1. **Discovery:** advertise `authorization_endpoint`, add `authorization_code`
   (+ `refresh_token`) to `grant_types_supported`, `code_challenge_methods_
   supported:[S256]`.
2. **Dynamic Client Registration (RFC 7591)** — `POST /register`. MCP hosts
   self-register; without it the "just works" flow doesn't. In-memory client
   store is fine for v1.
3. **`GET /authorize`** — PKCE-guarded. Redirects the browser to a
   BrowserID warrant-approval page (below), carrying `audience = this
   resource`, the requested scopes, and a return URL. On approval, redirect
   back to the host's `redirect_uri` with an auth `code`.
4. **`POST /token` `grant_type=authorization_code`** — verify the PKCE
   verifier, redeem the code for the approved warrant material, mint the same
   short-lived bearer Lane A mints (into the same store, so per-call
   fail-closed status checks are identical).

### The central design decision: who is the grantee in Lane B?

In Lane A the agent holds a device cert and is the warrant's grantee. In Lane
B the host is a generic OAuth client with no BrowserID identity. Options for
what the browser approval produces:

- **(A) Gateway-as-agent.** The gateway provisions ONE BrowserID agent
  identity for itself; Lane-B warrants name the gateway as grantee, the
  connecting human as grantor. The gateway mints bearers from it. Simplest,
  reuses the provisioning path we just hardened. Attribution granularity:
  per-human-grantor (the axis that matters), not per-host. **Recommended for
  v1.**
- **(B) Per-connection provisioned identity.** At authorize time the gateway
  provisions a fresh agent identity (a sub-identity of the connecting human,
  e.g. `friend+claude@…`) → full "host X as agent Y for human Z" attribution.
  Heavier — it's the managed-agent provisioning path we hardened 2026-08-12 —
  but it's the one that makes an agent **human-meaningfully nameable**, so the
  gateway owner can *see* and *ban* an individual agent.
- **(C) Warrant-to-holder-key.** Approval binds the warrant to a bare holder
  key the gateway generated for the connection. Lighter than B, and it lets
  the *connecting human* revoke their own individual agents — but the holder
  is a deliberately opaque random string (spec), so it gives the **owner** no
  meaningful way to see or ban one agent. It optimizes the wrong side for the
  "my server, my friends" case. **Skip it.**

Start at (A), design toward (B) — NOT (C). Rationale (settled 2026-08-12):
per-*human* revocation is what the wedge case needs, and (A) already delivers
it (each human signs their own warrant → own status ref → self-revoke at
browserid.me; owner revokes via the allowlist). The only thing (A) loses is
per-*agent-of-the-same-human* granularity, and the axis that matters there is
**owner visibility/control**, which (C)'s opaque holders can't give but (B)'s
named sub-identities can. So (A) now (correct for one-agent-per-human), (B)
when multi-agent-per-human is real. Keep the warrant status ref per-warrant
(per grantor) from day one so A→B is additive, not a re-architecture.

This decision also needs a small addition
on `browserid.me`: a **browser warrant-approval endpoint** that takes
`(audience, scopes, grantee = the gateway identity, return_url)`, runs the
existing consent UI (the user's keystore signs the warrant), and returns a
redeemable code to the gateway. Much of this exists — `/authorize` (pairing)
and `/consent` (warrant) already drive keystore-signed approvals; this is a
headless-friendly variant that returns to an arbitrary `return_url`.

## What exists vs. what's missing

**Exists:** `mcp-auth` (JS+Python) fail-closed resource-server + assertion
grant + discovery; the wallet; hosted registrar + status-list revocation;
OIDC bridge for Gmail onboarding; the whole cert/warrant/holder core.

**Missing (build list):**
1. Lane B in `mcp-auth`: discovery fields, DCR, `/authorize`, auth-code token
   grant, PKCE. *(critical path)*
2. The `browserid.me` browser warrant-approval-with-return_url endpoint that
   Lane B redirects to. *(critical path; reuses consent UI + keystore)*
3. `@browserid-ng/gate` CLI: stdio↔HTTP proxy, tool→scope auto-map, grantor
   allowlist, attribution logging.
4. Docs: tunnel recipes (`tailscale funnel`, `cloudflared`), a "share your
   notes vault" quickstart.

## Milestones

- **M1 — Lane B end to end (headless).** mcp-auth gains the auth-code lane +
  DCR; browserid.me gains the approval-return endpoint; prove it with curl:
  discover → register → authorize (approve in browser) → code → token →
  gated `tools/call`. No CLI yet.
- **M2 — the `gate` CLI.** Wrap an arbitrary stdio server; allowlist;
  tool→scope map; attribution. Wrap ONE recognizable local-data OSS server
  (filesystem or sqlite) as the dogfood.
- **M3 — the five-minute share.** Tunnel recipe + quickstart; add the server
  to claude.ai via URL; a friend on Gmail connects via the OIDC hop; their
  agent acts, attributed; revoke just them at browserid.me → next call fails
  closed. This is the wedge demo — non-abstract, on a real server.
- **M4 — second server + emergent kill switch.** Gate a second, different
  server; show one agent across both in `browserid.me/account`; kill one.
- **M5 — SaaS framing.** Write the "same middleware, bigger knobs" story +
  the OAuth-less-long-tail design-partner profile. No new code required.

## Open questions / decisions to make

- **Grantee model:** SETTLED — (A) for v1, (B) as the target, skip (C). See
  the design decision above.
- **Per-friend scopes (owner policy, NOT a warrant):** the owner wants "friend
  A read-only, friend B may post." This needs NO new BrowserID infra and NO
  cross-user warrant — it's purely gateway-side policy: generalize the
  allowlist from `{email → allowed}` to `{email → allowed scopes}`, and
  enforce at CALL time as `warrant.scopes ∩ owner.policy[grantor]`. Call-time
  (not authorize-time) because the gateway learns *which* human approved only
  after the browserid.me hop returns the warrant. The friend's warrant is a
  normal self-delegation (friend → friend's-agent); the owner's cap is local
  policy layered on top. Both consents must agree → the intersection is the
  effective scope. Configured in the gateway management UI (below).
- **Gateway management UI:** an admin-signed-in webpage to configure the
  allowlist (+ per-friend scopes) and view the attribution log. Start with
  just allowlist config; grow to logs and scopes. Rich area — own bean.
- **Refresh tokens in Lane B, or short bearers + silent re-auth?** Bearers
  already carry fail-closed status re-checks; refresh adds a rotation
  surface. *(lean: short bearers, re-run /authorize silently when the host
  supports it; revisit if hosts demand refresh.)*
- **Where the gateway's own identity lives** (Option A): a machine-local
  provisioned credential, re-provisionable. *(reuse the wallet's ~/.browserid
  credential store shape.)*
- **Scope grammar for wrapped tools:** `tool:<name>` by default; allow a
  config map for coarser groupings later. *(start literal per-tool.)*
- **Multi-user gateway state** (allowlist, per-grantor bearers): in-memory
  for v1, pluggable store for the SaaS lane (mcp-auth already has a
  BearerStore interface).

## Non-goals (gravity wells)

- No relay/tunnel of our own — document existing ones.
- No new RP login adapters (strategic drift; "Sign in with BrowserID" is
  Persona's losing game).
- No new toy resource servers to demo the mechanism — wrap real ones.
- Not chasing mature-SaaS-with-good-OAuth as the wedge; the wedge is the
  OAuth-less long tail and the hobbyist. Mature SaaS is pulled later by the
  org-governance story (managed identities), not by plumbing.
