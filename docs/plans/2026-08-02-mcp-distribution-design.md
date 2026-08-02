# MCP as the distribution vector — design plan

**Date:** 2026-08-02
**Status:** design sketch, first epic scoped. Companion to
`2026-08-02-roadmap-directions.md` (Theme 2). Prior art in-tree: the wallet
MCP server (`@browserid-ng/wallet`), the bsky bridge's RFC 7521 token
endpoint (`/browserid/token`), the guestbook's warrant-gated tools, and the
scope grammar (`action:`, `path:`, `repo:`) the bridge enforces.

**One line:** make browserid the identity layer MCP hosts already speak —
per-human, per-agent, scoped, revocable authority for tool calls — by
riding MCP's own OAuth model instead of proposing a new one.

## The unlock: MCP's OAuth spec is already compatible

MCP standardized remote-server auth on OAuth 2.1: hosts obtain a bearer
token from an authorization server (AS) and present it to the MCP server
(resource server). The bsky bridge already implements the adapter between
that world and ours: **an RFC 7521 assertion grant** — POST a browserid
warrant presentation to a token endpoint, get a scoped bearer back.

So the architecture is: each MCP server ships with a tiny AS whose only
grant type is the 7521 browserid exchange. Hosts run their existing MCP
OAuth machinery unmodified and never need to know browserid exists; the
wallet performs the exchange; the warrant's scopes flow through as OAuth
scopes enforced per tool call.

## Authority vs. redemption (why per-server ASes don't fragment anything)

The design rests on a separation the protocol already enforces:

- **Minting authority** happens exactly once, at the approval hop: only the
  user's config cert can sign a warrant, and that signature happens at
  their ISSUER's account surface (browserid.me/account for fallback
  identities; a primary's own surface otherwise). The issuer therefore
  knows every grant it brokered, lists it (Authorized sites), and stamps
  each warrant with a `status` ref into the issuer-published status list
  (core §6.4).
- **Redeeming authority** is all an AS does: verify the presentation —
  signature chain, audience, expiry, **and the status ref, fail-closed** —
  then issue a short-lived bearer. The bsky bridge is the reference
  implementation (TOKEN_TTL ~1h, warrant status re-checked on every
  action, not just at exchange).

Consequences:

- **Revocation stays centralized-per-issuer no matter how many ASes
  exist.** Revoke at browserid.me/account flips a bit on browserid.me's
  status list; every AS in the world consults that list and fails closed.
  A thousand independent MCP-server ASes share one revocation surface per
  issuer, by construction.
- **Revocation latency** = min(status-list cache TTL, per-action re-check
  cadence), bounded by bearer TTL as the backstop. Status lists cache for
  5 minutes; the middleware makes per-tool-call status checks the
  non-optional default, so revoke lands next-call to minutes — never
  "until the token expires" alone.
- The issuer UI shows grants *it* brokered. Users on their own primary see
  their grants at their primary — correct decentralized behavior, not a
  gap.

## The first epic: adapter + middleware + flagship (one artifact, really)

### 1. `@browserid-ng/mcp-auth` — warrant-gated tools in ten lines

Middleware for the dominant MCP server frameworks (TypeScript SDK first,
FastMCP/Python second) providing:

- the 7521 token endpoint (the embedded AS), ported from the bridge;
- per-call bearer validation with fail-closed status checks;
- scope→tool/path mapping using the existing grammar;
- `ctx.grantor` / `ctx.grantee` / `ctx.holder` exposed to tool code, so
  every action is attributable to "agent X on behalf of human Y";
- optional per-call attestation hook for high-value actions (the
  attested-post pattern), where a bearer alone isn't enough.

### 2. The killer demo: "stop putting PATs in your MCP config"

Today an MCP server holds a long-lived API key in env/config — the agent
*effectively owns the credential*: unscoped, unattributed, revocable only
by rotating the key everywhere. Convert one flagship OSS server (GitHub is
the obvious target) to warrant-gated: `repo:read` + `issues:create` on
your behalf, every action attributed, revocation one click with no key
rotation — and demonstrate the revoke killing the agent mid-conversation.
This contrast is the most legible security argument the project has, aimed
at exactly the audience that installs MCP servers.

### 3. Wallet distribution mechanics

- Package the local wallet everywhere: MCP registries, an MCPB/DXT bundle
  for one-click desktop install, Docker MCP catalog. It already shares
  `~/.browserid` with the CLI — one identity per machine, every host.
- The claude.ai remote-wallet connector is the template for
  remote-only hosts; the open design question is identity portability
  across devices (the holder model — per-browser holders — is the right
  substrate; needs a small design note of its own).
- Approval stays out-of-band by design (an agent must never approve its
  own warrant), but the hop can get slicker: the wallet knows a request is
  pending, so a push notification deep-linking into /account cuts the
  clunkiest step.

### 4. Scope conventions registry

A small public registry documenting scope families (`repo:`, `path:`,
`action:` — per service) so approval cards render legibly: "create issues
on repo X, nothing else." Cheap, compounding, and the seed of the spec
work in Theme 4.

### Later, from strength: spec-community engagement

Take working code to the MCP spec community — the grant type, the
middleware, the flagship server, and a live revocation demo — as an
implementation of their existing OAuth flow, not a proposal to change it.

## Open questions

1. **AS placement** — decided above as in-middleware (every server its own
   AS; keeps the decentralization story clean). The alternative (a hosted
   AS at browserid.me for servers that want zero AS code) could be offered
   *additionally* later; it re-centralizes redemption but not authority,
   so it's a convenience trade, not a security one.
2. **Bearer TTL vs. per-call verification** — the middleware defaults to
   short bearers + per-call status checks; is there a class of
   high-frequency tools where the status-check cost matters? (Status lists
   are cached; likely no. Measure in the flagship.)
3. **Scope negotiation UX** — when a host requests a server's tools, who
   proposes the scope set the wallet asks the human to approve? Likely the
   server's metadata advertises required-scopes-per-tool and the wallet
   composes the minimal ask.
4. **Identity portability across devices** for the remote wallet — needs
   its own small design (holder model).
