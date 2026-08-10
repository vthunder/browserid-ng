# `@browserid-ng/mcp-auth` — flight-build spec

**Date:** 2026-08-10
**Bean:** browserid-ng-4w3n (epic). This is the concrete, autonomously-
buildable slice of the MCP-distribution design
(`2026-08-02-mcp-distribution-design.md`), scoped so it can be built,
tested, and deployed without mid-build human input.

**One line:** ship the reusable middleware that turns any TypeScript MCP
server into a warrant-gated resource server speaking MCP's own OAuth 2.1
flow — a 7521 token endpoint mints short-lived scoped bearers, and every
tool call re-checks the warrant's status fail-closed.

## Why this shape (vs. today)

`guestbook-mcp` today takes a `presentation` **argument on every tool
call** and forwards it to the guestbook HTTP API for verification
(`guestbook-mcp/src/mcp.mjs`). That works but isn't how MCP hosts speak:
they run OAuth 2.1, obtain a **bearer**, and send it in the
`Authorization` header. This build makes browserid ride that: the agent
exchanges a warrant presentation for a bearer once, then makes normal
bearer-authenticated tool calls; the middleware enforces scope + status.

## Architecture (thin TS over the hosted verifier)

No crypto/DNSSEC in JS — verification is delegated to the broker's hosted
verifier (which is DNSSEC-rooted, per bean 0p5f). The middleware is a thin
OAuth layer:

1. **Embedded AS — token endpoint.** `POST /token`,
   `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`,
   `assertion=<warrant presentation>`, `resource=<this server's audience>`.
   - Verify the presentation via the broker `POST /verify-access`
     (`audience` = this resource server's canonical URL; broker resolves
     issuer keys via DNSSEC + fail-closed status at exchange time).
   - Extract `grantor`, `grantee`, `holder`, `scopes`, and the returned
     `status_refs`.
   - Mint an opaque short-lived bearer (default TTL 1h, matching the
     bridge), stored server-side with the grant context **and the status
     refs** so per-call re-checks need no re-presentation.
   - Return `{access_token, token_type: "Bearer", expires_in, scope}`.
2. **Bearer validation middleware / `requireWarrant(scopes)`.** On each
   tool call: parse the `Authorization: Bearer` header, look up the grant,
   **re-check its status refs fail-closed** via broker `POST /status/check`
   (any `ok:false` ⇒ 401, treat as revoked), enforce that the tool's
   required scopes ⊆ the grant's scopes (scope→tool map), then expose
   `ctx.grantor / ctx.grantee / ctx.holder / ctx.scopes` to tool code.
   Cache status results for the list TTL (≤5 min) but never past it.
3. **OAuth discovery metadata.** Serve
   `/.well-known/oauth-protected-resource` (RS metadata → points at the AS)
   and `/.well-known/oauth-authorization-server` (AS metadata: token
   endpoint, the jwt-bearer grant, scopes-supported) so an MCP host's
   stock OAuth client discovers everything with zero browserid awareness.
4. **Scope grammar.** Reuse the bridge's `action:` / `path:` / `repo:`
   families; a `scopesForTool` map declares required scopes per tool.
5. **Attribution + revocation legibility.** `ctx` carries the full
   grantor/grantee/holder so tools log "agent X on behalf of human Y";
   a revoked warrant kills the agent **next tool call** (fail-closed
   re-check), demonstrable live.

## Deliverables (this build)

- **`sdk/mcp-auth/`** — the TypeScript package: token endpoint handler,
  `requireWarrant()` middleware, OAuth metadata handlers, bearer store
  (in-memory default + a pluggable interface), scope map, `ctx` types.
  Framework-agnostic core + a thin adapter for the MCP TypeScript SDK's
  HTTP transport (what guestbook-mcp/wallet-service already use).
- **Reference server** — retrofit `guestbook-mcp` (or a sibling minimal
  server) onto `mcp-auth`: the bearer flow end to end, same guestbook
  backend, demonstrating exchange → bearer → tool call → revoke-kills-next-
  call. Self-contained; needs no external accounts.
- **Tests** — unit (token exchange, scope enforcement, fail-closed status,
  metadata shape, bearer expiry) with the broker endpoints mocked; one
  integration test against a locally-run broker.
- **README** — the "warrant-gated tools in ten lines" quickstart.
- **Deploy** — the reference server to the id-host (dokku), verified;
  publish NO npm packages autonomously (left for a supervised release).

## Decided defaults (autonomous — documented, reversible)

- **TypeScript only** this build; Python/FastMCP is a follow-up.
- **Verification is delegated to the hosted `/verify-access`**, not
  reimplemented in JS (keeps DNSSEC as the single Rust implementation).
- **Bearer store**: in-memory reference impl behind an interface (Redis/db
  later); fine for a single-process reference server.
- **Flagship = self-contained reference server**, not GitHub — GitHub needs
  a registered OAuth app + live API credentials I don't have and is
  outward-facing, so it's a supervised follow-up, not an unattended build.

## Explicitly deferred (follow-up beans)

GitHub flagship conversion; Python/FastMCP middleware; MCPB/DXT desktop
bundle + registry publishing; the scope-conventions public registry;
per-call attestation hook for high-value actions; remote-wallet identity
portability. All noted in 4w3n.

## Port sources / references

- 7521 token endpoint (Rust, to port the logic): `~/src/browserid-bsky/
  pds-bridge/src/idp/oauth.rs`, `relay/oauth.rs`, `routes.rs`.
- Broker verifier + status endpoints: `POST /verify-access`,
  `POST /status/check` (browserid-broker `routes/device.rs`,
  `routes/status.rs`).
- Existing warrant-gated MCP server: `guestbook-mcp/src/*.mjs`.
- Scope grammar + RP token exchange: `browserid-rp` `exchange()`,
  `oauth_metadata()`.
