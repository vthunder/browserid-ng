# @browserid-ng/mcp-auth

Warrant-gated MCP tools over MCP's own OAuth 2.1 — **no API keys**. An agent
redeems its human's short-lived, scoped, **revocable** BrowserID warrant for a
bearer, and every tool call is attributable to "agent X on behalf of human Y".
Revoke at `browserid.me/account` and the agent dies on its next call.

Hosts run their existing MCP OAuth client unmodified and never learn BrowserID
exists: the middleware embeds a tiny **authorization server** whose only grant
type is the RFC 7521 `jwt-bearer` assertion grant (a BrowserID warrant
presentation in, a bearer out), plus a **resource-server** guard that
re-checks the warrant's revocation status **fail-closed on every call**.

Verification is delegated to the broker's DNSSEC-rooted hosted verifier
(`POST /verify-access`) and `POST /status/check` — no crypto in JS.

## Warrant-gated tools in ten lines

```js
import { createMcpAuth, McpAuthError } from "@browserid-ng/mcp-auth";

const auth = createMcpAuth({
  resource: "https://mcp.example.com",          // this server (OAuth resource + audience)
  scopesForTool: { create_issue: ["issues:create"] },
});

// 1. Serve discovery so the host's OAuth client finds the AS:
//    GET /.well-known/oauth-protected-resource   -> auth.protectedResourceMetadata()
//    GET /.well-known/oauth-authorization-server  -> auth.authorizationServerMetadata()

// 2. The token endpoint (the embedded AS):
//    POST /token  ->  auth.handleToken(body)     // body = {grant_type, assertion, scope?}

// 3. Gate a tool call (per-call fail-closed status re-check + scope enforcement):
const ctx = await auth.requireWarrant(req.headers.authorization, "create_issue");
// ctx = { grantor, grantee, holder, issuer, scopes } — attribute every action.
```

On any failure `requireWarrant` / `handleToken` throw `McpAuthError` with an
`oauthError` code and `httpStatus`; render `err.toTokenErrorResponse()` at the
token endpoint and `auth.challenge()` in the `WWW-Authenticate` header on a 401.

## Why this shape

- **Revocation stays at the registrar.** Any number of independent MCP-server
  ASes share ONE revocation surface — the human's `browserid.me/account`.
  Every AS consults the same status list and fails closed.
- **Attribution is intrinsic.** `ctx.grantor` (human) and `ctx.grantee` (agent)
  come from the warrant, so tools log who really acted.
- **Least privilege.** The warrant's scopes are the ceiling; a requested
  `scope` may narrow but never widen them, and each tool declares what it needs.

See `mcp-demo/` for a runnable reference server, and
`docs/plans/2026-08-10-mcp-auth-flight-build-spec.md` for the design.

## API

- `createMcpAuth(opts) -> auth` — `opts`: `resource` (required), `broker`
  (default `https://browserid.me`), `scopesForTool`, `tokenTtlS` (3600),
  `statusCacheS` (60), `acceptedFallbacks`, `store`, `fetch`.
- `auth.handleToken(params)` — redeem a presentation for a bearer.
- `auth.authenticate(header)` — validate a bearer, re-check status, return ctx.
- `auth.requireWarrant(header, toolNameOrScopes)` — authenticate + enforce scopes.
- `auth.protectedResourceMetadata()` / `auth.authorizationServerMetadata()`.
- `auth.challenge()` — `WWW-Authenticate` value.
- `createMemoryStore()` — the default bearer store (swap for Redis/db in prod).

MPL-2.0.
