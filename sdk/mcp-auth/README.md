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

## The authorization-code lane (Lane B, optional)

Everything above is the **assertion lane**: an agent that already has a
BrowserID wallet POSTs its warrant presentation to `/token`. A *generic* OAuth
host (claude.ai, Cursor, a phone) has no wallet — it expects the ordinary
redirect dance: discover → register → open `/authorize` in a browser →
approve → code → token. `createAuthCodeLane` adds exactly that, WITHOUT
changing Lane A:

```js
import { readFileSync } from "node:fs";
import { createMcpAuth, createAuthCodeLane } from "@browserid-ng/mcp-auth";

const auth = createMcpAuth({ resource, broker, scopesForTool });
// The gateway's OWN agent identity (the wallet's ~/.browserid shape) —
// provision one with `npx -y @browserid-ng/wallet provision <name>`.
const { credential } = JSON.parse(readFileSync(`${process.env.HOME}/.browserid/agent-credential.json`));
const lane = createAuthCodeLane({ mcpAuth: auth, credential, label: "my gateway" });

// Serve (any framework; every handler is transport-agnostic):
//   GET  /.well-known/oauth-authorization-server -> lane.authorizationServerMetadata()
//   GET  /.well-known/oauth-protected-resource   -> auth.protectedResourceMetadata()
//   POST /register          -> lane.handleRegister(jsonBody)                     // RFC 7591 DCR
//   GET  /authorize         -> { redirect } = await lane.handleAuthorize(query);  // 302 redirect
//   GET  /authorize/return  -> { redirect } = await lane.handleAuthorizeReturn(query);
//   POST /token             -> lane.handleToken(body)   // auth-code + jwt-bearer
// Tool calls stay exactly as before: auth.requireWarrant(header, tool).
```

How it works: `/authorize` (PKCE **S256 required**) raises a warrant request
as the gateway agent — audience pinned to this `resource` — and sends the
browser to the broker's consent page with an **origin-validated** `return_url`
back to `/authorize/return`. The human approves (picking which of their
identities delegates); the browser bounces back; the lane picks up the
approved `warrant~config_cert` and mints a **single-use, ~60s** OAuth code
bound to `client_id` + `redirect_uri` + the PKCE challenge. `/token` verifies
all of that, mints a presentation with the gateway's DeviceAgent, and feeds it
through the SAME `/verify-access` + bearer mint as Lane A — so revocation and
per-call fail-closed status checks are identical across both lanes.

`@browserid-ng/agent` is loaded lazily — Lane-A-only users never pull it in.

### curl walkthrough (local broker)

```sh
# 0. A broker on localhost:3000 with an account, and a provisioned gateway
#    identity (approve the printed link in your browser):
BROWSERID_BROKER=http://localhost:3000 npx -y @browserid-ng/wallet provision gate

# 1. Run your lane-enabled server, e.g. resource http://localhost:8787, then:
curl -s http://localhost:8787/.well-known/oauth-authorization-server | jq

# 2. Register a client (what an MCP host does automatically):
CLIENT=$(curl -s -X POST http://localhost:8787/register \
  -H 'content-type: application/json' \
  -d '{"redirect_uris":["http://localhost:9999/cb"],"client_name":"curl"}')
CLIENT_ID=$(echo "$CLIENT" | jq -r .client_id)

# 3. PKCE pair:
VERIFIER=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=\n')

# 4. Authorize — follow the 302 to the consent page IN A BROWSER and approve;
#    the browser lands back on /authorize/return and then on your
#    redirect_uri with ?code=…&state=…:
open "http://localhost:8787/authorize?response_type=code&client_id=$CLIENT_ID\
&redirect_uri=http://localhost:9999/cb&code_challenge=$CHALLENGE\
&code_challenge_method=S256&scope=notes:read&state=xyz"

# 5. Exchange the code (from the redirect) within its ~60s TTL:
curl -s -X POST http://localhost:8787/token \
  -d "grant_type=authorization_code&code=$CODE&client_id=$CLIENT_ID\
&redirect_uri=http://localhost:9999/cb&code_verifier=$VERIFIER" | jq
# -> { "access_token": "bat_…", … } — the same bearer Lane A mints.

# 6. Call a gated tool with it; revoke at the broker's /account page and the
#    next call fails closed.
```

## API

- `createMcpAuth(opts) -> auth` — `opts`: `resource` (required), `broker`
  (default `https://browserid.me`), `scopesForTool`, `tokenTtlS` (3600),
  `statusCacheS` (60), `acceptedFallbacks`, `store`, `fetch`.
- `auth.handleToken(params)` — redeem a presentation for a bearer.
- `auth.redeemPresentation(presentation, scope?)` — the shared verify+mint
  both grants terminate in.
- `auth.authenticate(header)` — validate a bearer, re-check status, return ctx.
- `auth.requireWarrant(header, toolNameOrScopes)` — authenticate + enforce scopes.
- `auth.protectedResourceMetadata()` / `auth.authorizationServerMetadata()`.
- `auth.challenge()` — `WWW-Authenticate` value.
- `createMemoryStore()` — the default bearer store (swap for Redis/db in prod).
- `createAuthCodeLane({ mcpAuth, credential, broker?, fetch?, label?,
  codeTtlS?, pendingTtlS? }) -> lane` — the optional authorization-code lane:
  `lane.authorizationServerMetadata()`, `lane.handleRegister(body)`,
  `lane.handleAuthorize(query)`, `lane.handleAuthorizeReturn(query)`,
  `lane.handleToken(params)`.
- `verifyPkceS256(verifier, challenge)` — RFC 7636 S256 check.

MPL-2.0.
