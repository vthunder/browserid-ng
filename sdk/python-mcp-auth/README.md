# browserid-mcp-auth (Python)

Warrant-gated MCP tools over MCP's own OAuth 2.1 — the Python port of
`@browserid-ng/mcp-auth`. **No API keys**: an agent redeems its human's
short-lived, scoped, **revocable** BrowserID warrant for a bearer, and every
tool call is attributable to "agent X on behalf of human Y". Revoke at
`browserid.me/account` and the agent dies on its next call.

An embedded authorization server (the RFC 7521 `jwt-bearer` assertion grant) +
a resource-server guard that re-checks the warrant's revocation status
**fail-closed on every call**. Verification is delegated to the broker's
DNSSEC-rooted hosted verifier (`POST /verify`) and `POST /status/check`
— no crypto in Python. Stdlib-only (no runtime deps).

## Use

```python
from browserid_mcp_auth import McpAuth, McpAuthError

auth = McpAuth(
    resource="https://mcp.example.com",           # this server (OAuth resource + audience)
    scopes_for_tool={"create_issue": ["issues:create"]},
)

# 1. Discovery (serve as JSON):
#    GET /.well-known/oauth-protected-resource   -> auth.protected_resource_metadata()
#    GET /.well-known/oauth-authorization-server  -> auth.authorization_server_metadata()

# 2. Token endpoint (the embedded AS):
#    POST /token  ->  auth.handle_token(request_body)   # {grant_type, assertion, scope?}

# 3. Gate a tool call:
ctx = auth.require_warrant(authorization_header, "create_issue")
# ctx.grantor (human), ctx.grantee (agent), ctx.holder, ctx.issuer, ctx.scopes
```

On failure `handle_token` / `require_warrant` raise `McpAuthError` with
`.oauth_error` and `.http_status`; render `err.to_token_error_response()` at the
token endpoint and `auth.challenge()` in the `WWW-Authenticate` header on a 401.

## FastMCP

FastMCP servers speak MCP OAuth; mount the three surfaces above on the server's
HTTP app (the token endpoint + the two discovery routes), and call
`auth.require_warrant(request.headers.get("authorization"), tool_name)` at the
top of each tool. The core is synchronous and dependency-free; call it directly
or wrap in a thread from async handlers. `http_post` is injectable if you
prefer `httpx`/`requests` over the stdlib `urllib` default.

## API

`McpAuth(resource, broker="https://browserid.me", scopes_for_tool=None,
token_ttl_s=3600, status_cache_s=60, accepted_fallbacks=None, store=None,
http_post=None)`; `handle_token(params)`, `authenticate(header)`,
`require_warrant(header, tool_or_scopes)`, `protected_resource_metadata()`,
`authorization_server_metadata()`, `challenge()`. MPL-2.0.
