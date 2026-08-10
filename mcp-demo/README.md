# @browserid-ng/mcp-demo

A runnable reference **warrant-gated MCP server** built on
[`@browserid-ng/mcp-auth`](../sdk/mcp-auth) — the "stop putting PATs in your
MCP config" demo. No API keys: authority is a human's short-lived, scoped,
**revocable** BrowserID warrant, and every tool call is attributed to
"agent X on behalf of human Y".

## Endpoints

- `GET /.well-known/oauth-protected-resource` · `GET /.well-known/oauth-authorization-server` — OAuth discovery.
- `POST /token` — the embedded AS: RFC 7521 `jwt-bearer` assertion grant (a BrowserID warrant presentation in, a scoped bearer out).
- `POST /mcp` — the MCP endpoint (Streamable HTTP), bearer-gated, with a fail-closed status re-check on every call.
- `GET /` — landing · `GET /healthz` — probe.

## Tools

- `log_action` (scope `demo:write`) — record an action, attributed to the acting agent + its human.
- `read_log` — list recent attributed actions (any valid warrant).

Revoke the grant at `browserid.me/account → Authorized sites` and the next
tool call fails closed — the live "revoke kills the agent" demo.

## Run

```sh
npm install
PORT=3300 MCP_RESOURCE=http://localhost:3300 npm start
```

Config: `PORT`, `MCP_RESOURCE` (this server's public URL / the warrant
audience), `BROWSERID_BROKER` (default `https://browserid.me`). Stateless
(in-memory log); deployed at `https://mcp-demo.browserid.me`.
