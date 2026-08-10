# browserid FastMCP demo (Python)

The Python parallel of [`mcp-demo`](../mcp-demo): a runnable, warrant-gated
**FastMCP** server on [`browserid-mcp-auth`](../sdk/python-mcp-auth). No API
keys — authority is a human's short-lived, scoped, **revocable** BrowserID
warrant, and every tool call is attributed to "agent X on behalf of human Y".
Revoke at `browserid.me/account` and the agent dies on its next call.

## Surfaces
- `POST /token` — the embedded AS (RFC 7521 jwt-bearer assertion grant).
- `GET /.well-known/oauth-protected-resource` · `/.well-known/oauth-authorization-server` — discovery.
- the FastMCP endpoint (`/mcp`) — tool calls gated per-call by the warrant (fail-closed status re-check).
- `GET /` landing · `GET /healthz` probe.

## Tools
`log_action` (scope `demo:write`), `read_log`.

## Run
```sh
pip install -r requirements.txt ../sdk/python-mcp-auth
PORT=3400 MCP_RESOURCE=http://localhost:3400 python server.py
```
Config: `PORT`, `MCP_RESOURCE`, `BROWSERID_BROKER` (default `https://browserid.me`).
`python test_integration.py` runs a token→bearer→tool-call smoke test.
Deployed at `https://python-mcp-demo.browserid.me`.
