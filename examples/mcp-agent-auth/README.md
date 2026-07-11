# MCP agent auth — a browserid-ng reference integration

An [MCP](https://modelcontextprotocol.io) server whose tools require the caller
to be an **agent with a browserid-ng identity and a human-signed warrant**. When
an agent calls a tool, the server verifies its assertion and learns three things:

- **who the agent is** (`researcher@browserid.me`),
- **who it acts for** (`alice@acme.com`, its human principal), and
- **what that human authorized here** (the scopes Alice signed for *this* server).

Each tool is gated on the right scope. The human approved a warrant naming this
server and these scopes — and can revoke it anytime. This is agent auth with
attribution and consent, in ~120 lines.

```
agent  ──assert(audience)──▶  MCP tool call  ──▶  server verifies via /verify
                                                    ├─ agent identity
                                                    ├─ principal (the human)
                                                    └─ scopes for THIS audience
                                                  → enforce scope → run tool
```

## Run it end-to-end (with a real agent)

**1. Create an agent identity.** At [browserid.me/agents](https://browserid.me/agents)
create an agent key and download `agent-credential.json`.

**2. Mint an assertion** for this server's audience. The agent CLI runs the
consent flow the first time (it prints a URL; your principal approves the
warrant, granting `post`/`read`):

```bash
cargo run -p browserid-agent --example agent_cli -- \
  agent-credential.json grant https://notes.mcp.example post read
cargo run -p browserid-agent --example agent_cli -- \
  agent-credential.json assert https://notes.mcp.example
# → prints:  <certificate>~<assertion>~<warrant>
```

**3. Call the MCP server** with that assertion:

```bash
npm install
SERVER_AUDIENCE=https://notes.mcp.example \
  node client.mjs --assertion "<paste the assertion>" post "hello from my agent"
# → posted (#0) by agent researcher@browserid.me, acting for alice@acme.com.

node client.mjs --assertion "<...>" list
```

By default the server verifies against the hosted `https://browserid.me/verify`.
Point `VERIFIER_URL` at your own broker's `/verify` to avoid trusting a third
party.

## Try it offline (no consent, no network)

The end-to-end test wires a real MCP client to the real server with a mock
`/verify`, and asserts the auth-gating — scope enforcement, agent requirement,
fail-closed:

```bash
npm install
npm test
```

## What to copy into your own MCP server

The whole security boundary is one helper (`server.mjs`):

```js
async function authorize(assertion, requiredScope) {
  const r = await verifier.verify(assertion, SERVER_AUDIENCE, { allowAgent: true });
  if (!r.ok) throw new Error(`authentication failed: ${r.reason}`);
  if (!r.agent) throw new Error("agents only: no warrant present");
  if (!r.agent.scopes.includes(requiredScope)) throw new Error("not authorized for " + requiredScope);
  return r; // r.email, r.agent.parent, r.agent.scopes
}
```

Notes:
- This demo passes the assertion as a **tool argument** so the check is visible
  in one file. Production would hoist auth to the transport / MCP OAuth layer and
  verify once per session — the check itself is identical.
- `SERVER_AUDIENCE` is your server's stable identifier; pin it, and it's what the
  agent targets in `assert <audience>`.
- Uses [`@browserid/verify`](../../sdk/js); see also
  [`docs/verify-quickstart.md`](../../docs/verify-quickstart.md).
