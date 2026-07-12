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

## Run it — from an agent, by pasting a prompt

The point of the demo is that **the agent does the work**: it surfaces the
consent URL, waits for you to approve, and calls the tool as itself. You just
paste a prompt.

### One-time setup

1. **Agent identity.** At [browserid.me/agents](https://browserid.me/agents)
   create an agent key and save `agent-credential.json` in this directory.
2. `npm install`
3. **Register the notes server** with an MCP-capable, shell-capable agent
   (Claude Code, Cursor, Claude Desktop…). For Claude Code, `.mcp.json`:

   ```json
   {
     "mcpServers": {
       "notes": {
         "command": "node",
         "args": ["/ABS/PATH/examples/mcp-agent-auth/server.mjs"],
         "env": { "SERVER_AUDIENCE": "https://notes.mcp.example" }
       }
     }
   }
   ```
4. Tell the assertion helper where your credential is (default shown):

   ```bash
   export AGENT_CLI="cargo run -q -p browserid-agent --example agent_cli -- ./agent-credential.json"
   ```

### Then paste this to your agent

> Post a note saying **"hello from my agent"** to the **notes** MCP server.
> It needs a browserid-ng assertion for the audience `https://notes.mcp.example`. To get one:
> 1. Run `node examples/mcp-agent-auth/mint-assertion.mjs consent https://notes.mcp.example`.
>    It prints `CONSENT_URL: …` — **show me that link and wait** until I say I've approved it.
> 2. Then run `node examples/mcp-agent-auth/mint-assertion.mjs get https://notes.mcp.example`
>    to read the `ASSERTION:` value (retry once if it says PENDING).
> 3. Call the notes server's `post_note` tool with that assertion and the text.

What happens: the agent shows you a browserid.me consent URL; you approve a
warrant naming *this server* and the `post`/`read` scopes; the agent reads back
its assertion and calls `post_note` — and the server logs the note as
*"by agent researcher@browserid.me, acting for you."* Ask it to `list_notes`
next and it reuses the same warrant.

By default the server verifies against the hosted `https://browserid.me/verify`;
set `VERIFIER_URL` on the server to point at your own broker instead.

### Without an agent (manual, for debugging)

`mint-assertion.mjs` and `client.mjs` are just thin wrappers you can run by hand:

```bash
node mint-assertion.mjs consent https://notes.mcp.example   # → CONSENT_URL (approve it)
node mint-assertion.mjs get     https://notes.mcp.example   # → ASSERTION: <...>
SERVER_AUDIENCE=https://notes.mcp.example \
  node client.mjs --assertion "<paste ASSERTION>" post "hello from my agent"
```

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
