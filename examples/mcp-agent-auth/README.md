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

## Run it — the agent guides the rest

The point of the demo is that **the agent does the work**: it surfaces the
consent URL, walks you through approving it, and calls the tool as itself.

**1. Clone + install.** (Needs Node 18+, and Rust for the agent CLI.)

```bash
git clone https://github.com/vthunder/browserid-ng.git
cd browserid-ng/examples/mcp-agent-auth
npm install
```

**2. Point your agent at the notes server.** A ready [`.mcp.json`](./.mcp.json)
lives here, so **Claude Code / Cursor auto-register it** when you launch in this
directory — nothing to edit. (Claude Desktop: copy the `mcpServers` block into
its config, using an absolute path to `server.mjs`.)

**3. Run your agent in this directory and paste:**

> Read `AGENT_INSTRUCTIONS.md` and follow it to post a note to the notes MCP
> server. Guide me through anything that needs me.

That's it. The agent will check whether you have an agent identity (and if not,
walk you through creating one at [browserid.me/agents](https://browserid.me/agents)),
show you a consent link to approve a warrant for this server, then call
`post_note` as itself — and the server logs the note *"by agent
researcher@browserid.me, acting for you."* Ask it to list notes next and it
reuses the same warrant.

By default the server verifies against the hosted `https://browserid.me/verify`;
set `VERIFIER_URL` on the server to point at your own broker instead.

### Under the hood / debugging by hand

The agent just runs these — you can too. No env vars: the helper finds your
credential (`agent-credential.json` here) and the CLI on its own, requests the
`post`/`read` scopes, and `get` waits for you to approve.

```bash
node mint-assertion.mjs consent https://notes.mcp.example   # → CONSENT_URL (approve it)
node mint-assertion.mjs get     https://notes.mcp.example   # → ASSERTION: <...> (polls until approved)
SERVER_AUDIENCE=https://notes.mcp.example \
  node client.mjs --assertion "<paste ASSERTION>" post "hello from my agent"
```

`consent` takes optional scopes (`… consent <aud> post read`, the default). For a
credential that reserves several fixed names, set `AGENT_NAME=<reserved-name>`.

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
