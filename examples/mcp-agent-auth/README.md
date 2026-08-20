# MCP agent auth — a browserid-ng reference integration

Two [MCP](https://modelcontextprotocol.io) servers that together show an AI agent
signing in **as itself**, acting for a human, within scopes the human approved:

- **wallet** — the agent's browserid-ng identity, built on
  [`@browserid-ng/agent`](../../sdk/agent): `identity`, `authorize(audience, scopes)`,
  `get_assertion(audience)`. It provisions the identity, runs the consent flow,
  and mints assertions — all in-process.
- **notes** — a target server whose tools require an agent assertion and enforce
  scope, built on [`@browserid-ng/verify`](../../sdk/js): `post_note` (needs `post`),
  `list_notes` (needs `read`).

The agent calls `wallet.authorize` → shows you a consent link → `wallet.get_assertion`
→ `notes.post_note`. The notes server verifies and learns **who acted, for whom,
and what you allowed here**. **Node-only — no Rust, no shell** — so it runs in any
MCP client, including Claude Desktop.

```
wallet.authorize ─▶ APPROVE_URL ─▶ human approves warrant (browserid.me)
wallet.get_assertion ─▶ access_cert ~ assertion ~ warrant ~ config_cert  (the bundle)
notes.post_note(assertion) ─▶ verify ─▶ agent + principal + scopes ─▶ enforce ─▶ run
```

## Run it — the agent guides the rest

The point of the demo is that **the agent does the work**: it surfaces the consent
URL, walks you through approving it, and acts as itself.

**1. Clone + install** (Node 18+; no Rust):

```bash
git clone https://github.com/vthunder/browserid-ng.git
cd browserid-ng/examples/mcp-agent-auth
npm install
```

**2. Launch an MCP client in this directory.** The committed [`.mcp.json`](./.mcp.json)
auto-registers **both** servers in **Claude Code / Cursor** — nothing to edit.
**Claude Desktop**: copy the `mcpServers` block into its config with absolute paths
to `wallet.mjs` and `server.mjs`.

**3. Paste this prompt:**

> Read `AGENT_INSTRUCTIONS.md` and follow it to post a note to the notes MCP
> server. Guide me through anything that needs me.

The agent checks its identity (guiding you to create one at
[browserid.me/agents](https://browserid.me/agents) if needed), gets your approval
for a scoped warrant, then posts as itself — and the notes server logs it *"by
agent researcher@browserid.me, acting for you."* Ask it to list notes next and it
reuses the same warrant.

By default the wallet talks to `https://browserid.me` and the notes server verifies
against `https://browserid.me/verify`. Override with `BROWSERID_BROKER` (in the
credential) / `VERIFIER_URL` to run against your own broker.

## Try it offline (no consent, no network)

`npm test` runs two end-to-end tests over the real MCP protocol, no network:

- **notes** (`test.mjs`) — a real MCP client ↔ the notes server with a mock
  `/verify`, asserting the auth-gating (scope enforcement, delegation
  attribution, fail-closed).
- **wallet** (`wallet.test.mjs`) — a real MCP client ↔ the wallet server driving
  `authorize` → `get_assertion` against a local mock broker that auto-approves,
  proving the whole agent-native flow with no shell and no Rust.

```bash
npm install
npm test
```

### Debugging the notes server by hand

`client.mjs` calls the notes server directly with an assertion (e.g. one from
`wallet.get_assertion`):

```bash
SERVER_AUDIENCE=https://notes.mcp.example \
  node client.mjs --assertion "<paste an ASSERTION>" post "hello from my agent"
```

## What to copy into your own MCP server

The whole security boundary is one helper (`server.mjs`):

```js
async function authorize(assertion, requiredScope) {
  const r = await verifier.verify(assertion, SERVER_AUDIENCE);
  if (!r.ok) throw new Error(`authentication failed: ${r.reason}`);
  if (!r.scopes.includes(requiredScope)) throw new Error("not authorized for " + requiredScope);
  return r; // r.email (attributed identity), r.grantee (actor of record), r.scopes
}
```

Authorization rests on the warrant's **scopes** — the human approved them for
exactly this audience. `r.email` is who the action is attributed to; `r.grantee`
is who acted (a named agent differs from `email`; an "as-you" agent is
indistinguishable from its owner by design, so there is no human/agent flag to
check).

Notes:
- This demo passes the assertion as a **tool argument** so the check is visible
  in one file. Production would hoist auth to the transport / MCP OAuth layer and
  verify once per session — the check itself is identical.
- `SERVER_AUDIENCE` is your server's stable identifier; pin it, and it's what the
  agent targets when it calls `wallet.authorize` / `get_assertion`.
- Uses [`@browserid-ng/verify`](../../sdk/js); see also
  [`docs/verify-quickstart.md`](../../docs/verify-quickstart.md).
