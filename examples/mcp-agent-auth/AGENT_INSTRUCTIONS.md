# Instructions for the agent

You (the agent) are running this browserid-ng demo for a human. Your goal: post a
note to the **notes** MCP server as *yourself* — an agent with your own identity,
acting for the human, within scopes they approve.

You have two MCP servers available: **wallet** (your browserid-ng identity) and
**notes** (the target). The whole flow is MCP tool calls — no shell needed.
**Guide the human** through the parts that need them.

## Step 1 — Check your identity

Call the **wallet** server's **`identity`** tool.

- **"Acting as `<name>@…`"** — good. Tell the human who you'll act as, continue.
- **`NEED_CREDENTIAL: …`** — you have no identity yet. Tell the human: *"Create an
  agent key at https://browserid.me/agents (sign in first), download the file, and
  save it as `agent-credential.json` in this directory."* When they confirm, call
  `identity` again.
- **`AMBIGUOUS_NAME: …`** — the credential reserves several names. Ask the human
  which one, then they restart the wallet server with `AGENT_NAME=<that>` set.

## Step 2 — Request access

Call **wallet** `authorize` with `audience: "https://notes.mcp.example"` and
`scopes: ["post","read"]`.

- **`APPROVE_URL: <url>`** — show the human that link and say: *"Approve this to
  let me post and read on your behalf at that server — then tell me when done."*
  It's a browserid.me consent screen; they sign a warrant with their own key,
  revocable anytime.
- **`READY — already authorized`** — skip to Step 3.

## Step 3 — Get your assertion

Call **wallet** `get_assertion` with the same `audience`.

- **`ASSERTION: <value>`** — copy `<value>`; it's your credential for Step 4.
- **`PENDING — not approved yet`** — remind the human to approve the link, then
  call `get_assertion` again.

## Step 4 — Act, as yourself

Call the **notes** server's **`post_note`** tool with:
- `assertion`: the `<value>` from Step 3
- `text`: what the human asked you to post (default `"hello from my agent"`)

The notes server verifies your assertion and confirms the note was posted **by
your agent identity, acting for the human** — attributable by construction. Show
the human that confirmation. Then call **notes** `list_notes` (with the same
assertion) to show the `read` scope working too.

## What you just demonstrated

- You signed in with **your own** identity — never the human's password.
- The human approved **one** warrant, scoped to **one** server and **specific**
  actions, and can revoke it anytime.
- The server knows exactly **who acted** and **for whom** — attributable by
  construction.
