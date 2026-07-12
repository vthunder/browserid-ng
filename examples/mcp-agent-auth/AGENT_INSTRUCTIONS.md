# Instructions for the agent

You (the agent) are running this browserid-ng demo for a human. Your goal: post a
note to the **notes** MCP server as *yourself* — an agent with your own identity,
acting for the human, within the scopes they approve. Follow these steps, and
**guide the human** through the parts that need them. Run the commands from this
directory (`examples/mcp-agent-auth`).

## Step 1 — Know who you'll act as

First, check your identity (this reads the credential; it never asks the human to
guess a name):

```bash
node mint-assertion.mjs whoami
```

- **`NEED_CREDENTIAL: …`** — you have no agent identity yet. Tell the human:
  *"Create an agent key at https://browserid.me/agents (sign in first), download
  the credential file, and save it as `agent-credential.json` in this directory."*
  When they confirm, run `whoami` again.
- **`provisions as: <name>@…`** — a single identity. Tell the human *"I'll act as
  `<name>@…`"* and continue to Step 2.
- **`provisions as: <name>@… (auto-generated under a pattern)`** — a fresh random
  identity will be created under that pattern. Mention that, and continue.
- **`reserved names: a, b, c … pass it explicitly`** — the credential reserves
  several identities. **Ask the human which one to use** (suggest the first if
  they have no preference), then set `AGENT_NAME=<their choice>` for the next
  commands.

## Step 2 — Request access

```bash
node mint-assertion.mjs consent https://notes.mcp.example
# (prefix with AGENT_NAME=<name> if Step 1 said to pick one)
```

This asks the human to grant you the `post` and `read` scopes at this server.

- **`CONSENT_URL: <url>`** — a warrant needs approval. Go to Step 3.
- **`READY`** — you already hold a warrant covering these scopes. Skip to Step 4.
- Any **`ERROR: …`** — show it to the human; it's the real cause.

## Step 3 — Get the human's approval

Show the human the `CONSENT_URL` and say something like: *"I need your approval to
act for you at `https://notes.mcp.example` with the `post` and `read` scopes.
Open this link, review it, and click Approve — then tell me when you're done."*

This link is a browserid.me consent screen. The human signs a **warrant** with
their own key naming exactly this server and these scopes. It's revocable anytime
from their account.

## Step 4 — Read your assertion

```bash
node mint-assertion.mjs get https://notes.mcp.example
```

This **waits** (polls up to ~2½ minutes) for the human to approve, so you can run
it right after showing the link.

- **`ASSERTION: <value>`** — copy the `<value>` (a `certificate~assertion~warrant`
  string). That's your credential for the next step.
- **`PENDING …`** — still not approved. Remind the human to finish approving the
  link, then run `get` again.
- **`ERROR: …`** — show it to the human.

## Step 5 — Call the tool as yourself

Call the **notes** MCP server's `post_note` tool with:
- `assertion`: the `<value>` from Step 4
- `text`: what the human asked you to post (default: `"hello from my agent"`)

The server verifies your assertion and replies confirming the note was posted
**by your agent identity, acting for the human** — every action attributable to
them. Show the human that confirmation.

Then, to show scopes at work, call `list_notes` with the same assertion (it needs
the `read` scope, which the same warrant granted).

## What you just demonstrated

- You signed in with **your own** identity — never the human's password.
- The human approved **one** warrant, scoped to **one** server and **specific**
  actions, and can revoke it anytime.
- The server knows exactly **who acted** and **for whom** — attributable by
  construction.
