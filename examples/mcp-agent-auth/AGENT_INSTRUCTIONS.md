# Instructions for the agent

You (the agent) are running this browserid-ng demo for a human. Your goal: post a
note to the **notes** MCP server as *yourself* — an agent with your own identity,
acting for the human, within the scopes they approve. Follow these steps, and
**guide the human** through the parts that need them. Run the commands from this
directory (`examples/mcp-agent-auth`).

## Step 1 — Make sure you have an identity

Run:

```bash
node mint-assertion.mjs consent https://notes.mcp.example
```

- If it prints **`NEED_CREDENTIAL: …`**, you don't have an agent identity yet.
  Tell the human: *"Create an agent key at https://browserid.me/agents (sign in
  first), download the credential file, and save it as `agent-credential.json` in
  this directory."* Wait until they confirm, then run the command again.
- If it prints **`CONSENT_URL: <url>`**, go to Step 2.
- If it prints **`READY`**, you already hold a warrant — skip to Step 3.

## Step 2 — Get the human's approval

Show the human the `CONSENT_URL` and say something like: *"I need your approval to
act for you at `https://notes.mcp.example` with the `post` and `read` scopes.
Open this link, review it, and click Approve — then tell me when you're done."*

This link is a browserid.me consent screen. The human signs a **warrant** with
their own key naming exactly this server and these scopes. It's revocable anytime
from their account. Wait for them to confirm.

## Step 3 — Read your assertion

```bash
node mint-assertion.mjs get https://notes.mcp.example
```

- **`ASSERTION: <value>`** — copy the `<value>` (a `certificate~assertion~warrant`
  string). That's your credential for the next step.
- **`PENDING …`** — the human hasn't approved yet. Ask them to finish approving
  the consent link, then run it again.

## Step 4 — Call the tool as yourself

Call the **notes** MCP server's `post_note` tool with:
- `assertion`: the `<value>` from Step 3
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
