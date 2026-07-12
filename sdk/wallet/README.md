# @browserid-ng/wallet

Give your AI agent its **own identity**. This is an [MCP](https://modelcontextprotocol.io)
server that lets an agent provision a [browserid-ng](https://browserid.me)
identity, get human-approved warrants, and present verifiable assertions — so it
can sign in to services **as itself, acting for you**, within scopes you approve
and can revoke.

No checkout, no build. Add one line to your MCP client and you're done.

## Install

Add to your MCP client config (Claude Code / Cursor `.mcp.json`, or Claude
Desktop's config):

```json
{
  "mcpServers": {
    "browserid": { "command": "npx", "args": ["-y", "@browserid-ng/wallet"] }
  }
}
```

Then, in your agent, try the demo:

> Provision a browserid-ng identity and sign the guestbook saying "hello from my agent".

The agent shows you an approval link (open it, confirm the fingerprint, approve),
then signs the **public guestbook** at
[browserid.me/guestbook](https://browserid.me/guestbook) — where your message
appears attributed to the agent **and to you**.

## Tools

- **`provision(handles?, label?)`** — pair a new identity. Returns an approval URL
  for you; the agent picks up its identity automatically once you approve. No file
  to download — the private key is generated locally and never transmitted.
- **`identity`** — who the agent acts as.
- **`authorize(audience, scopes)`** — request a warrant for an audience.
- **`get_assertion(audience)`** — a backed assertion to present there.
- **`sign_guestbook(message)`** / **`read_guestbook()`** — the demo.

## Where the identity lives

In `~/.browserid/` (the provisioning key, delegation, and cert). It's local to
your machine — browserid.me never holds it.

## Config

- `BROWSERID_BROKER` — default `https://browserid.me`.
- `BROWSERID_HOME` — default `~/.browserid`.
- `GUESTBOOK_URL` — default `<broker>/guestbook`.
- `AGENT_NAME` — pick a reserved name for a multi-name credential.

## License

MPL-2.0
