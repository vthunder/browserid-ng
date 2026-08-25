# BrowserID gate — your local MCP servers: published, shared, revocable

> Your notes, your home automation, your database: MCP servers that only work
> on your machine. One command gives each a real URL your agents can reach
> from anywhere — and that you can hand to the people you choose, by email,
> tool by tool.

```
npx @browserid-ng/gate --admin you@example.com
```

No accounts to create, no API keys anywhere — people connect as themselves, by
email.

## Why this and not a tunnel + an API key

Exposing a local server usually means a bearer token in somebody's config —
unscoped, unattributed, and revocable only by breaking everyone. Gate replaces
that with identity:

- **People, not keys** — whoever connects signs in as themselves. Nothing to
  paste, nothing to leak, nothing to rotate.
- **Per-server, per-tool** — roles decide exactly which tools each person
  gets; your partner can read your notes without being able to write them.
- **A real kill switch** — every call is logged with who made it and which
  tool they used. Cut one person off and their agent's very next call fails;
  nobody else notices.

## From laptop-only to anywhere (five minutes)

1. **Run the gateway** (one command). It provisions its own identity (approve
   one link, first run only) and prints your console URL. With
   [Tailscale Funnel](https://tailscale.com/kb/1223/funnel) it's public
   automatically at `https://your-machine.ts.net`; without it, gate runs
   locally and works with any tunnel you point at it.
2. **Add a server in the web console** (name · path · command). Sign in with
   BrowserID — only the admin email you launched with gets in. Paste the same
   command you'd put in an MCP config; gate publishes it at
   `https://<host>/<path>/mcp`.
3. **Copy the URL — or share it.** Add it to claude.ai as a connector and your
   agent has your tools everywhere. Grant a friend a role and the same URL
   works for them — as themselves, with exactly the tools you checked.

## Get it

A hundred-kilobyte npm package that runs on your own machine, built on the
open BrowserID protocol — open source (MPL-2.0), top to bottom.

- [README](https://github.com/vthunder/browserid-ng/tree/main/sdk/gate)
- [@browserid-ng/gate on npm](https://www.npmjs.com/package/@browserid-ng/gate)
- [All demos](/demos) · [llms.txt](/llms.txt)
