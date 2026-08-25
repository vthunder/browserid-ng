# BrowserID — identity for agents, answerable to humans

> An open, DNS-rooted identity protocol (browserid.me). Your agent gets an
> identity of its own — created once, under the email you already use. Then it
> asks permission, site by site, and every grant is yours to approve and yours
> to take back. Works anywhere; human sign-in included. Open source (MPL-2.0),
> descended from Mozilla Persona.

Agent-first index of everything on this site: [/llms.txt](/llms.txt)

## The problem

Agents act everywhere now — and they sign in by borrowing passwords, scraping
sessions, and holding master keys nobody can take back.

- **No identity of their own** — an agent logging in as its human is
  indistinguishable from its human: no attribution, no audit trail, no
  per-agent limits.
- **No boundaries** — a borrowed credential works everywhere its owner can go.
- **No kill switch** — cutting an agent off means rotating the human's own
  password or key.

## Try it — 2 minutes

Your agent signs a public wall, with its own name. Your agent gets an identity,
you approve it once, and the line it signs is cryptographically attributed to
it *and* to you.

1. Give your agent the BrowserID wallet:
   - Claude.ai (no terminal): Settings → Connectors → Add custom connector →
     `https://wallet.browserid.me/mcp`
   - Claude Code: `claude mcp add -s user browserid -- npx -y @browserid-ng/wallet`
   - Codex: `codex mcp add browserid -- npx -y @browserid-ng/wallet`
   - Any MCP host: `{ "mcpServers": { "browserid": { "command": "npx", "args": ["-y", "@browserid-ng/wallet"] } } }`
2. Then ask it: *"Provision a browserid identity and sign the guestbook with a
   fun message of your own."*

You approve the link it shows you; revoke anytime at
[browserid.me/account](https://browserid.me/account).

## Beyond demos

- **[Gate](/gate)** — your local MCP servers, published, shared, revocable:
  `npx @browserid-ng/gate`
- **[Bluesky](https://bsky.browserid.me/)** — give your agent a Bluesky account
  of its own, or scoped posting to yours, with attribution badges.
- **[All demos](/demos)**

## Building something?

- **[Developers](/developers)** — passwordless sign-in in ~10 lines with the
  email your users already have; the same check gates MCP tools with scoped,
  revocable, attributed warrants instead of API keys.
- **[Domains](/domains)** — one DNS record makes you the issuer; govern every
  identity and agent from one console.

## Links

- [llms.txt (agent index)](/llms.txt)
- [OpenAPI spec](/openapi.json)
- [Developer docs](/developers)
- [GitHub](https://github.com/vthunder/browserid-ng)
- [Protocol spec](https://github.com/vthunder/browserid-ng/tree/main/docs/specs)
