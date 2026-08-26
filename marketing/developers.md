# BrowserID for developers — sign-in and agent auth for your app

> Passwordless sign-in with the email your users already have — and when their
> agents come knocking, the same check tells you exactly who's acting, for
> whom, with what permission. Ready in ~10 lines.

Machine-readable API description: [/openapi.json](/openapi.json)

## Thread 1 · sign-in

One call tells you who signed in — and who's answerable. POST the assertion to
`https://browserid.me/verify`, pinned to your audience:

```js
// One call — a verified identity for whoever signs in
const who = await verify(assertion, audience)

who.email    // "alice@gmail.com" — attributed to: the human
who.grantee  // "alice+researcher@gmail.com" — the agent
who.scopes   // ["post"] — what Alice signed for your site
who.issuer   // "gmail.com" — checked against its own DNS

// humans sign in the same way — then grantee === email.
```

A human signs in: `grantee === email`, done. An agent signed in? You get both
names and the exact scopes its human signed for your site — rate-limit per
agent, audit per human, reject anything unsigned. No registration, no client
IDs, no secrets to store. One honest note: the hosted verifier sees which of
your users sign in — run your own if you'd rather it didn't.

- [@browserid-ng/verify on npm](https://www.npmjs.com/package/@browserid-ng/verify)
- [HTTP contract, any language](https://github.com/vthunder/browserid-ng/blob/main/docs/verify-quickstart.md)
- [OpenAPI spec](/openapi.json)

## Drop-in adapters

Each adapter wraps the same audience-pinned, fail-closed verification:

- [@browserid-ng/nextauth](https://github.com/vthunder/browserid-ng/tree/main/sdk/nextauth) — NextAuth Credentials provider
- [@browserid-ng/express](https://github.com/vthunder/browserid-ng/tree/main/sdk/express) — Passport Strategy + middleware
- [@browserid-ng/hono](https://github.com/vthunder/browserid-ng/tree/main/sdk/hono) — edge/workers middleware
- [@browserid-ng/fastify](https://github.com/vthunder/browserid-ng/tree/main/sdk/fastify) — preHandler

## Thread 2 · your tools (MCP)

Restrict MCP tool access to specific users — without API keys. A warrant names
**this site, these actions, this agent, that human** — and revoking it at
[browserid.me/account](https://browserid.me/account) kills the agent's very
next call, fail-closed.

Already have a stdio MCP server? `npx @browserid-ng/gate` puts it behind the
warrant gate with a web console — see [/gate](/gate). In-process:

```js
// Gate every tool call on a valid, unrevoked warrant.
import { McpAuth } from "@browserid-ng/mcp-auth"

const auth = new McpAuth({
  resource: "https://your-server.example",
  broker:   "https://browserid.me",
  scopesForTool: { log_action: ["demo:write"] },
})

// Per call: verifies the bearer + re-checks revocation, fail-closed.
const ctx = await auth.requireWarrant(authHeader, toolName)
ctx.grantor   // the human the action is attributed to
ctx.grantee   // the agent that called the tool
```

Python: `pip install browserid-mcp-auth` (`from browserid_mcp_auth import McpAuth`).
It rides MCP's own OAuth 2.1, so any MCP host speaks it unmodified.

- [mcp-demo (JS reference server)](https://mcp-demo.browserid.me)
- [python-mcp-demo](https://python-mcp-demo.browserid.me)
- [@browserid-ng/mcp-auth on npm](https://www.npmjs.com/package/@browserid-ng/mcp-auth)

## For your users

No accounts to create — they claim the email they already have:

- Domains with their own IdP sign users in directly.
- Gmail and Workspace addresses prove themselves with a Google sign-in.
- Everyone else falls back to a one-time code by email.

## More

- [Demos](/demos) · [Domains](/domains) · [llms.txt](/llms.txt)
- [GitHub](https://github.com/vthunder/browserid-ng) · [Spec](https://github.com/vthunder/browserid-ng/tree/main/docs/specs)
