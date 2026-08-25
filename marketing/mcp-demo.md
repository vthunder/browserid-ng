# BrowserID MCP demo — watch a revoke kill an agent, live

> A tiny MCP server whose auth is browserid natively: no API keys — every tool
> call carries a warrant naming who granted it, and revocation is re-checked
> on every single call. Three minutes, from claude.ai or any MCP host.

## 1 · Add the connector (once — approve one card)

- claude.ai: Settings → Connectors → Add custom connector →
  `https://mcp-demo.browserid.me/mcp`
- Claude Code: `claude mcp add --transport http mcp-demo https://mcp-demo.browserid.me/mcp`
- Any MCP host works — it runs its ordinary OAuth flow, which lands you on the
  browserid consent card: sign in with your email, approve `demo:write` once.

## 2 · Ask your agent to use it (ordinary tool calls)

The server's tools now appear like any connector's. Every call carries your
warrant; the reply shows the attribution — this agent, on your behalf. Try:
*"Log a fun action at the browserid mcp-demo, then read the log back and show
me how it was attributed."*

## 3 · Now revoke it (the point of the demo)

Open [browserid.me/account](https://browserid.me/account) → Authorized sites →
revoke the mcp-demo grant. Then ask the agent to log one more action: the very
next call is refused, fail-closed — the server re-checks the warrant's status
on every call. Nothing else you've granted is touched.

## + · Read the code (~250 lines)

The server is the reference for building your own:
[mcp-demo](https://github.com/vthunder/browserid-ng/tree/main/mcp-demo) (JS,
on `@browserid-ng/mcp-auth`). It mounts both auth lanes: the connector flow
above (authorization code), and an assertion grant for headless agents and
tests. A Python twin on `browserid-mcp-auth`
([source](https://github.com/vthunder/browserid-ng/tree/main/python-mcp-demo))
implements the assertion lane.

## More

[All demos](/demos) · [Developers](/developers) · [llms.txt](/llms.txt) ·
[GitHub](https://github.com/vthunder/browserid-ng)
