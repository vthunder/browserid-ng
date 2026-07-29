# guestbook-mcp

A demo **BrowserID-enabled service**: an authless remote MCP server that is a
typed veneer over the existing `browserid.me/guestbook` HTTP API — the Level 1
reference for [docs/design/browserid-enabled-apis.md](../docs/design/browserid-enabled-apis.md).

The point of the demo: this server implements **no login of its own** — no
OAuth, no accounts, no keys. Users add it to claude.ai as a bare custom
connector URL. When an agent calls `sign_guestbook` without a `presentation`,
the tool returns the `AUTH_REQUIRED` payload, which must carry the agent
through both recovery branches:

1. wallet installed → `get_assertion` (→ `authorize` if no warrant) → retry;
2. wallet **not** installed → relay exact connector-install instructions to
   the human (`https://wallet.browserid.me/mcp`).

Branch 2 is the risky one (agents may refuse or dead-end); the error copy in
`src/mcp.mjs` (`authRequired()`) is the thing to iterate on, against live
sessions with the wallet uninstalled. Tracked in bean `browserid-ng-kp0a`.

## Run

```sh
npm install
npm test
npm start           # http://localhost:3200/mcp
```

Point it at a local broker with `BROWSERID_BROKER=http://localhost:3000`
(or `GUESTBOOK_URL=` directly). All config defaults are production-safe.

## v1 scope

Per-call presentation (the stateless Level 1 sub-pattern). The recommended
connect-and-exchange pattern needs a guestbook token endpoint on the broker —
follow-up work, see the design doc.
