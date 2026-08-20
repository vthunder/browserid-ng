# RP quickstart — passwordless human sign-in in ~5 minutes

A complete relying party (RP) in one file. It serves a page with a **Sign in**
button (the browserid-ng browser shim) and verifies the returned assertion to
start a session. No passwords, no registration, no client secret.

The entire integration is one handler in `server.mjs`:

```js
// POST /api/login
const r = await verifier.verify(assertion, RP_ORIGIN);   // pin YOUR origin
if (!r.ok) return json(res, 401, { reason: r.reason });  // fail closed
startSession(r.email);
```

## Run it

```bash
npm install
npm start
# open http://localhost:8080 and click Sign in
```

The page loads the dialog from `https://browserid.me` by default and verifies
against that broker's hosted `/verify`. To run fully against your own broker:

```bash
BROKER=http://localhost:3000 RP_ORIGIN=http://localhost:8080 npm start
```

Config (env): `PORT`, `RP_ORIGIN` (the audience you pin), `BROKER` (serves
`include.js` + the dialog), `VERIFIER_URL` (defaults to the broker's `/verify` —
point at your own to self-verify), `SESSION_SECRET`.

## Offline test

`npm test` runs the server against a mock `/verify` and checks the glue —
verify → signed session cookie → `/api/me`, fail-closed on a bad assertion, and
rejection of a tampered cookie. (The browser sign-in itself needs a running
broker, so it isn't in the test.)

## Notes

- **Delegation is visible, not blocked.** `r.email` is who the session belongs
  to; `r.grantee` is the actor of record and differs from `email` when a named
  agent acted on the user's behalf (which the user explicitly approved for this
  audience). Compare them if you want a delegation policy; there is no
  human/agent flag (see the [MCP example](../mcp-agent-auth) for scope-gated
  agent access).
- **Pin `RP_ORIGIN` server-side.** Never verify a client-supplied audience.
- The session here is a minimal HMAC-signed cookie — swap in your framework's
  session store for real use.
- Any-language version of this glue: [`docs/verify-quickstart.md`](../../docs/verify-quickstart.md).
