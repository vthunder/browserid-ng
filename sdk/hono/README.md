# @browserid-ng/hono

**Sign in with BrowserID** for [Hono](https://hono.dev) — edge and serverless
(Cloudflare Workers, Bun, Deno, Node). A middleware that verifies a BrowserID
presentation server-side at the hosted verifier (`/verify-access`, via
[`@browserid-ng/verify`](../js)) — no crypto in JS, fail-closed.

```js
import { Hono } from "hono";
import { browseridLogin } from "@browserid-ng/hono";

const app = new Hono();

// The browser POSTs { presentation } (from the login dialog); verify it here.
app.post("/auth/browserid",
  browseridLogin({ audience: "https://app.example.com" }),
  (c) => {
    const id = c.get("browserid");   // { email, issuer, grantee, scopes, statusRefs }
    // set your own session cookie from id.email, then:
    return c.json({ ok: true, email: id.email });
  });
```

On failure the middleware responds `401` and never runs your handler.

## Config

`audience` (**required** — pin to your canonical origin; the confused-deputy
guard), `broker` (default `https://browserid.me`), `verifierUrl`,
`acceptedFallbacks`, `allowAgent` (default false — humans only). On Workers,
pass a bound `fetch` via `fetch` if you route the verifier through a binding.

## Also exported

- `verifyBrowserID(config)` → `(presentation) => identity | null` (custom wiring).
- `browseridSessionValid(statusRefs, opts?)` → `{ ok, revoked }`, fail-closed —
  re-check revocation on activity for long sessions.

The client half (opening the dialog to get a presentation) is
`signInWithBrowserID` from `@browserid-ng/nextauth/client`, which works
standalone. MPL-2.0.
