# @browserid-ng/fastify

**Sign in with BrowserID** for [Fastify](https://fastify.dev) — a `preHandler`
hook that verifies a BrowserID presentation server-side at the hosted verifier
(`/verify-access`, via [`@browserid-ng/verify`](../js)) — no crypto in JS,
fail-closed.

```js
import { browseridLogin } from "@browserid-ng/fastify";

// The browser POSTs { presentation } from the login dialog.
fastify.post("/auth/browserid",
  { preHandler: browseridLogin({ audience: "https://api.example.com" }) },
  async (req, reply) => {
    // req.browserid = { email, issuer, grantee, scopes, statusRefs }
    req.session.user = { email: req.browserid.email }; // your session
    return { ok: true };
  });
```

On failure the preHandler replies `401` and short-circuits the route.

## Config

`audience` (**required** — pin to your canonical origin), `broker` (default
`https://browserid.me`), `verifierUrl`, `acceptedFallbacks`, `allowAgent`
(default false — humans only).

## Also exported

- `verifyBrowserID(config)` → `(presentation) => identity | null`.
- `browseridSessionValid(statusRefs, opts?)` → `{ ok, revoked }`, fail-closed.

MPL-2.0.
