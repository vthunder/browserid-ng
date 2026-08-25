# @browserid-ng/express

**Sign in with BrowserID** for Express — a Passport strategy and a plain
middleware. Verifies a BrowserID presentation server-side at the hosted
verifier (`/verify`, via [`@browserid-ng/verify`](../js)) — no crypto in
JS, fail-closed. The client gets the presentation from the login dialog (use
`@browserid-ng/nextauth/client`'s `signInWithBrowserID`, which works
standalone) and POSTs it; you verify it and set your own session.

## Passport strategy (idiomatic Express)

```js
import passport from "passport";
import { Strategy } from "@browserid-ng/express";

passport.use(new Strategy({ audience: "https://api.example.com" }, (id, done) => {
  // map the verified BrowserID identity (id.email, id.issuer, …) to your user
  User.findOrCreate({ email: id.email }).then((u) => done(null, u), done);
}));

// login route: the browser POSTs { presentation } (JSON body parser first)
app.post("/auth/browserid", express.json(), passport.authenticate("browserid"), (req, res) => {
  res.json({ ok: true, user: req.user });
});
```

## Plain middleware (no Passport)

```js
import { browseridLogin } from "@browserid-ng/express";

app.post("/auth/browserid", express.json(),
  browseridLogin({ audience: "https://api.example.com" }),
  (req, res) => {
    req.session.user = { email: req.browserid.email }; // your session
    res.json({ ok: true });
  });
```

## Revocation-aware sessions

Store `req.browserid.statusRefs` at login; re-check on activity:

```js
import { browseridSessionValid } from "@browserid-ng/express";
const { ok } = await browseridSessionValid(req.session.statusRefs);
if (!ok) req.session.destroy(); // fail-closed: revoked OR unverifiable
```

## Config

`audience` (**required** — pin to your canonical origin; the confused-deputy
guard), `broker` (default `https://browserid.me`), `verifierUrl`,
`acceptedFallbacks`. The identity carries `email` (attributed) and `grantee`
(actor of record) — compare them for delegation policy; there is no
human/agent flag (see the `@browserid-ng/verify` README). MPL-2.0.
