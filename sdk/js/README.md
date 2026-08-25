# @browserid-ng/verify

Verify [BrowserID-NG](https://browserid.me) access presentations (device-cert
model) from your relying party (RP) backend. Zero dependencies, **fail-closed**.

This is the *hosted-verifier* path: your server POSTs the presentation to a
running `/verify` service (default `https://browserid.me/verify`)
which does the DNSSEC-rooted key resolution, the full cryptographic join
(access cert + assertion + warrant + config cert), primary/fallback
conformance, and revocation checks. You get back a small typed result.

> **Trust:** a hosted verifier is a party you trust to verify honestly — the same
> party you already discover keys through. If you need to verify *without*
> trusting a third party, run your own `/verify` (the broker is open
> source) and set `verifierUrl` to it.

## Install

```
npm install @browserid-ng/verify
```

Requires Node 18+ (uses global `fetch`).

## Use

```js
import { createVerifier } from "@browserid-ng/verify";

const verifier = createVerifier({
  // verifierUrl: "https://browserid.me/verify",  // default
  // acceptedFallbacks: ["browserid.me"],                 // optional (spec §8.1)
});

// In your login handler, `presentation` came from the browser (delivered to
// navigator.id.watch()'s onlogin); `audience` is YOUR origin — the exact
// string, pinned server-side, never taken from the client.
const result = await verifier.verify(presentation, "https://app.example.com");

if (result.ok) {
  // result.email is verified — log the user in.
  session.user = result.email;
} else {
  // Any failure — expired, wrong audience, bad signature, revoked, network error.
  res.status(401).json({ error: result.reason });
}
```

`result` is either `{ ok: true, email, issuer, subject, scopes, statusRefs }`
or `{ ok: false, reason }`. There is no status string to remember to check — a
truthy `.ok` is the only success signal, and every error path (including network
failures and malformed responses) resolves to `ok: false`.

### Revocation re-checks ("logged out everywhere")

Verification already rejects revoked credentials at login. But your session
outlives the presentation, so a device revoked *after* login would otherwise
stay signed in until your session expires. Store `result.statusRefs` (plain
`{uri, idx}` pointers — no key material) with the session and re-check on
session activity:

```js
// e.g. in session middleware, throttled to once per few minutes
const status = await verifier.checkStatus(session.statusRefs);
if (!status.ok || status.revoked) {
  // Fail-closed (spec §6.4): "cannot prove unrevoked" is a rejection.
  session.destroy();
}
```

The browser shim additionally polls revocation client-side to flip open tabs
to `onlogout` without a reload — that signal is UX; this check is the
enforcement.

### Agents and delegation

A successful result carries two identities:

- `result.email` — the **attributed** identity: who the session/action belongs
  to (the warrant grantor).
- `result.grantee` — the **actor of record**: equals `email` when the identity
  acted for itself; differs when another identity (typically a named agent
  like `dan+agent@example.com`) acted on `email`'s behalf.

A delegated presentation at your audience exists only because the user
explicitly approved a warrant for it — attribute the session to `email`, log
`grantee` for provenance, and gate actions on `result.scopes`. If your policy
requires the account owner to be the actor of record, compare the two:

```js
const result = await verifier.verify(presentation, audience);
if (result.ok && result.grantee !== result.email) {
  // a delegate acted for result.email — apply your delegation policy here
}
```

There is **no human/agent flag**, deliberately: a user can always provision an
agent with an "as-you" credential (`grantee === email`), so no verifier can
promise "this is a human". Anything claiming otherwise would be false
assurance. (The old `allowAgent` option was exactly that and has been removed;
passing it now throws.)

## API

- `createVerifier(opts?)` → `{ verify, verifierUrl }`
  - `opts.verifierUrl` — hosted `/verify` URL (default
    `https://browserid.me/verify`)
  - `opts.acceptedFallbacks` — default fallback-IdP issuer domains for
    no-primary emails (primaries are always accepted)
  - `opts.timeoutMs` — request timeout (default `10000`)
  - `opts.fetch` — custom fetch implementation
- `verifier.verify(presentation, audience, callOpts?)` → `Promise<VerifyResult>`
  - `callOpts.acceptedFallbacks` — override for this call
- `verifyPresentation(presentation, audience, opts?)` — one-shot convenience wrapper

## Security notes

- **Pin the audience server-side.** Pass your own origin; never echo a
  client-supplied audience.
- **Verify on the server.** The presentation is a bearer credential for your
  origin; verifying in the browser gives no security.
- Failures are deliberately coarse (`reason` is for logging, not branching).

## License

MPL-2.0
