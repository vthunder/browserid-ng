# @browserid-ng/verify

Verify [BrowserID-NG](https://browserid.me) access presentations (device-cert
model) from your relying party (RP) backend. Zero dependencies, **fail-closed**.

This is the *hosted-verifier* path: your server POSTs the presentation to a
running `/verify-access` service (default `https://browserid.me/verify-access`)
which does the DNSSEC-rooted key resolution, the full cryptographic join
(access cert + assertion + warrant + config cert), primary/fallback
conformance, and revocation checks. You get back a small typed result.

> **Trust:** a hosted verifier is a party you trust to verify honestly — the same
> party you already discover keys through. If you need to verify *without*
> trusting a third party, run your own `/verify-access` (the broker is open
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
  // verifierUrl: "https://browserid.me/verify-access",  // default
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

`result` is either `{ ok: true, email, issuer, subject, scopes }` or
`{ ok: false, reason }`. There is no status string to remember to check — a
truthy `.ok` is the only success signal, and every error path (including network
failures and malformed responses) resolves to `ok: false`.

### Agents

By default an **agent** presentation (an AI agent acting under a user-authorized
warrant) is **rejected** — a human login endpoint should not silently accept
one. To accept agents, opt in and read the subject + scopes:

```js
const result = await verifier.verify(presentation, audience, { allowAgent: true });
if (result.ok && result.subject === "agent") {
  // result.email  — the agent identity (e.g. dan+agent@example.com)
  // result.scopes — what the user's warrant authorized at this audience
  if (!result.scopes.includes("post")) throw new Error("not authorized to post");
}
```

## API

- `createVerifier(opts?)` → `{ verify, verifierUrl }`
  - `opts.verifierUrl` — hosted `/verify-access` URL (default
    `https://browserid.me/verify-access`)
  - `opts.acceptedFallbacks` — default fallback-IdP issuer domains for
    no-primary emails (primaries are always accepted)
  - `opts.timeoutMs` — request timeout (default `10000`)
  - `opts.fetch` — custom fetch implementation
- `verifier.verify(presentation, audience, callOpts?)` → `Promise<VerifyResult>`
  - `callOpts.acceptedFallbacks` — override for this call
  - `callOpts.allowAgent` — accept agent presentations (default `false`)
- `verifyPresentation(presentation, audience, opts?)` — one-shot convenience wrapper

## Security notes

- **Pin the audience server-side.** Pass your own origin; never echo a
  client-supplied audience.
- **Verify on the server.** The presentation is a bearer credential for your
  origin; verifying in the browser gives no security.
- Failures are deliberately coarse (`reason` is for logging, not branching).

## License

MPL-2.0
