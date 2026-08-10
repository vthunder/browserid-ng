# @browserid-ng/nextauth

Drop-in **"Sign in with BrowserID"** for [Auth.js / NextAuth](https://authjs.dev).
A Credentials provider whose `authorize()` verifies a BrowserID presentation
server-side at the hosted verifier (`/verify-access`, via
[`@browserid-ng/verify`](../js)) — **no crypto in JS, fail-closed** — plus tiny
browser helpers that drive the login dialog. Works with Auth.js **v5** (primary)
and **v4** (the provider is a plain options object, version-agnostic).

## Server: add the provider

```ts
// auth.ts (Auth.js v5)
import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { BrowserID } from "@browserid-ng/nextauth";

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    Credentials(
      BrowserID({
        // REQUIRED: pin to your canonical origin. The presentation is
        // audience-bound; this is the confused-deputy guard. Never accept a
        // client-supplied audience.
        audience: "https://app.example.com",
      })
    ),
  ],
  callbacks: {
    // Carry the BrowserID claims (incl. statusRefs) onto the session so you
    // can re-check revocation later (see below).
    async jwt({ token, user }) {
      if (user?.browserid) token.browserid = user.browserid;
      return token;
    },
    async session({ session, token }) {
      session.browserid = token.browserid;
      return session;
    },
  },
});
```

> Auth.js **v4**: `providers: [CredentialsProvider(BrowserID({ audience }))]`
> with `import CredentialsProvider from "next-auth/providers/credentials"`.
> The `BrowserID({...})` object is identical across versions.

## Client: a sign-in button

```tsx
"use client";
import { signIn } from "next-auth/react";
import { signInWithBrowserID } from "@browserid-ng/nextauth/client";

export function SignInButton() {
  async function login() {
    const presentation = await signInWithBrowserID({ siteName: "My App" });
    await signIn("browserid", { presentation, redirectTo: "/" });
  }
  return <button onClick={login}>Sign in with BrowserID</button>;
}
```

Prefer the observer style? Call `watchBrowserID({ onlogin })` once at page init
and `requestBrowserID()` on click — both from `@browserid-ng/nextauth/client`.

## Revocation-aware sessions (recommended)

A NextAuth session outlives the ~5-minute presentation, but a BrowserID
warrant/cert is revocable. Re-check on session activity and sign out if revoked:

```ts
import { browseridSessionValid } from "@browserid-ng/nextauth";

// in a middleware / server action, on activity:
const { ok } = await browseridSessionValid(session.browserid.statusRefs);
if (!ok) await signOut(); // fail-closed: revoked OR unverifiable => out
```

## API

- `BrowserID(config)` → Auth.js Credentials-provider options.
- `browseridAuthorize(config)` → the standalone `authorize` function (for
  custom wiring / testing).
- `browseridSessionValid(statusRefs, opts?)` → `{ ok, revoked }`, fail-closed.
- Client (`@browserid-ng/nextauth/client`): `loadBrowserID`, `watchBrowserID`,
  `requestBrowserID`, `logoutBrowserID`, `signInWithBrowserID`.

`config`: `audience` (**required**), `broker` (default `https://browserid.me`),
`verifierUrl` (default `${broker}/verify-access`), `acceptedFallbacks`,
`allowAgent` (default `false` — humans only; agents use the MCP path).

Reference app: `examples/nextauth-app/`. Design:
`docs/plans/2026-08-10-nextauth-adapter-build-spec.md`. MPL-2.0.
