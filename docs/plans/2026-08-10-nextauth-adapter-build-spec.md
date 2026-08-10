# NextAuth (Auth.js) adapter — build spec

**Date:** 2026-08-10
**Bean:** (to be filed). Drives RP-side distribution (roadmap Theme 5,
"Drop-in RP adapters"): make "Sign in with BrowserID" a dependency install
for the largest JS auth ecosystem.

**One line:** `@browserid-ng/nextauth` — a Credentials provider + a tiny
client helper that turns BrowserID into a drop-in Auth.js sign-in, verifying
the presentation server-side at the hosted `/verify-access`.

## Why a Credentials provider (not OAuth)

BrowserID's browser flow does not match NextAuth's OAuth model (which needs an
`authorization_endpoint` that redirects and returns a `code`). Instead the
**dialog** (loaded via `include.js`) produces a *presentation* string, and the
RP backend verifies it. That maps 1:1 onto a NextAuth **Credentials** provider:
`authorize({presentation})` verifies it and returns a user or null. This is
exactly what `examples/rp-quickstart/server.mjs:96–105` does, lifted into the
Auth.js contract. No hosted intermediary AS, verification stays at the RP
backend (matches the model), fewest moving parts.

(An OAuth provider *is* possible pointed at a `wallet-service` instance —
`wallet-service/src/oauth.mjs` is a real authorization-code + PKCE AS whose
login step is BrowserID sign-in — but that needs an AS to run/host. We
document it as the alternative for OAuth-native apps; the Credentials provider
is the primary drop-in.)

## Package shape (`sdk/nextauth/`, `@browserid-ng/nextauth`)

Three small exports, ESM `.mjs` + `index.d.ts` (repo convention):

1. **`BrowserID(config)` — the provider.** A NextAuth `CredentialsProvider`
   factory:
   - `credentials: { presentation: {} }`.
   - `authorize({ presentation })`: call the hosted verifier
     (`@browserid-ng/verify` `createVerifier({verifierUrl}).verify(
     presentation, audience)`) — which POSTs `{presentation, audience,
     accepted_fallbacks}` to `/verify-access` and returns fail-closed
     `{ok, email, grantee, issuer, scopes, statusRefs}`. On `ok`, return
     `{ id: email, email, name: email, browserid: {issuer, grantee, holder,
     scopes, statusRefs} }`; else return null.
   - Config: `broker` (default `https://browserid.me`), `verifierUrl`
     (default `${broker}/verify-access`), **`audience` (REQUIRED — pin to
     your canonical origin; the single security-critical value)**,
     `acceptedFallbacks?`, `allowAgent?` (default false — humans only).
2. **`signInWithBrowserID(opts)` — the client helper.** Framework-agnostic:
   loads `${broker}/include.js` once, calls `navigator.id.request({siteName})`
   on invocation, and resolves with the presentation from the `onlogin`
   observer; the caller passes it to Auth.js `signIn("browserid",
   {presentation, redirect})`. Also exposes `watchBrowserID({onlogin,
   onlogout})` for the explicit-trigger contract. (The audience is derived by
   the dialog from `window.location.origin`; the helper needs no audience —
   only the provider does, server-side.)
3. **Docs + a working Next.js example** under `examples/nextauth-app/`:
   `auth.ts` wiring the provider, a sign-in button calling
   `signInWithBrowserID`, and a protected page. This is the "5-minute
   integration" for the Next.js world.

## Reuse

- `@browserid-ng/verify` (`sdk/js/index.mjs`) — already POSTs to
  `/verify-access`, fail-closed, with `checkStatus` for long sessions. The
  provider is a thin wrapper; no new verification code.
- `include.js` — the client helper just loads and drives it (watch/request);
  no re-implementation of the dialog/relay/FedCM machinery.
- `examples/rp-quickstart` — the reference for the exact verify call + audience
  pinning (`RP_ORIGIN`).

## Session revocation (long-lived NextAuth sessions)

BrowserID warrants/certs are revocable; a NextAuth session outlives the
5‑minute presentation. Ship an optional **`refreshBrowserIDSession`** helper
(and document the pattern): stash `statusRefs` in the JWT/session at sign-in
via the `jwt` callback, and on session activity call `verify.checkStatus(refs)`
(`POST /status/check`) fail-closed — sign the user out if revoked. Wire it as a
documented `callbacks.session` snippet + a helper, not magic, so apps opt in.

## Auth.js version

Target **Auth.js v5** (`next-auth@5` / `@auth/core`) as primary — the current
line. The Credentials provider + client helper also work under **v4**; provide
a short v4 compat note (the provider factory is near-identical; the import path
and `signIn` ergonomics differ). Keep the provider logic framework-agnostic so
a `@auth/core` core + thin next-auth wrappers cover both.

## Security notes (must-get-right)

- **`audience` is pinned server-side, never client-supplied.** It must equal
  the origin the browser was on when the dialog ran (your canonical origin).
  This is the confused-deputy guard; wrong audience = accepting a presentation
  minted for another site.
- **Fail-closed:** any verifier error / `ok:false` → `authorize` returns null.
- **Humans only by default:** `allowAgent:false` so an agent presentation
  can't silently log in as a person (agents use the MCP path instead).
- For scoped API access (not plain login) the audience must be
  `<origin>/<path>` — documented, but the default login audience is the origin.

## Decisions (settled 2026-08-10)

1. **Credentials provider is the primary drop-in.** Verify the presentation
   server-side at `/verify-access`; zero new infra. The
   OAuth-against-wallet-service path is *documented* as the alternative for
   OAuth-native apps, not built. A generic hosted authorization-code AS is a
   separate, larger bet (deferred).
2. **Auth.js v5 primary + v4 compat note.** Framework-agnostic provider core;
   thin v5 wiring; a short v4 compatibility note.
3. **Package name `@browserid-ng/nextauth`.**

## Deferred (follow-ups)
The OAuth-provider-against-wallet-service path as a supported package; a
generic hosted authorization-code AS ("Login with BrowserID" button with zero
RP backend); Remix/SvelteKit/Express adapters off the same framework-agnostic
core; publishing to npm.
