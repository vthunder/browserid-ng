# NextAuth + BrowserID — reference app

A minimal Next.js (App Router) app showing `@browserid-ng/nextauth` as a
drop-in "Sign in with BrowserID". Reference code — the wiring is the point.

## Files

- `auth.ts` — Auth.js v5 config with the `BrowserID` Credentials provider.
- `app/api/auth/[...nextauth]/route.ts` — the Auth.js route handlers.
- `app/page.tsx` — a sign-in button using the client helper `signInWithBrowserID`.
- `app/layout.tsx` — wraps the app in `SessionProvider`.

## Run

```sh
npm install
# Pin the audience to the origin the browser is actually on:
BROWSERID_AUDIENCE=http://localhost:3000 AUTH_SECRET=$(openssl rand -hex 32) npm run dev
```

Open http://localhost:3000, click **Sign in with BrowserID**: the dialog opens
(served from `browserid.me`), you authenticate, and the returned presentation is
verified server-side by the provider (`/verify-access`, bound to
`BROWSERID_AUDIENCE`). On success you're signed in as your verified email.

## Notes

- **`audience` is the one security-critical value** — it must equal the origin
  the browser was on when the dialog ran. In production set `BROWSERID_AUDIENCE`
  to your real origin (e.g. `https://app.example.com`).
- Humans only by default. Agents use the MCP path (`@browserid-ng/mcp-auth`),
  not this login provider.
- For long sessions, re-check revocation with `browseridSessionValid(
  session.browserid.statusRefs)` and sign out if it returns `{ ok: false }`.
