# Menubar wallet prototype (bean 7oi3)

A native macOS wallet that replaces the browserid.me dialog popup: an Electron
menubar app holds your device keys and runs the login ceremony; a Chrome/Arc
extension provides `navigator.id` on every page and routes login clicks to the
app over localhost. Approval-push: the app polls for pending agent-warrant
requests and raises native notifications.

**Status:** working end-to-end against a local broker (see `e2e.mjs`, green).
Login flow: RP page → click sign in → native macOS approval → 4-object
presentation → `/verify` okay. No popup, no browser storage, keys never leave
the app.

## Morning test drive (Arc, against production)

1. **Start the app** (first run downloads nothing; Electron is already in
   node_modules):

   ```sh
   cd prototypes/menubar-wallet/app
   npx electron .
   ```

   A menubar item appears (`id…`). Click it → **Bootstrap with browserid.me…**
   → an app window opens browserid.me/account → sign in as yourself → the
   window closes itself and the tray notifies "Wallet bootstrapped as …".
   (The wallet registers as a device in your account's browsers namespace,
   labeled by its User-Agent: `BrowserID-Menubar-Wallet/0.1`.)

2. **Load the extension in Arc**: `arc://extensions` → enable Developer Mode →
   *Load unpacked* → select `prototypes/menubar-wallet/extension/`.

3. **Try it**: open https://browserid.me/broker-demo and click *Sign in*.
   First click pairs the extension with the app (native confirm), then the
   native "Sign in to https://browserid.me?" dialog appears — approve, and the
   page verifies the presentation. No popup at any point. The fedcm-demo page
   on www.browserid.me exercises the cross-origin RP case.

Caveats for the prod run: the interactive bootstrap window and approval-watch
were built tonight but only exercised via their test lanes (BrowserWindow
session polling is identical code, but no human walked it yet). If bootstrap
misbehaves, the fallback is the password lane:
`curl -X POST 127.0.0.1:8873/test/bootstrap -d '{"email":"…","pass":"…"}'`
(requires launching with `WALLET_TEST=1`, and a fallback-account password).

## What's in here

- `app/` — Electron menubar app.
  - `main.js` tray + native dialogs/notifications; `server.js` localhost
    bridge on `127.0.0.1:8873` (pair → token → `/login`, `/status`);
    `ceremony.js` the protocol lanes; `bidcrypto.js` Ed25519/JWS matching
    dialog.js exactly; `store.js` file-backed state (`0600`, Keychain later).
- `extension/` — MV3. `shim.js` installs `navigator.id` as an un-displaceable
  accessor (include.js's own shim install is swallowed by the setter);
  `relay.js` bridges page ↔ service worker; `background.js` talks to the app.
- `e2e.mjs` — full loop under Playwright (Chromium + extension + local
  broker + the real broker-demo page). `app/test-ceremony.mjs` unit-tests the
  ceremony; `app/test-approvals.mjs` proves the approval-push polling path.

Local test env: `DISABLE_SMTP=1 AGENT_PROVISIONING=1 ADMIN_TOKEN=localtest-admin
cargo run -p browserid-broker`, then `node e2e.mjs`.

## Design notes / protocol findings (for the write-up)

- **Bootstrap uses the session lane, not agent-provision.** The pairing lane
  never yields a config (Authorization) cert, so every new RP would need a
  browser approval round. Instead the app opens browserid.me in an Electron
  window (user signs in on the real site), then calls `/device/issue` from
  that session — yielding the same device+config pair the dialog gets. After
  that, login is fully native: self-signed login warrant per audience (config
  key), `/access/mint` is device-cert-authed (no cookies, ever).
- **The verifier doesn't care where the wallet lives.** No holder-namespace or
  cert-type check blocks an external wallet — by design ("they are all you").
- **Approval-push has no external endpoint** (`/wsapi/warrant_requests` is
  session-cookie only). The app reuses its persisted Electron session to poll
  it — works, but dies with the broker session. The clean fix is a small
  broker addition: a device-cert-authenticated inbox (auth primitive already
  exists in `warrant_request`, backing query already exists). Worth a bean.
- **Login warrants are minted without status refs** (v1 warrants allow it;
  the dialog treats allocation as best-effort). Means: revoking the wallet's
  *certs* kills it, but individual site warrants have no revocation bit.
  Fine for a prototype; a real wallet should allocate status refs while the
  bootstrap session is alive.
- Prototype trust model for the localhost bridge: 127.0.0.1 bind + native
  pairing confirm + bearer token. Not hardened (any local process could try
  to pair; each attempt raises a native dialog).
