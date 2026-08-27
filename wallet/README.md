# BrowserID Wallet

The native wallet: a macOS menubar app that holds your BrowserID device keys
and replaces the browserid.me dialog popup. A companion MV3 browser extension
provides `navigator.id` on pages and routes login clicks to the app over
localhost — sign-in with no popup and no broker involvement in the login
path. Approvals ride the registry API (registry-api-v1): the app polls your
pending-consent inbox with a sender-constrained token and raises native
notifications.

Successor to `prototypes/menubar-wallet` (branch `proto/menubar-wallet`),
which is now reference material. What changed from the prototype:

- **Single-login bootstrap (bean gxi9).** Email-first: the app asks which
  identity it should hold, then routes by `address_info` — primaries log in
  ONCE at their own IdP (device-authorize hop) and the app joins the broker
  registry silently via `auth_with_presentation`; secondaries log in once at
  the broker, which *is* their issuer. The prototype's broker-first double
  login is gone.
- **Keychain-gated key custody.** State is encrypted at rest with Electron
  `safeStorage` (macOS: key held in the login keychain), replacing the
  plaintext 0600 JSON. Ed25519 signing stays in software — Secure Enclave is
  P-256-only, so enclave custody is a protocol-suite question (bean hd63),
  not a wallet setting.
- **Registry API client.** Approvals inbox, warrant status-ref allocation,
  and warrant registration run over `POST /api/v1/token` + DPoP-style
  request proofs signed with the config key — no borrowed cookies. Site
  warrants now carry per-site revocation bits and appear (revocably) on the
  account page, closing the prototype gap.
- **Real .app packaging.** `npm run pack` builds an LSUIElement .app via
  electron-builder, which solves the macOS 26 invisible-tray trap properly
  (LaunchServices grants the menubar slot). Dev runs use `npm run tray`.
- **Broker-audience warrants carry the `registry` scope** (ig9p) — required
  by the token exchange, soon by the cookie lane too.

## Layout

- `src/main.js` — tray, native dialogs/notifications, lifecycle.
- `src/bootstrap.js` — the gxi9 single-login bootstrap (both lanes) + the
  only cookie-carrying code in the app (the one-time issuer session).
- `src/login.js` — steady-state ceremony: self-signed login warrant (with
  allocated status ref) + `/access/mint` + assertion → 4-object presentation.
- `src/registry.js` — registry API client: token exchange, request proofs,
  inbox watch, warrant allocation/registration.
- `src/crypto.js` — Ed25519/JWS matching the protocol + the
  `browserid-registry-proof-v1` request proof.
- `src/store.js` — safeStorage-encrypted state.
- `src/server.js` — localhost bridge for the extension
  (`127.0.0.1:8873`; pair → token → `/login`, `/status`).
- `extension/` — MV3 bridge (un-displaceable `navigator.id` shim).

## Run

```sh
npm install
npm test          # crypto/proof unit tests (no Electron)
npm run tray      # dev, via LaunchServices so the tray is visible
npm run pack      # build the .app (dist/mac*/BrowserID Wallet.app)
```

Point it at a broker with `WALLET_BROKER=http://localhost:3000` (default:
`https://browserid.me`).

E2E (local broker on :3000 with `DISABLE_SMTP=1 AGENT_PROVISIONING=1
ADMIN_TOKEN=localtest-admin`, Playwright from `../e2e-tests`):

```sh
node e2e.mjs
```

## Trust model notes

- Localhost bridge: 127.0.0.1 bind + native pairing confirm + bearer token,
  bound to the browser origin it was paired under. Browser callers are
  allowlisted (the extension's `chrome-extension://` origin plus loopback
  pages for the e2e harness); any other web origin is 403'd before the
  pairing dialog can fire, and CORS reflects the specific caller — never `*`.
  Native local processes send no Origin and are gated by the pairing and
  per-login dialogs, which name the caller (and the identity in play) so the
  human isn't approving blind. Remaining hardening (per-caller token model,
  process attestation) is tracked on the bean.
- The extension shim installs `navigator.id` as an un-displaceable accessor
  so include.js's own shim cannot displace it.
- Test lanes (`/test/*`) exist only under `WALLET_TEST=1` and never expose
  key material.
