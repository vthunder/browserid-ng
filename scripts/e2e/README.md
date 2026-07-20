# Browser e2e scripts (playwright, ad-hoc)

Not part of `cargo test` — these drive a **real headless browser** against a
running broker (local or prod) to exercise the login dialog, the redirect
fallback, and the SBO signer end to end. Written during the device-cert
migration; kept here so they don't live only in a session scratchpad.

## Setup
```
npm install playwright && npx playwright install chromium
```

## Local broker (most scripts)
```
cd browserid-ng
cargo build
DISABLE_SMTP=1 BROKER_PORT=3199 ./target/debug/browserid-broker > /tmp/broker.log 2>&1 &
```
`DISABLE_SMTP=1` prints verification codes to the log (the scripts scrape them)
and enables the `/wsapi/test/*` mock-IdP routes. Scripts expect the log at a
path they read from `./broker.log` — run them from a dir with that symlink, or
edit the `LOG` const.

## The scripts
- `browser-dialog-test.mjs` — account-based login: cold-start create-account +
  the signed-in chooser, both verified via `/verify-access`.
- `dialog-redirect-test.mjs` — the full-page redirect fallback (`window.open`
  stubbed to null): create-account round trip + the primary same-tab hop
  against a mock primary IdP.
- `signer-device-test.mjs` — the `/sign` SBO signer on the device model: log in,
  grant the origin, drive `/sign` with a real sbo-wasm envelope, verify the
  returned presentation.
- `prod-signin-check.mjs` — sign-in smoke against **prod** browserid.me + mingo
  (popup + redirect modes reaching the email screen). No login completion (prod
  needs a real emailed code).
- `smoke-prod-dc.mjs` — prod device flow via the admin-seed path (needs
  `ADMIN_TOKEN`, e.g. `ADMIN_TOKEN=$(ssh dokku@sandmill.org config:get id ADMIN_TOKEN)`).
