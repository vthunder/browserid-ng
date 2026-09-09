# Handoff: registry API done; next is the pages (zpbh) and native approvals (e98a)

Written 2026-09-09 at the end of the session that built registry-api-v1.
Resume from beans **zpbh** and **e98a**; this note is the context.

## Where things stand (all on main, all deployed to browserid.me)

- **registry-api-v1** is implemented as the spec reads today: accounts
  (create / lookup), login by `login_page` (the broker's `/registry-login`
  page checks the account password) or `stored_key` (registry-signed login
  certs, 90 days, at `/api/v1/login-keys`), sessions whose members are the
  login key plus the identity certs proven under them, attach / detach /
  delete under a session, the leaving cascade with a 30-day hold and
  inbox notices, warrants (lookup, strict register, fresh index after
  revoke), certs, holders (three fixed namespaces; moves are gone),
  discovery (`login_methods`, `browser.login`).
- **Web dialog**: `common/js/registry-session.js`. Lookup → login (password
  passed straight to the page backend on this origin; popup elsewhere) →
  attach → login cert in the keystore (kind `login`); headless `stored_key`
  logins after. No approval screen.
- **Native wallet**: `wallet/src/registry.js` + `bootstrap.js`; same flow,
  the login page in a window in the wallet's partition. Its e2e
  (`cd wallet && node e2e.mjs`, local broker on :3000) passes.
- **Ceremony pages** share `common/css/ceremony.css` in the dialog's
  design language; a tenant's page carries the tenant's domain.
- **Verification**: `cargo test --workspace` green (run via
  `ssh localtest`); 121 Playwright e2e green against a warm broker; the
  production log (`ssh -i ~/.ssh/mini-ops dokku@browserid.me logs id`)
  prints every registry API call (`registry api method= path= status=`)
  and `attach: recorded …` lines, which is how a sign-in is verified.
- Beans **0c49** and **r9jo** are completed with summaries; the design
  history (guard → login) is on r9jo and `docs/plans/2026-09-08-registry-login-draft.md`.

## Rulings that shape the next work (Dan, 2026-09-09)

1. **The account page logs in as its own keyless device.** It generates a
   login key in the browser, logs in once through the login page with the
   password, mints a login cert, then logs in by stored key. This works in
   a browser that runs a native wallet and has no keystore certs.
2. **§4.3 changes from "change or sign" to "sign".** Management writes
   (revoke cert / warrant / login key, forget / rename holder, detach,
   delete) need only a session. Signing (respond, register, allocate)
   needs a config-cert member. Update the spec sentence and drop the
   matching `require_config()` calls (registrar `api.rs`, `account.rs`).
3. **Signing happens where the config key is.** Web wallet: the consent
   page and the account page's manual signing card use the keystore, as
   today. Native wallet: the wallet signs natively (e98a, below). No new
   server surface for either.
4. **Reads vs writes on the account page**: open question left to the
   implementer — reads could stay on the cookie session so the page works
   before any registry login; Dan leaned to "maybe okay" on the keyless
   device model, so go with a registry session for everything unless it
   hurts.

## zpbh — the pages onto the API, then delete the cookie registry routes

Order, each step behind a local e2e run (`e2e-tests`, warm broker):

1. Spec: §4.3 sentence + §7.1 `config_cert_required` wording; code:
   remove `require_config` from management handlers.
2. A small page client on top of `registry-session.js`: "log in as this
   browser" with a page-local login key (no identity certs). The client
   already handles `stored_key`; add a keyless mode where `ensure()`
   skips lookup/attach and uses `login_page` with the password the page
   collects (or the account page's existing sign-in form).
3. **account.html** (1,827 lines; `api()`/`post()` helpers at the top;
   registry calls at roughly lines 744–752 warrants, 924/1125/1187
   holders, 1160–1183 and 1478/1702 certs, 1527–1529 manual signing,
   1768–1770 the load). Map: `/wsapi/warrants` → `GET /api/v1/warrants`
   (items now carry `grantor`/`grantee`/`status`), `revoke_warrant` →
   `warrants/revoke`, `forget_warrant` → gone (drop the UI action),
   `device_certs` → `GET /api/v1/certs`, `revoke_device_cert` →
   `certs/revoke {id}` (returns `{revoked}`), `cert_revocation_status` →
   gone (use `revoked` from the list), `holders`/`rename_holder`/
   `forget_holder` → `/api/v1/holders*`, manual signing → `allocate_status
   {grantee}` + `warrants/register` (keystore browsers only; hide the card
   otherwise). Also list login keys (`GET /api/v1/login-keys`) as
   "signed-in devices" with revoke — new, small, and the thing a lost
   device needs.
4. **consent.html**: `warrant_requests` → `GET /api/v1/requests`,
   `warrant_respond` → `requests/respond` (no csrf), `warrants` → API.
   **authorize.html**: same treatment for whatever it calls (check).
5. Delete the cookie registry-role routes + handlers: registrar
   `/wsapi/{warrant_requests,warrant_respond,warrants,register_warrant,
   forget_warrant,revoke_warrant,allocate_warrant_status}`; broker
   `/wsapi/{device_certs,revoke_device_cert,cert_revocation_status,holders,
   rename_holder,forget_holder}`. Keep the issuer-role ones
   (sign-in, codes, passwords, emails, `browser_holder`, `list_emails`,
   `/device/issue`). Drop the `holder_moves` table and store methods.
6. Tests that drive the deleted routes: Rust `agent_flows_v2_test`,
   `connection_record_test`, `device_cert_test`, `hosted_primary_test`,
   `merged_provision_test`, `status_endpoints_test`,
   `warrant_return_url_test`, `warrant_device_test`; e2e
   `silent-assertion`, `connection-sharing`, `sbo-signing-grants`
   (they read `/wsapi/warrants` / `device_certs` to assert). Port them to
   the session helpers in `browserid-broker/tests/registry_api_test.rs`
   (`login_session`, `session_call`, `attach_call`, …).
7. Close the parity note in the spec (§3.4 / invariant 1 area).

Size: 2–3 days. CSP: `account.html` and `consent.html` have inline
module scripts; editing them changes their hash — the guard test in
`routes/mod.rs` (`inline_script_hashes_match`) prints the new value.

## e98a — native wallet approvals (and later login methods)

First item: the wallet answers inbox requests itself. It already polls
`GET /api/v1/requests`; add a native dialog (like `approveLogin` in
`main.js`) listing the grants, sign the warrants with the config key
(`login.js` has the JWS helpers; `allocate_status` gives the ref), post
`requests/respond`. Today it opens the consent page in a browser, which
has no key when the wallet is native. Then: deferred attach of a second
identity's fresh certs, the mediator inside the embedded browser, the
`device` and `identity` login methods on the login page.

## Gotchas learned this session

- Dan rejects approval-click ceremonies that add no security; authenticate
  with something real (password, stored key). Copy is not the fix for
  confusion — branding and visual design are.
- The broker is issuer AND registry: on takeover/transfer it revokes the
  old account's certs for the identity (hg2j). Record carried certs on the
  destination BEFORE the membership move, or the fresh certs die.
- `attach` must accept a header proof by a carried cert when the session
  has no member yet (a page-login session), see `account.rs`.
- Logs: the default filter now includes `browserid_registrar=info`; the
  request log lives in `session.rs::buffer_body`.
- Keystore `healthRemote` must skip kind `login` records or it deletes
  the login key on every account-page load.
- Wallet on macOS 26: launch with `npm run tray` (LaunchServices) or the
  tray is invisible. `WALLET_BROKER` defaults to production.
