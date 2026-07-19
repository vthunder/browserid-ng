# Old-protocol removal inventory (clean cutover — no dual implementations)

**Decision (restated):** clean cutover. The **classic BrowserID protocol** — the
`Certificate` (identity/agent cert), the `cert~assertion` presentation, the
identity-key-signed `Warrant`, `navigator.id`/the hidden-iframe dialog, the
classic `cert_key` issuance, the classic `/verify`, and FedCM's `cert~assertion`
minting — is **removed entirely**. Everything that logs in or verifies uses the
**device-cert model** (`browserid-core::device`: DeviceCert/AccessCert/config
cert/Warrant, the 4-object `access_cert~assertion~warrant~config_cert` bundle).
This is the inventory of everything still on the old protocol. **My earlier
"kept as substrate" was a mistake** — this corrects it.

## KEEP — genuine shared substrate (NOT the old protocol)

- `browserid-core`: `keys.rs`, `jws.rs`, `status.rs` (StatusRef/StatusList),
  `discovery.rs` + `dns.rs` (DNSSEC resolution), `error.rs`, and **`Assertion`**
  (the 2-claim `{aud,exp}` JWS — reused *inside* `AccessPresentation`).
- Broker **account/session/email layer**: `stage_user`/`complete_user_creation`,
  `authenticate_user`, email add/verify, sessions, password reset. The IdP still
  proves email control (SMTP) and holds accounts — the device-cert bootstrap uses
  this. (This is user management, not the wire protocol.)
- The DNSSEC-rooted verifier plumbing (`fallback_fetcher`, discovery) — reused by
  `verify_access_with_dns`.

Everything below is **old protocol → cut or convert to device certs.**

---

## A. Core (`browserid-core`)

- [ ] `certificate.rs` — `Certificate`, `AgentClaims`, `TYP_AGENT_CERT`,
  `create_agent*` — the classic identity/agent cert. **REMOVE** (DeviceCert +
  AccessCert replace it).
- [ ] `assertion.rs` — `BackedAssertion`, `AgentAttribution`,
  `VerifiedPresentation` (the `cert~assertion` / `agent_cert~warrant~assertion`
  presentation). **REMOVE** (AccessPresentation replaces). **KEEP `Assertion`.**
- [ ] `warrant.rs` — `Warrant`, `TYP_AGENT_WARRANT` (identity-key-signed,
  `parent-cert`-embedded). **REMOVE** (`device::Warrant` replaces).
- [ ] `rp_auth.rs` — the token-exchange grant is a `cert~assertion` string.
  **UPDATE** the grant to the device bundle (or remove if token-exchange is dropped).
- [ ] `lib.rs` — remove the exports of the above.

## B. Broker — classic issuance / verify / IdP (`browserid-broker/src`)

- [ ] `routes/cert.rs` — `/wsapi/cert_key` + `/wsapi/admin/cert_key` (classic cert
  issuance). **REMOVE** (→ `/device/issue` + `/access/mint`). Note: the device
  bootstrap needs an equivalent "issue a device cert to a session-verified email"
  — that's `/device/issue`, already built; the admin seed path needs a device
  equivalent.
- [ ] `routes/verify.rs` + `verifier.rs::verify_assertion_with_dns` — classic
  `/verify`. **REMOVE** (→ `/verify-access` + `verify_access_with_dns`).
- [ ] `routes/primary.rs` — `auth_with_assertion`, `set_password` (classic primary
  auth via assertion). **REMOVE/RESHAPE** to the device bootstrap.
- [ ] `routes/fedcm.rs` + `/.well-known/web-identity` + `/fedcm/*` — mints
  `cert~assertion`. **REMOVE** (or re-spike on device certs later — not dual).
- [ ] `routes/fallback_idp.rs` — `/auth/send`, `/auth/verify`, `/cert_key`,
  `/whoami`: the fallback IdP's classic cert issuance. **CONVERT**: keep the SMTP
  email-verification, replace `cert_key` issuance with **device-cert issuance**
  (fallback issues device certs, iss=browserid.me).
- [ ] `routes/guestbook.rs` — verifies the classic bundle. **CONVERT** to the
  device bundle (`AccessPresentation`).

## C. Broker — classic client (the login dialog etc., `browserid-broker/static`)

**This is the big build: the device-cert LOGIN DIALOG.**
- [ ] `include.js` — the `navigator.id` shim + `communication_iframe` bootstrap +
  FedCM silent path. **REWRITE** as the device-cert RP entry: invoke the dialog,
  return the 4-object bundle to the RP.
- [ ] `dialog.js` + `dialog.html` — the classic state machine (`cert_key`, primary
  hidden-iframe, `returnAssertion`). **REWRITE**: email → discovery → route to the
  IdP's `/device_cert` (fallback SMTP or primary popup) → `/access/mint` → sign the
  warrant with the config cert → return the bundle.
- [ ] `provisioning.js` + `provisioning_api.js` — hidden-iframe primary provisioning.
  **REMOVE.**
- [ ] `communication_iframe.html` + `communication_iframe/start.js` — silent
  assertion + logout + **SBO signing** (`signSboEnvelope`). **REMOVE** — gated by
  relocating SBO signing (`browserid-ng-3b8m`) to the same-tab/popup surface.
- [ ] `auth.html` + `auth.js` + `authentication_api.js` — classic primary auth page. **REMOVE.**
- [ ] `provision.html` + `provision.js` — classic primary provision page. **REMOVE.**
- [ ] `common/js/keystore.js` — stores classic certs; **CONVERT** to store device
  certs (record kind: device/config, purpose/subject).
- [ ] `common/js/user.js`, `network.js`, `xhr.js` — classic client libs. **REMOVE**
  (fold anything still needed into the new dialog).
- [ ] `account.html` — finish removing the classic identity-activation (`cert_key`)
  + agent-provisioning sections (partially done in cleanup); keep the P8 Devices card.
- [ ] `consent.html` — signs the classic warrant with the **identity key**.
  **CONVERT** to sign `device::Warrant` with the **config cert**.
- [ ] `common/js/sbo-sign.js` + `sbo-signer.js` — sign SBO envelopes with the
  identity key. **CONVERT** to the device model (part of `3b8m`).
- [ ] `broker-demo.html`, `fallback-demo.html`, `demo.html`, `sbo-smoke-test.html`,
  `sign.html` — classic demo/util pages. **CONVERT or REMOVE.**

## D. Registrar (`browserid-registrar/src`)

- [ ] `consent.rs` — the warrant consent flow (`respond`, warrant registry,
  status) validates the **identity-key-signed** `Warrant`. **CONVERT** to
  `device::Warrant` (config-cert-signed). **ADD** the device-shaped
  `/warrant/request` entry (removed in the chain cleanup; browser consent surface
  kept but its request path needs rebuilding for device warrants).

## E. RP libraries + SDK

- [ ] `browserid-rp/src/lib.rs` — the classic `Verifier` (BackedAssertion,
  Certificate, Warrant, StatusCache for classic). **REPLACE** with device-bundle
  verification (`AccessPresentation` + fail-closed status + conformance). Remove classic.
- [ ] `sdk/js` (`index.mjs`, `.d.ts`, tests) — posts to `/verify` for a
  `cert~assertion`. **REPOINT** to `/verify-access`; device response shape.
- [ ] `sdk/agent` (`src/crypto.mjs`, tests) — classic agent presentation.
  **CONVERT** to device (DeviceAgent-shaped).
- [ ] `sdk/wallet` — classic framing. **CONVERT.**

## F. Demo RPs / examples / marketing

- [ ] `examples/rp-quickstart` (`server.mjs`, `test.mjs`) — `verifier.verify` a
  `cert~assertion`. **CONVERT** to the device bundle + a real device-cert login.
- [ ] `examples/mcp-agent-auth` (`server.mjs`, `mock-verifier.mjs`, `test.mjs`) —
  `agent_cert~warrant~assertion`. **CONVERT** to the device bundle.
- [ ] `marketing/fedcm-demo.html`, `marketing/index.html` — classic snippets.
  **CONVERT/REMOVE.**

## G. Consumers (separate repos — partial device work already exists)

- [ ] **mingo** (`~/src/mingo`): `mingo-idp` (`agent.rs`, `lib.rs`, `poster.rs`,
  `routes.rs`, `store.rs`, `verify.rs` — classic `cert_key`/`from-assertion`/
  `create_agent`/`Warrant`) — has a **partial** `device.rs` (from the interrupted
  agent). `mingo-web` (`app.js`, `index.html` — `navigator.id`). `mingo-app`
  (`login.rs` classic; **partial** `device_login.rs`). **FINISH** the device
  migration, remove the classic paths, bump the browserid-ng pin to `0efbd1c`+.
- [ ] **sbo** (`~/src/sbo`): `sbo-core` (`attribution.rs`/`authorize.rs` classic
  Auth-Cert/Warrant) — has a **partial** `device_attribution.rs`. `sbo-capture`
  (classic `cert_key`). `sbo-cli`, `sbo-daemon/validate.rs`, `wire`, `envelope`,
  `wasm/kit.rs`. **FINISH** the device migration, remove classic, bump the pin.

## H. Tests

- [ ] Remove/replace every classic-path test (cert/assertion/warrant/verifier/
  fedcm/primary/guestbook-classic) with device-cert coverage. (The delegation
  tests were already removed in the chain cleanup.)

---

## The load-bearing new build

**The device-cert login dialog** (§C: `include.js` + `dialog.js` rewrite) is the
single biggest piece and the prerequisite for *any* real RP login on the device
model — it's the cold-start mediator (Stage 1–4) that dc-login faked. Everything
else (demos, consumers) plugs into it.

## Gated

- **Hidden-iframe deletion** (§C) is gated by **SBO-signing relocation
  (`browserid-ng-3b8m`)** — `signSboEnvelope` lives on the iframe.

## Suggested execution order

1. **Login dialog** (§C `dialog.js`/`include.js` for device certs) + convert the
   **fallback IdP** issuance (§B `fallback_idp.rs`) — one working device-cert
   login on a real RP.
2. **RP verification** (§E `browserid-rp` + `sdk/js` → device) + convert the
   **demo RPs** (§F) — real RPs verifying the bundle.
3. **Registrar warrant** (§D) — device `/warrant/request` + config-cert consent.
4. **Remove classic core + broker** (§A, §B `cert_key`/`verify`/`primary`/`fedcm`)
   once nothing calls them.
5. **SBO relocation `3b8m`** → delete the iframe (§C).
6. **Consumers** (§G mingo, sbo) onto the device model + pin bump.
7. **Tests** (§H) throughout.
</content>
