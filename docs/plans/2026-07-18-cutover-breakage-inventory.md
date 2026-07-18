# Clean-cutover breakage inventory (device-cert model)

**Decision (2026-07-18):** hard cutover, no dual-support. This is the punch-list of
**everything that breaks** and must be rewritten to the new formats. Grounded in
the divergence analysis + adversarial review + code scouts. Work items are
checkboxes; file:line anchors included. Cross-repo: `~/src/browserid-ng`,
`~/src/sandmill`, `~/src/mingo`, `~/src/sbo`.

New wire model (target): device certs (`purpose`×`subject`, IdP-signed, never
RP-seen) → access cert (fresh key, RP-facing); config cert (`authorization`,
client-side non-extractable) → warrant over `(identifier,subject)→audience`; RP
bundle = **access_cert ~ assertion ~ warrant ~ config_cert**, joined by
`(identity,subject,audience)`, 3 fail-closed revocation authorities.

---

## A. Irreversible data loss (accepted under clean cutover)

- [ ] **sbo append-only log — historical warrants.** Old `TYP_AGENT_WARRANT`,
  identity-key-signed, `parent-cert`-embedded warrants are baked into the log
  forever (`sbo/crates/sbo-core/src/attribution.rs`, inclusion-time-gated). New
  core `Warrant::parse` rejects the old `typ` → **historical attribution for
  already-included agent writes becomes unverifiable.** (mingo's backing store.)
- [ ] **Broker `warrants` rows** (`sqlite.rs:317`): identity-key-signed, no
  config-cert ref → dead under the new verifier; **users re-consent.**
- [ ] **Broker `provisioning_certs` + `api_keys` tables** dropped — in-flight agent
  delegations orphaned server-side.
- [ ] **Client keystores (IndexedDB)** hold cached identity certs keyed by
  (issuer,email) → stale; **all users re-login** to get device certs.
- [ ] **mingo CLI on-disk** `~/.mingo/credential.json` (`AgentCredential`) +
  `identity.json` (agent cert + warrants) → unparseable/unusable; **re-provision.**

## B. Core types & format — compile breaks in every crate pinning `browserid-core`

- [ ] `browserid-core/src/certificate.rs` — add `purpose`/`subject`; or new
  `DeviceCert`/`AccessCert` types. `TYP_AGENT_CERT` + `agent{parent}` block
  removed/reshaped (`certificate.rs:16,22,59`).
- [ ] `browserid-core/src/warrant.rs` — re-cut: new `typ`, drop `parent-cert`
  (`:51,68,114,131`), signer flips identity-key → config-cert, verify join gains
  `subject` (`:178-223`). **Config cert carries a status ref** (revocation).
- [ ] `browserid-core/src/assertion.rs` — `BackedAssertion` → 4-object
  `AccessPresentation` parse/verify (`:167,187,295`), 2 DNSSEC discoveries,
  3 fail-closed status checks.
- [ ] `browserid-core/src/provisioning.rs` — `P_cert`/`RequestBundle`/`Endorsement`
  **retired** (whole chain model); `Constraint` role moves to device-cert
  `identities`.
- [ ] `browserid-core/src/rp_auth.rs` — grant value is `<cert~assertion>` (`:13`)
  → the new bundle; used by `browserid-rp` + `browserid-agent`.
- [ ] New: `purpose`/`subject` enums, **fail-closed on unknown values**; config-cert
  issuer-binding (`iss==domain(identity)`, DNSSEC) in verify; per-device status
  index (revoke-one-device kills its access certs).
- [ ] **Golden cross-language test-vectors** (`test-vectors/`) — new deliverable so
  Rust/JS/PHP agree byte-for-byte (none exist today; `conformance_test.rs:707`
  self-generates Rust-only).

## C. Broker HTTP endpoints (`browserid-broker/src/routes/`)

- [ ] `POST /wsapi/cert_key` (`cert.rs:175`) → **device-cert issuance** (batch:
  user + config, purpose×subject) + a separate **access-cert mint API**.
- [ ] `POST /provision/mint` (`agent.rs:121`) — drop endorsement/chain
  (`verify_as_target_idp` `:72`); output = access cert over a fresh key; add
  **single-use nonce + rate limit**.
- [ ] `POST /provision/endorse` (`registrar registry.rs:318`) — **removed.**
- [ ] `POST /provision/reserve` (`agent.rs:222`) — **removed.**
- [ ] `register_provisioning_cert` / `revoke_provisioning_cert` /
  `/wsapi/provisioning_certs` (`registry.rs:79-297`) — **removed** (device-cert
  lifecycle replaces).
- [ ] Warrant endpoints (`consent.rs`, `/warrant/request|respond|poll`,
  `/wsapi/warrant_*`, `register/revoke/forget_warrant`) — validate **config-cert-
  signed** `(identifier,subject)` warrants; gate flips `owns_verified_email` →
  "config cert is mine" (`consent.rs:550,624,707`). ADD **config-cert registry** +
  **device-cert registry** (list/revoke-by-device).
- [ ] `POST /verify` (`verify.rs`) — accept the **4-object bundle**; always-warrant;
  config-cert signer; subject join; **3 fail-closed status authorities**, foreign
  status-list fetch (port `browserid-rp` `StatusCache`); **2nd conformance
  discovery** for the config cert.
- [ ] `GET /whoami` (`fallback_idp.rs:264`) — cookie-based, low impact; confirm.
- [ ] Self-login **auto-warrant** issuance (new; every login).

## D. Broker client JS (`browserid-broker/static/`)

- [ ] `dialog.js` — primary path (hidden iframe) → **HTTP device-cert issuance via
  popup**; `cert_key` → device issuance + access mint; `returnAssertion` → 4-object
  bundle (`dialog.js:574,799,826`, `provisioning.js:31-116`).
- [ ] `provisioning.js` + `provisioning_api.js` — **removed** (iframe cert flow /
  `navigator.id.*` provisioning postMessage).
- [ ] `communication_iframe.html` + `communication_iframe/start.js` — silent
  assertion + logout (`getSilentAssertion` `start.js:87`) → migrate/retire.
  **Gated by SBO signing relocation (`3b8m`).**
- [ ] `common/js/keystore.js` — store **device certs** (new record kind,
  purpose/subject) instead of identity certs; config cert non-extractable.
- [ ] `include.js` — RP-return contract survives (opaque token), BUT the embedded
  `communication_iframe` injection (`:1171`), `logout` wiring (`:1191`), and FedCM
  silent path (`:1289-1517`) touch the cert model.
- [ ] `account.html` / `agents.html` — management UI: **device-cert view**
  (user/agent, revoke=logout-device), **config-cert section**, warrant rows show
  `subject`+config cert; remove provisioning-cert sections + identity-key warrant
  signing (`account.html:492,779,828-874`).
- [ ] `consent.html` — warrant signing → **config cert** not identity key
  (`:34,209`); same-tab handshake shifts to config cert (`:112-173`).
- [ ] `sbo-sign.js` / `sbo-signer.js` — signs with the **identity key** today; decide
  what signs SBO envelopes under device certs (`sbo-sign.js:8,78-90`,
  `start.js:184`). Part of `3b8m`.

## E. FedCM + silent + token-exchange (easy to miss)

- [ ] `routes/fedcm.rs` (~338 lines) + `/.well-known/web-identity` + `/fedcm/*`
  (`mod.rs:134-138`) — mints `cert~assertion` (`fedcm.rs:245-267`); **migrate or
  retire.**
- [ ] `rp_auth` token exchange — grant is `cert~assertion`; define the new exchanged
  token (`browserid-rp` `Verifier/TokenAgent`, `browserid-agent` `token_for`).

## F. Verifier libs (RP-side)

- [ ] `browserid-rp/src/lib.rs` — 4-object bundle, always-warrant, config-cert
  signer, subject join; pinned-key path has **no primary/fallback discrimination**
  (`:162-195`) — add DNSSEC discovery if it must honor conformance. `StatusCache`
  (`:456-521`) defaults `fail_closed=false` → flip to fail-closed.
- [ ] `sdk/js` (`@browserid-ng/verify`) — response typedef gains `subject`; delegates
  to hosted `/verify` (mostly survives).
- [ ] (No Python/Go verifier libs exist — ADD if wanted.)

## G. sandmill.org — `~/src/sandmill` (Laravel/PHP, deploy `dokku@sandmill.org:sandmill`)

- [ ] `App\Http\Controllers\BrowserIdController` (`routes/web.php:194-266`) — today
  `/.well-known/browserid`, `POST /api/browserid/cert_key` (24h identity certs),
  `/browserid/{provision,auth}` iframe pages. ADD **device-cert issuance** (both
  purposes, subjects), **access-cert mint API**, **config-cert issuance**, signed
  with its `_browserid.sandmill.org` key; update discovery; replace the iframe
  provision page. **PHP Ed25519 JWS must byte-match `browserid-core`** (golden
  vectors). Deploy via dokku. **Until this lands, `@sandmill.org` primary logins
  fail** (correct).

## H. mingo — `~/src/mingo` (deeply coupled; it is itself an IdP)

- [ ] `mingo-idp` — a **full BrowserID IdP**: `/cert_key` (`routes.rs:197`),
  `/provision_return` (`:276`), `/provision/{mint,reserve}` + endorsement verify
  (`agent.rs:111-273`), `/session/from-assertion` (`verify.rs:104`). Needs the
  **same device-cert conformance as sandmill** (its own P10-sibling).
- [ ] `mingo-web` — browser client (`navigator.id`, `browserid.me/include.js`,
  `/session/from-assertion`) → new dialog/bundle (`app.js:250,286`).
- [ ] mingo CLI (`mingo-app`) — wraps `browserid-agent` SDK
  (`login.rs`); credential format + device-code + warrant flow all change;
  **forced re-login.**
- [ ] `mingo-poster` — per-user agent cert + user-signed external warrant
  (`poster.rs:44-93`) → device-cert/config-cert model.
- [ ] All three mingo crates pin browserid-ng `rev` → coordinated bump.

## I. sbo — `~/src/sbo` (offline verifier consumer)

- [ ] `sbo-core/src/attribution.rs` + `authorize.rs` — offline verify of
  `Auth-Cert` + `Auth-Evidence` + optional `Auth-Warrant` (`attribution.rs:12-160`)
  → new bundle parse/authority/window rules; `subject` axis; config-cert signer.
- [ ] `sbo-capture` — provisions via `POST /wsapi/cert_key` expecting a single
  identity `Auth-Cert` (`lib.rs:146-169`) → device-cert/access-cert capture; header
  shape (`Auth-Cert`/`Auth-Evidence`) reshaped.
- [ ] `/sys/trust/brokers` allowlist + issuer rules (`attribution.rs:64,155`) —
  re-root for access-cert/config-cert issuers.
- [ ] pins browserid-ng `rev` → coordinated bump; historical log (see §A).

## J. Docs / marketing / README

- [ ] `README.md:166-178` (backed-assertion format + "warrant signed by identity
  key"), `:100-113` (chain "one picture"), `:139-157` (human sign-in snippet).
- [ ] `docs/verify-quickstart.md:26,48`; `sdk/agent/README.md:77-88`;
  `examples/mcp-agent-auth/README.md:21`; `sdk/wallet/README.md`.
- [ ] `docs/specs/*` — P0 spec rewrite (protocol §4.1/§5/§6.2; agent §4).
- [ ] `marketing/fedcm-demo.html` (navigator.id) + landing positioning (add
  mandatory-conformance / headless / device-cert story).
- [ ] Demo RPs (`rp-quickstart`, `broker-demo`, `fallback-demo`) — treat assertion
  as opaque + delegate to `/verify`, so **survive** if the `/verify` request/
  response contract stays compatible; verify after the bundle change.

## K. DB migration (`browserid-broker/src/store/sqlite.rs`)

- [ ] **Schema is at v11** (not v10) — new migration is **`migrate_v12+`**, bump
  `SCHEMA_VERSION` to 12 (`sqlite.rs:17,95`).
- [ ] ADD `device_certs` table (user_id, identities, purpose, subject, pubkey,
  validity, revoked, **per-device status_idx**).
- [ ] ADD `subject` + config-cert-ref columns to `warrants`.
- [ ] DROP `provisioning_certs` (`:238`), `api_keys` (`:213`) — irreversible;
  snapshot first.
- [ ] `status_entries` gains `device`/`access`/`config` kinds (additive).
- [ ] `RegistrarStore` trait (`store.rs:12-45`) — remove 6 provisioning-cert methods
  + `ProvisioningCertRecord`; update `registrar_glue::BrokerRegistrarStore`.

## L. Tests (all must be updated to the new formats)

- [ ] `browserid-core/tests/conformance_test.rs` (rewrite + emit shared vectors),
  warrant/assertion/certificate tests.
- [ ] `browserid-broker/tests/`: `agent_provisioning_test.rs`, `fedcm_test.rs`,
  cert/warrant/verify tests, `cookie_session_security`.
- [ ] `browserid-agent/tests/` (consent_flow, rp_flow — note the known-flaky
  `7v1h`).
- [ ] `e2e-tests/` fixtures + helpers.
- [ ] New: cross-language conformance run (Rust ↔ JS ↔ PHP) against the golden
  vectors.

## M. Non-breaks / survives (for scoping confidence)

- `users`, `emails` (+`email_type`/`parent_email`), `sessions`,
  `pending_verifications` DB tables — **untouched**; live accounts survive.
- Discovery (`address_info`/DNSSEC), fallback SMTP, WinChan popup, dialog shell,
  device-grant pairing flow, warrant registry + status-list machinery (shapes),
  keystore non-extractable custody — **reused**, changed in payload not structure.
- Email verification / account creation flows — independent of the cert model.
