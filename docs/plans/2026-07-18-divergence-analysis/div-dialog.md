# Divergence inventory — login dialog, discovery, primary/fallback routing, issuance, keystore

Target: `docs/design/browserid-end-to-end-flow.md` (device-cert model).
Surface: the human login path as it exists today.

## 1. The existing flow (as built)

Cold arrival at RP → include.js opens the dialog via a **WinChan first-party popup**
(also supports a `?origin=` query / postMessage path). `dialog.js` runs the state machine:

1. **Dialog asks email** (`email-form`, dialog.js:934) OR, if the broker session is
   already authenticated, shows a **chooser** of the account's emails (`init`, dialog.js:1439-1456).
2. **Discovery** — `checkEmail()` → `GET /wsapi/address_info` (dialog.js:214, email.rs:403).
   Server-side does mock-IdP lookup, else DNS discovery via `fallback_fetcher().discover(domain)`
   (DNSSEC `_browserid` + `.well-known` for endpoint paths only; discovery.rs). Returns
   `{type: primary|secondary, state, auth, prov, issuer}`.
3. **Routing** on `addressInfo.type`:
   - **primary** → `handlePrimaryIdP()` (dialog.js:574).
   - **secondary** → this broker acts as **fallback IdP**; gated by `brokerFallbackAccepted()`
     (spec §8.1 acceptedFallbacks). Can also route to an **external** fallback IdP
     (`handleExternalFallback`, dialog.js:172) which is driven exactly like a primary.
4. **Primary path mechanism = HIDDEN CROSS-ORIGIN IFRAME + postMessage**
   (`provisioning.js`: `BrowserID.Provisioning.start()` creates `display:none` iframe at the
   IdP's `/provision`, drives `navigator.id.*` — beginProvisioning → genKeyPair → registerCertificate
   over postMessage). If not authenticated to the IdP, `tryPrimaryProvisioning` rejects with
   `needsAuth` → `redirectToPrimaryAuth()` opens the IdP `/auth` in a **popup** (with mobile
   tap-to-continue fallback), then retries provisioning. Two assertions are minted:
   one for the **broker audience** → `POST /wsapi/auth_with_assertion` to establish a broker
   account/session (primary.rs:33, links/transfers the email), one for the **RP audience**
   → returned. (dialog.js:574-643, 1528-1605)
5. **Fallback path (this broker is the IdP)** — `completeSignIn()` (dialog.js:799) calls
   `generateCertificate()` → `POST /wsapi/cert_key` (cert.rs:175). Server issues a
   **24h identity cert via `state.keypair`** (`issue_certificate`, cert.rs:52), gated on a
   verified email + a 90-day re-verification window. Password/SMTP account flows
   (create/verify/reset/set-password) all funnel to `completeSignIn`. The external-fallback
   variant instead drives the remote fallback's `/provision`+`/auth` like a primary
   (fallback_idp.rs SMTP-cookie model, 24h certs).
6. **Keystore** (`common/js/keystore.js`) — non-extractable Ed25519 CryptoKeys in IndexedDB,
   keyed by `(issuer, email)`, record `{issuer, email, publicKeyX, privateKey, cert}`.
   `getStoredEmailKeypair` reuses a cached cert if unexpired AND `storedCertAcceptable`
   (issuer acceptable to RP). A `pending` store (mingo-ytrs) already exists for a **same-tab
   handle-provisioning** handshake, but it is used by `consent.html`, NOT the login dialog —
   the login dialog's primary path is still the hidden iframe.
7. **Exit** — `returnAssertion()` (dialog.js:826): a single `cert~assertion` string to the RP
   (optionally gated by an SBO-signing consent screen). Format is `certificate~assertion`.

## 2. Divergence from the device-cert design

### KEEP (largely unchanged)
- Dialog shell + WinChan first-party popup entry (design §Stage 1.1 explicitly wants the popup,
  NOT a hidden iframe — the popup half is already right).
- Email entry + chooser UI; discovery via `address_info` / DNSSEC `_browserid` + `.well-known`.
- Primary vs fallback routing decision; acceptedFallbacks (§8.1) gate; external-fallback routing.
- Fallback IdP = this broker; SMTP challenge as the fallback's control proof (fallback_idp.rs).
- Keystore = non-extractable CryptoKeys in IndexedDB, keyed by issuer/email.
- RP-facing exit through a single funnel (`returnAssertion`).

### CHANGE
- **Issuance target.** Today `/wsapi/cert_key` mints a **per-login 24h *identity* cert** bound
  to a fresh key each sign-in (cert.rs:52, 24h validity, `create_with_status`). Design replaces
  this with **durable device-cert issuance** (Stage 1): the device generates a device keypair
  ONCE, and the IdP issues long-lived **device cert(s)** carrying `purpose`
  (authentication/authorization) + `subject` (user/agent) metadata. Per-login work moves to
  **Stage 2 access-cert minting** (a separate short-lived cert certifying a *fresh* access key,
  minted by signing an access-request token with the device key). So `cert_key` becomes/splits
  into a **device-cert issuance endpoint** + a distinct **access-cert mint API**.
- **Primary path mechanism.** Today: **hidden cross-origin iframe** (provisioning.js) — the design
  explicitly rejects this ("a first-party popup, not a hidden cross-origin iframe", §Stage 1.1;
  "no hidden iframe"). Must become an **HTTP device-cert issuance endpoint** at the domain IdP,
  reached via the popup — analogous to the mingo-ytrs same-tab handle-provisioning that already
  exists for consent. The `navigator.id.* beginProvisioning/genKeyPair/registerCertificate`
  postMessage protocol goes away.
- **Cert reuse semantics.** `getStoredEmailKeypair`/`storedCertAcceptable` today looks for an
  unexpired reusable *identity* cert (dialog.js:303-343). Under the new model the keystore holds a
  **durable device cert**; the reuse check becomes "do I hold a valid device cert for this identity/
  issuer?" and, if so, skip issuance and go straight to **mint an access cert** — not "reuse the
  assertion cert".
- **Two-assertion primary dance** (broker-audience assertion → `auth_with_assertion`, then
  RP-audience assertion) is an identity-cert construct. Under device certs, the broker/keystore
  linkage is via the device cert; the RP-facing object is **access cert + assertion + warrant +
  config cert**, not a bare `cert~assertion`.
- **Dialog's job.** Shifts from "obtain a fresh identity cert and emit an assertion" to
  "ensure a device cert exists (issue if needed, via popup to primary or via fallback SMTP), then
  mint an access cert and assemble the RP bundle (access cert + assertion + warrant + config cert)."

### ADD
- **Device keypair generation** (once per device, non-extractable) + storage of **device certs**
  in the keystore (new record kind alongside identity certs; `purpose`/`subject` fields).
- **Access-cert mint API** (client-broker/dialog signs an access-request token with the device
  key, posts to IdP mint API, receives short-lived access cert for a fresh key) — Stage 2. The
  IdP can **refuse** even a valid device cert (dialog must handle "re-login required").
- **Warrant + config-cert** assembly into the RP bundle (Stage 3/4) — today the dialog returns no
  warrant at all.
- **Device-cert issuance endpoint** on the broker's fallback IdP (replacing/renaming `cert_key`),
  emitting device certs with purpose/subject; primary IdPs must expose the same HTTP endpoint.
- Config-cert storage choice (server-side hosted broker vs on-device keystore).

### REMOVE
- **`provisioning.js` hidden-iframe machinery** and the `navigator.id.*` provisioning postMessage
  protocol on the login path (provision.js/provisioning_api.js as the primary mechanism).
- **Per-login identity-cert issuance** as the core credential (`cert_key` 24h identity cert becomes
  device-cert issuance + access-cert mint; the identity-cert-per-signin model retires).
- The **broker-audience assertion → `auth_with_assertion`** round-trip as the way to prove primary
  email ownership to the broker (replaced by device-cert custody), though account linking logic may
  survive in another form.

## Key cites
- Dialog state machine / routing: dialog.js:440-523 (`handleEmailChosen`), 934-1010 (email form).
- Primary path = iframe: provisioning.js:31-116; popup auth: dialog.js:650-773.
- Fallback external-primary drive: dialog.js:172-211.
- Issuance (24h identity cert): cert.rs:52-171 (`issue_certificate`), 175-212 (`/wsapi/cert_key`).
- auth_with_assertion (broker session/linking): primary.rs:33-160.
- Discovery: email.rs:403-475 (`address_info`), discovery.rs (SupportDocument, DNSSEC-rooted).
- Keystore: common/js/keystore.js (IndexedDB, non-extractable, `pending` staging = mingo-ytrs).
- Fallback IdP (SMTP cookie, 24h certs): fallback_idp.rs:1-60.
</content>
</invoke>
