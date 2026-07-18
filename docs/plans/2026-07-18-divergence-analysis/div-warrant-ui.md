# Divergence: warrant flow, management UI, warrant service/registry

Target design: `docs/design/browserid-end-to-end-flow.md` (device-cert model).
Surface: broker `static/{account,agents,consent}.html`, `browserid-registrar/src/consent.rs`,
warrant/status endpoints in `browserid-broker/src/routes/`.

## 1. How today's warrant is signed vs. the design

**Today:** A warrant is signed by the **user/delegator's identity key**, and the delegator's
`U_cert` is embedded in the warrant as `parent-cert`. It authorizes
**(delegator email, agent_email) → audience [+scopes]**.
- Claims shape: `browserid-core/src/warrant.rs:51` `WarrantClaims` — `iss` (=delegator email =
  parent-cert principal), `agent`, `aud`, `parent-cert` (the U_cert), `scopes`, `status`.
- `warrant.rs:114` rejects an agent-subject parent cert; the parent must be a plain email-principal
  user cert. Verification (`warrant.rs:165`+): parent-cert same-domain as agent, warrant signed by
  the parent cert's subject key.
- Client signing sites: `consent.html:209 signWarrant()`, `account.html:835` (reissue) and
  `account.html:863` (manual/debug) — all build `typ: browserid-agent-warrant-v1` with
  `iss: id.email`, `parent-cert: id.cert`, and sign with the **non-extractable identity key**.

**Design (Stage 3, lines 44/102-120):** A warrant is signed **once by a config cert**
(`authorization` purpose), over **(identifier, subject) → audience[+scopes]**. It is
**device-agnostic**, long-lived, stored in the hosted-broker **registry**, reused across devices,
and NOT bound to any device/access key. RP sees **warrant + the config cert that signed it**.

### CHANGES (warrant object + signing)
- **Signer flips** from user identity key → **config cert** (`authorization`+subject). The embedded
  `parent-cert` (a U_cert) becomes an embedded/linked **config cert**. `warrant.rs` create/verify,
  and all three client `signWarrant`/reissue/manual paths, change what they sign with and embed.
- **Subject axis is NEW.** Today the warrant ranges over (delegator, agent_email). Design ranges
  over **(identifier, subject∈{user,agent})**. Warrant claims gain a `subject`; the agent-vs-user
  distinction stops being "is agent_email one of my agents" heuristics and becomes an explicit field.
- **Self-login warrants** (design line 117: user login = default scopes, auto-issued). Today there
  is **no self-login warrant** — user login rides plain assertion+cert, warrants exist only for
  agents. ADD: auto-issue a `subject:user` warrant at login from a self-scoped config cert.
- **Verifier join key changes.** Today verify joins by (delegator, agent) via parent-cert. Design
  joins access-cert + warrant by **(identity, subject, audience)** (line 133). `routes/verify.rs`,
  `routes/guestbook.rs:156` bundle verification change accordingly.

## 2. Consent / registry code (`browserid-registrar/src/consent.rs`)

### KEEPS
- RFC-8628-shaped request/poll device-grant flow (`request`, `request_external`, `poll`) — design
  line 60/78 still uses a popup/hand-off consent for agent warrants.
- Per-delegator **warrant registry** (`upsert_warrant`, `list_warrants`, `forget_warrant`) — design
  line 119 explicitly keeps a hosted-broker registry.
- **Signed status list + per-grant status index** (`status_list_uri`, `warrant_status_subject`,
  `scope_fingerprint`, `get_or_allocate_status`, `revoke_warrant`, `status_list` at
  `.well-known/browserid-status`) — design line 120/134 keeps a status endpoint + revocation UI.
- Grant validation, all-or-nothing batch, external-request anti-spam/redirect-tie (`§6.6`).

### CHANGES
- `respond()` (consent.rs:550) validates the signed warrant against the pending request by
  `warrant.audience/agent/delegator`. Under the design it must validate a **config-cert-signed**
  warrant carrying `(identifier, subject)`, not a U_cert-`parent-cert` one. The `agent`/`delegator`
  match logic becomes `(identifier, subject)` match.
- `warrant_to_record` (consent.rs:624) reads `warrant.delegator()/agent()`; record schema
  (`WarrantRecord`) needs a **subject** field and a **config-cert reference** instead of implicit
  delegator=parent-cert-principal.
- `register_warrant` (consent.rs:707) gates on `owns_verified_email(delegator)`. Under the design the
  gate is "signed by a config cert this account controls," so the authorization proof changes from
  "delegator is my verified email" to "config cert is mine."
- `status_list` is signed by `state.keypair` (the registrar/hosted-broker key). Design keeps the
  **hosted broker** as the warrant's revocation authority (line 134) — consistent; the warrant must
  carry a link to it (already does via `status` claim). Likely KEEP.

### ADDS
- **Config-cert registry + issuance/consent.** Design line 32/46-49: config certs are a first-class
  credential (server-side at hosted broker OR on user machines). Nothing today issues, stores, or
  lists config certs — this is entirely new registrar/store surface (analogous to the existing
  provisioning-cert registry in `agent_provision.rs`, but for `authorization`-purpose device certs).
- **Device-cert registry/status** for user & agent **authentication** certs (mint credential). Today
  the only revocable/registered credentials are provisioning certs + warrants; the design's device
  certs (user/agent) need their own registry + revocation + status endpoint (line 72 "revoke one to
  log that device/agent out"; line 134 IdP is the device/access-cert revocation authority).

### REMOVES / obsolete
- The `parent-cert`-as-U_cert coupling and `owns_verified_email` delegator gate lose meaning once
  warrants are config-cert-signed and device-agnostic.

## 3. Management UI (`static/account.html`, `agents.html`, `consent.html`)

`agents.html` is just a redirect stub to `/account` — no change needed (KEEP).

### account.html — today's sections
- **Your identities** (emails, active/needs-sign-in) — maps to design's user device certs, but the
  page models identities as emails-with-cached-certs, not as enumerable **device certs**.
- **Agents** built from **provisioning certs** (`account.certs`, `agentEntries()` account.html:492)
  + minted agent emails.
- **External services** (§6.6 warrants to foreign agents).
- **Warrant detail/table** per agent/service with Copy / Reissue / Revoke / Forget
  (`renderDetailWarrants` account.html:779).
- **Advanced/debug** manual warrant signing (account.html:850) + paired-agent provisioning approval
  (account.html:894+, `showProvisionApproval`).

### KEEPS
- Warrant list/table, per-grant **Revoke** (status bit) and **Forget** (registry drop), external-
  service grouping, consent page + pending-request queue, paired-agent provisioning approval flow
  (design line 74-80 agent variant = device-grant hand-off; this UI already implements that shape).

### CHANGES
- "Your identities" must become (or gain) a **device-cert view**: list this account's **user certs**
  and **agent certs** (authentication) with **purpose/subject** badges, each revocable (= "log that
  device/agent out", design line 72). Today "active/needs sign-in" is per-email cached-cert state,
  not a device-cert inventory across devices.
- Warrant rows must show/carry **subject** and the **config cert** that signed them (not a U_cert
  delegator). Reissue/manual-sign paths (account.html:828-874) re-sign with the identity key → must
  re-sign (or reference) with a **config cert** instead.
- consent.html `signWarrant` (consent.html:209) + the whole "signs a warrant with your identity's
  own key held in this browser" model (consent.html:34-38 copy) changes to config-cert signing.
- The same-tab provisioning handshake (`startSameTabProvision`/`consumePendingProvision`,
  consent.html:112-173) provisions a **U_cert (identity cert)** to sign the warrant in-browser; under
  the design the browser needs the **config cert** available (or the hosted broker signs), so this
  handshake's purpose shifts from "get an identity key here" to "get/use a config cert."

### ADDS
- A **Config certs** management section: list, create (self-scoped `authorization+user` vs
  `authorization+agent`), and **revoke** config certs — none exists today.
- A **Device certs** management section distinguishing **authentication** (user/agent, mint
  credential, IdP-revoked) from **authorization** (config, warrant signer). Today the account page
  has no purpose/subject concept at all.
- Self-login warrant surfacing (auto-issued; design line 117) — user may want to see/revoke the
  auto warrants for sites they've logged into.

### REMOVES
- The identity-key-signs-warrant framing in copy + code (consent.html:34, account.html manual/debug,
  the `parent-cert: id.cert` construction in three places) — superseded by config-cert signing.

## 4. Endpoints touched
- `POST /wsapi/warrant_respond`, `/wsapi/register_warrant`, `/wsapi/allocate_warrant_status`,
  `/wsapi/revoke_warrant`, `/wsapi/forget_warrant`, `GET /wsapi/warrants`, `/wsapi/warrant_requests`,
  `POST /warrant/request`+`/warrant/poll`, `GET /.well-known/browserid-status` — all in consent.rs;
  routing wired at `routes/mod.rs:54-116`.
- Verification bundles: `routes/verify.rs:77-84`, `routes/guestbook.rs:156-176`, `routes/cert.rs:100`
  embed `status_list_uri` — all assume today's parent-cert warrant shape.
- NEW endpoints implied: config-cert create/list/revoke; device-cert (auth) list/revoke; self-login
  warrant auto-issue.
</content>
</invoke>
