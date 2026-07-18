# Divergence: agent endpoints + registrar + DB schema (device-cert design)

READ-ONLY inventory. Surface: broker agent endpoints, headless issuance, registrar, service/DB schema.

## The core structural divergence

The **existing** model is a **delegation chain**: a user signs an in-browser
`P_cert` delegating to a provisioning key `P_priv` (the "API key"); the agent
holds `P_priv` + the `U_cert~P_cert` bundle; each mint is a short-lived
`R` request signed by `P_priv`, endorsed by the registrar/broker, then
verified as a full `U_cert~P_cert~R` chain by the target IdP which stamps an
agent cert. Three signing parties, one composite chain credential.

The **design** collapses this to a **device cert issued directly by the IdP**:
the IdP issues an *agent device cert* after the user authorizes issuance
(device-grant hand-off of the agent's own pubkey). No `P_cert`, no `P_priv`, no
per-request endorsement, no chain. The agent then signs an **access-request
token** with its device key and posts to a **mandatory headless mint endpoint**;
the IdP returns a short-lived **access cert** over a *fresh* key. Warrants are
signed by a **config cert** (`authorization`-purpose device cert), over
`(identifier, subject)`, stored in the registry, reused device-agnostically.

So the design keeps the *shape* of the pieces that already exist (a mint API, a
registrar/registry, a consent flow, a status list, warrants, agent-subject
certs) but **re-roots the trust**: IdP-issued device certs replace the
user-signed delegation chain; endorsement disappears; the device-grant pairing
(currently only for bootstrapping the provisioning credential) becomes the
*primary* agent-cert issuance path.

---

## Endpoints (browserid-broker + browserid-registrar routers)

### KEEP (shape survives)
- **Headless mint** — `POST /provision/mint` (`browserid-broker/src/routes/agent.rs:121`)
  is the closest thing to the design's mandatory mint endpoint and stays as a
  concept. But its *semantics* change (see CHANGES): today it mints a
  **long-lived (24h) agent cert over the agent's own persistent key** from a
  dual-signed chain; the design wants it to mint a **short-lived access cert
  over a fresh key** from a device-cert-signed access-request token.
- **Device-grant pairing** — `/agent-provision/{request,poll,info,resolve,complete}`
  (`browserid-registrar/src/agent_provision.rs`, routes at `lib.rs:148-151`). This
  RFC-8628 flow (agent sends pubkey, human approves, poll picks up) is exactly
  the design's "agent device cert issued by the IdP after user authorization"
  hand-off — KEEP the flow, but it must yield an **IdP-signed agent device cert**
  rather than a **user-signed `U_cert~P_cert` delegation** (`complete` at
  `agent_provision.rs:382` currently returns a delegation, not a cert).
- **Warrant consent** — `/warrant/request` + `/warrant/poll` (`consent.rs:123`,
  `:402`) and browser side `/wsapi/warrant_*`. Stays: warrants are still
  requested-not-configured, approved in-browser, polled by the agent.
- **Warrant registry** — `/wsapi/warrants`, `register_warrant`, `forget_warrant`,
  `revoke_warrant`, `allocate_warrant_status` (`consent.rs:665-831`). Stays: the
  design's "hosted broker stores issued warrants + revocation UI".
- **Signed status list** — `GET /.well-known/browserid-status` (`consent.rs:836`).
  Stays: the design's status endpoint RPs consult.
- **Assertion verification** — `POST /verify` (`routes/mod.rs:130`) stays as the
  convenience-verifier surface.

### CHANGES
- `/provision/mint` verification: `verify_as_target_idp` (`agent.rs:72`) verifies
  a `U_cert~P_cert~R` chain + a fresh broker **endorsement** bound to the bundle.
  Under the design there is **no chain and no endorsement** — the input becomes an
  access-request token signed by an IdP-issued device cert; verification is
  "device cert is mine, unrevoked, in-validity, identity in its list" (design
  Stage 2). The `Endorsement` parameter and second signature check are removed.
- `/provision/mint` output: returns a persistent agent cert (`MintResponse`,
  `agent.rs:113`) — becomes a short-lived **access cert over a fresh key**.
- `/warrant/request` own-agent branch (`consent.rs:131-198`): today gated on the
  **provisioning-cert registry** (look up `P_pub`, verify `R` signed by `P_priv`).
  With no provisioning cert, the gate changes to "request signed by a valid
  IdP-issued agent/config device cert." External branch (`request_external`,
  `consent.rs:204`, `agent_cert~R`) already matches the design's foreign-agent
  shape and largely survives.
- Warrant signer: warrants are signed in-browser by the **identity key** today
  (`consent.rs:550` respond flow validates a client-signed warrant). Design says
  a warrant is signed by a **config cert** (`authorization`-purpose device cert) —
  the signing key/cert type and the presented "config cert" alongside the warrant
  are new.

### ADD
- **`purpose` / `subject` device-cert issuance API** — the design's Stage-1
  requirement: an IdP endpoint that issues device certs (both `authentication`
  and `authorization` purposes; subjects `user`/`agent`/blank), including issuing
  **several at once** (user cert + agent cert(s)). No such endpoint exists;
  `issue_certificate` (`cert.rs:52`) issues plain or agent certs but has no
  purpose/subject axis and is driven by session/email verification, not a
  device-cert issuance request.
- **Access-request-token mint** distinct from device-cert issuance (Stage 2) —
  the two-key split (device key certifies; access cert certifies a *fresh* key)
  does not exist; today the agent's persistent key is what gets certified.
- **Config-cert-signed warrant path** + presenting the config cert to the RP.

### REMOVE
- **`POST /provision/endorse`** (`registry.rs:318`) — endorsement is the chain
  model's per-request approval; the design has no endorser step. Removed with the
  whole `Endorsement` concept.
- **Provisioning-cert registry API** — `/wsapi/provisioning_certs`,
  `register_provisioning_cert`, `revoke_provisioning_cert` (`registry.rs:79-297`).
  Replaced by device-cert lifecycle (issue/list/revoke device certs). The
  in-browser `P_cert` signing that these register goes away.
- `/provision/reserve` (`agent.rs:222`) — a chain-era pre-allocation of
  constraint names; obsolete once names live in the device cert's identity list.

---

## Registrar (browserid-registrar)

- KEEP as a component: warrant consent, warrant registry, status list — the
  design's "registrar / revocation UI / status endpoints" map cleanly
  (`lib.rs:1-34` mission statement already says "records warrants; does not sign
  them" — consistent with design's hosted broker).
- CHANGE: the registrar's provisioning-cert role (register/endorse) is removed;
  `RegistrarState` drops the endorsement-signing responsibility for chains. Its
  keypair still signs the **status list** (KEEP) — the design's warrant registry
  revocation authority.
- CHANGE: `IssuerKeyResolver` (`lib.rs:105`) + `request_external` stay and matter
  more — foreign IdPs issuing device certs is now the norm, so DNSSEC issuer-key
  discovery is load-bearing for warrant verification.
- The `agent_name_allowed` anti-squatting rule (`lib.rs:79`) partially migrates:
  in the design the IdP controls which identities a device cert lists, so the
  "fallback must sub-address" rule moves into device-cert issuance policy rather
  than provisioning-cert registration.

---

## Headless SDK (browserid-agent/src/lib.rs)

- `AgentCredential` (`lib.rs:96`) = `{secret_key(P_priv), delegation(U~P), broker,
  idp}` → becomes `{device_key, agent_device_cert, idp}`. The `delegation` +
  `broker`-endorsement fields are REMOVED.
- `mint()` (`lib.rs:654`): today = build `U~P~R` bundle → `endorse()` at broker →
  `idp_post /provision/mint`. Becomes: sign access-request token with device key →
  post to mint → get access cert. The `endorse()` helper (`lib.rs:680`) is REMOVED.
- `provision()` (`lib.rs:215`) bootstrap: today loads a pre-existing delegation
  credential; becomes the device-grant pairing client (agent generates device
  key, gets IdP-issued agent device cert).
- KEEP: warrant request/poll/obtain (`lib.rs:310-455`), `assertion_for`
  (`lib.rs:471`, already emits `agent_cert~warrant~assertion`), `token_for` /
  RP challenge exchange (`lib.rs:534`), stored-identity persistence. The
  agent-cert-needs-a-warrant invariant (`lib.rs:478`) already matches the design.
- `StoredIdentity` (`lib.rs:194`) keeps agent key + cert + warrants; `handle`
  concept survives.

---

## DB SCHEMA CHANGES (explicit)

Broker sqlite schema at `browserid-broker/src/store/sqlite.rs` (migrations v1–v10),
registrar reads it via `registrar_glue` `BrokerRegistrarStore`.

### Tables that stay largely as-is
- **`emails`** (`sqlite.rs:150`, +`email_type` v3 `:188`, +`parent_email` v4 `:202`).
  `EmailType::Agent` (`store/models.rs:19`) + `parent_email` attribution survive —
  the design still has agent identities with a human parent. The
  `authentication` vs `authorization` purpose and the `user/agent/blank` subject
  are **NOT** modeled here yet — needs new columns or a device-cert table.
- **`warrants`** (v8 `:317`, UNIQUE reworked to scope-hash in v10 `:366`, cols:
  `delegator_email, agent_email, audience, scopes, warrant, status_idx,
  signed_at, expires_at`). KEEP — matches design's warrant registry. Note it
  keys on `(identity/agent, audience, scope-hash)`, aligning with the design's
  "(identifier, subject) → audience[+scopes]" — but **`subject` is not a stored
  column** (agent-ness is inferred from the email), an ADD.
- **`warrant_requests`** (v6 `:263`, rebuilt v7 `:291` for batch grants, +`external`
  v10 `:416`). KEEP — ephemeral consent-request rows.
- **`status_entries`** (v9 `:343`: `idx PK, kind, subject, revoked_at, UNIQUE(kind,
  subject)`). KEEP — the revocation index space. Design's access-cert vs warrant
  revocation both map onto `(kind, subject)`; today `kind ∈ {identity, warrant}`.

### Tables to REMOVE
- **`provisioning_certs`** (v5 `:238`: `user_id, delegator_email, provisioning_pub
  UNIQUE, bundle(U~P), label, created_at, last_endorsed_at, revoked_at`) — the
  chain model's registry of user-signed delegations. Gone in the device-cert
  model (no `P_cert`/`P_priv`, no endorsement, so `last_endorsed_at`/`bundle`/
  `provisioning_pub` are all chain artifacts).
- **`api_keys`** (v-early `:213`: `parent_email`, SHA-256 secret) — the pre-chain
  API-key table; already legacy, fully removed under device certs.

### Tables/columns to ADD
- A **device-cert table** (or agent-identity table) recording IdP-issued device
  certs: `(user_id, identity/email or identity-list, purpose{authentication,
  authorization}, subject{user,agent,blank}, pubkey, issued_at, expires_at,
  revoked_at, status_idx)`. This is the new durable credential replacing
  `provisioning_certs`. Revocation = "revoke one to log that device/agent out."
- **`subject` column** on `warrants` (design keys warrants on
  `(identifier, subject)`); today only agent_email + audience.
- **config-cert reference** on warrant rows (which config cert signed it), since
  the RP is shown "warrant + the config cert that signed it."
- Access certs are short-lived and IdP-gated online (design Stage 2), so likely
  **not persisted** beyond the `status_entries` index — but the identity→status
  index mapping (currently `get_or_allocate_status("identity", email)` in
  `cert.rs:99`) stays as the access-cert revocation root.

### Migration note
`registrar_glue::BrokerRegistrarStore` implements `RegistrarStore` (`store.rs:12`)
over these tables; removing `provisioning_certs` removes the
`register/get_by_pub/list/count/revoke/touch_provisioning_cert` trait methods
(`store.rs:17-45`) and the endorse path that consumes them.
</content>
</invoke>
