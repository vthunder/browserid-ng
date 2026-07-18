# Migration plan — device-cert model (grounded in the existing implementation)

**Epic:** browserid-ng-oup3
**Design (source of truth):** `docs/design/browserid-end-to-end-flow.md`
**Basis:** a six-surface divergence analysis of the *actual* codebase (spec+core,
login dialog/discovery/keystore, agent endpoints+registrar+DB, warrant+management
UI, include.js+verifier+demo RPs, README+docs). Supersedes the earlier greenfield
plan — this one is anchored in what already exists.

This is a **structural rewrite of the certificate chain**, not an additive
feature. But a large amount of mature infrastructure survives, which bounds the
blast radius. Read "what survives" first.

## What survives (reused, ~unchanged)

- **Dialog shell + WinChan first-party popup** entry (the design explicitly wants
  the popup, not a hidden iframe — the popup half is already right). `dialog.js`.
- **Discovery**: `GET /wsapi/address_info` + DNSSEC `_browserid` + `.well-known`
  (`email.rs:403`, `discovery.rs`). Primary/fallback routing + acceptedFallbacks
  (§8.1) gate + external-fallback path.
- **Fallback IdP = this broker** (SMTP challenge), `fallback_idp.rs`.
- **Keystore**: non-extractable Ed25519 in IndexedDB keyed by (issuer,email), with
  the `pending` same-tab staging store (mingo-ytrs). `common/js/keystore.js`.
- **The primary/fallback CONFORMANCE rule is ALREADY enforced** in the hosted
  verifier (`verifier.rs:223-233`: a fallback-issued cert for a primary domain
  already fails). The "critical" verifier gap is the *smallest*, not the biggest.
- **include.js** — least-divergent surface: the RP-return contract is an opaque
  token pass-through; it survives untouched as the bundle grows more segments.
- **Demo RPs** (`rp-quickstart`, `broker-demo`, `fallback-demo`) — treat the
  assertion as opaque + delegate to `/verify`; **no structural change**.
- **Device-grant pairing** (`browserid-registrar/agent_provision.rs`,
  RFC-8628) — already the design's "agent device cert issued after user
  authorization" hand-off; keep the flow, change what it returns.
- **Warrant registry + consent flow + signed status list**
  (`consent.rs`: `upsert_warrant`, `revoke_warrant`, `/.well-known/browserid-status`).
- **`browserid-rp` `StatusCache`** (`lib.rs:456-521`) — already does foreign
  status-list fetch+verify+cache; the hosted verifier lacks this and can port it.
- Core `keys.rs`, `Assertion`, `StatusRef`, host-cert §4.2, JWS idiom.

## The structural changes (the real work)

1. **Two-tier certs.** Add `purpose` (authentication|authorization) × `subject`
   (user|agent|any) to certs. Split the durable **device cert** (never seen by
   the RP) from a fresh, IdP-minted, RP-facing **access cert**. Today the
   long-lived identity/agent cert IS what the RP roots on (`cert.rs`,
   `certificate.rs:59` has only `is_agent()`/`agent_parent`).
2. **Warrant flips.** From agent-only, **user-identity-key-signed**, embedding the
   `U_cert` as `parent-cert` (`warrant.rs:51,114`) → **universal** (present for
   user logins too), **config-cert-signed**, over **(identifier, subject) →
   audience[+scopes]**, with the **config cert presented separately** to the RP
   (user cert never seen).
3. **Presentation + join.** From `cert~assertion` / `agent_cert~warrant~assertion`
   → **`access_cert~assertion~warrant~config_cert`**, verified by a two-path
   DNSSEC-rooted join on **(identity, subject, audience)** (`assertion.rs:295`,
   `warrant.rs:178`).
4. **Delegation chain retires.** `provisioning.rs` (`P_cert`, `RequestBundle`,
   `Endorsement`) + `/provision/endorse` + the provisioning-cert registry go away,
   collapsing into **direct IdP device-cert issuance** + a **mandatory headless
   mint API**. No endorser, no `U_cert~P_cert~R` chain.
5. **Mandatory HTTP issuance/mint is core conformance.** Every IdP MUST implement
   device-cert issuance (both purposes) + the access-cert mint API — so agents
   mint **headless**. Moves today's layered, endorsement-gated provisioning into
   required core, gated by the device-cert signature alone. **This is the point:
   the primary path stops being a browser-only hidden iframe.**

## Phases (dependency-ordered, with code anchors)

- **P0 — Spec.** Rewrite `browserid-ng-protocol.md` (§4.1/§5/§6.2 CHANGE; §7/§8 add
  the mandatory issuance+mint conformance) + `agent-provisioning-and-grant-api.md`
  (§4 mostly REPLACED; §6 consent + §7 grant exchange keep shape). Record the
  device-cert / access-cert / config-cert / warrant-over-identity chain.
- **P1 — Core types & format (`browserid-core`).** `DeviceCert{purpose,subject,
  identities,pubkey,validity,iss}`; `AccessRequest` (device-signed);
  `AccessCert` (fresh key, RP-facing); re-cut `Warrant` to `(identifier,subject,
  audience,scopes)` signed by a config cert (drop `parent-cert` embedding);
  `AccessPresentation` verify joining by (identity,subject,audience);
  fail-closed on unknown purpose/subject. Deprecate/retire `provisioning.rs`
  chain types. Keep `Assertion`/`keys`/`StatusRef`.
- **P2 — IdP issuance + mint (`browserid-broker/routes`).** Device-cert issuance
  API (both purposes/subjects, **batch** user+agent) — evolve `cert.rs:52`
  `issue_certificate`; **access-cert mint API** (device-cert-authed, headless,
  fresh key) — evolve `/provision/mint` (`agent.rs:121`) dropping
  `verify_as_target_idp`'s endorsement/chain; config-cert issuance. Remove
  `/provision/endorse` (`registry.rs:318`), the provisioning-cert registry
  (`registry.rs:79-297`), `/provision/reserve` (`agent.rs:222`).
- **P3 — DB schema migration (`store/sqlite.rs`).** ADD a `device_certs` table
  (user_id, identities, purpose, subject, pubkey, validity, revoked, status_idx).
  ADD `subject` + config-cert ref to `warrants` (v8/`:317`). REMOVE
  `provisioning_certs` (v5/`:238`) + `api_keys`. KEEP `emails`, `warrants`(mostly),
  `warrant_requests`, `status_entries`. Update `registrar_glue`/`RegistrarStore`
  trait (drop provisioning-cert methods).
- **P4 — Warrant model (`registrar` + core).** Config-cert-signed warrants;
  `consent.rs respond()`(`:550`)/`warrant_to_record`(`:624`) validate a
  config-cert-signed `(identifier,subject)` warrant; gate flips from
  `owns_verified_email` to "config cert is mine"; **self-login auto-warrant** from
  a self-scoped config cert; ADD a **config-cert registry** + device-cert registry.
- **P5 — Client: dialog + keystore (`static/`).** Dialog: ensure a device cert
  exists (issue via popup→**primary HTTP issuance endpoint** or fallback SMTP),
  **mint an access cert**, assemble the RP bundle. **Replace the hidden-iframe
  primary path** (`provisioning.js`, `navigator.id.*` postMessage) with the HTTP
  device-cert issuance endpoint via popup (reuse the mingo-ytrs same-tab
  handshake). Keystore stores device certs (new record kind); reuse-check becomes
  "hold a valid device cert? → mint access cert." Handle IdP mint refusal
  ("re-login required").
- **P6 — Verifier + RP contract.** Hosted `/verify` (`verify.rs`,`verifier.rs`):
  accept the 4-object bundle; **always-warrant**; config-cert-as-signer;
  purpose×subject validation + subject-in-join; two-authority revocation (access
  cert→IdP list [**port `StatusCache`**], warrant→broker list). Reuse the existing
  conformance check (`verifier.rs:223-233`). `browserid-rp` same, + optionally add
  DNSSEC discovery so the **pinned-key path** can honor conformance (it can't
  today). include.js + demo RPs unchanged; `sdk/js` response typedef gains subject.
- **P7 — Agent SDK + headless (`browserid-agent`, `agent_provision.rs`).**
  `AgentCredential{device_key,agent_device_cert,idp}` (drop delegation+broker
  endorse); `mint()`→sign access-request token→mint API (drop `endorse()`);
  `provision()`→device-grant pairing yielding an **IdP-signed agent device cert**
  (`agent_provision.rs complete()` `:382` returns a cert, not a delegation). Keep
  warrant request/poll, `assertion_for` (now emits the 4-object bundle), token
  exchange.
- **P8 — Management + warrant UI (`account.html`, `consent.html`).** Device-cert
  view (user/agent authn certs, purpose/subject badges, revoke=log out
  device/agent); **Config-cert** section (create self-scoped `authz+user` vs
  `authz+agent`, revoke); warrant rows show subject + config cert; consent signs
  with a **config cert** not the identity key; self-login warrant surfacing.
- **P9 — Docs + landing + README.** Fix the priority-wrong snippets:
  `README.md:166-178` (backed-assertion format + "warrant signed by identity
  key"), `README.md:100-113` (chain "one picture"), `sdk/agent/README.md:77-88`,
  `docs/verify-quickstart.md:26,48`, `examples/mcp-agent-auth/README.md:21`. ADD
  access-cert/device-cert/purpose×subject/config-cert/mandatory-conformance/
  headless-minting. Landing is least-diverged (keep narrative, add positioning).
- **P10 — sandmill.org primary IdP conformance (`~/src/sandmill`, Laravel/PHP;
  deploy `dokku@sandmill.org:sandmill`).** sandmill.org is the reference
  **primary** for `@sandmill.org`. Today it is a classic Persona-style IdP —
  `App\Http\Controllers\BrowserIdController` serves `GET /.well-known/browserid`
  (discovery), `POST /api/browserid/cert_key` (24h identity certs signed by its
  IdP key), and the `GET /browserid/{provision,auth}` **hidden-iframe** pages
  (`routes/web.php:194-266`). Bring it to device-cert conformance: implement
  **device-cert issuance** (both `purpose`s, subjects `user`/`agent`, batch),
  the mandatory **access-cert mint API** (headless, fresh key), and **config-cert
  issuance**, all signed with its existing IdP key (published at
  `_browserid.sandmill.org`); update `/.well-known/browserid` to advertise the new
  endpoints; replace the iframe `/browserid/provision` page with the popup + HTTP
  issuance flow. **The PHP Ed25519 JWS output MUST be byte-compatible with
  `browserid-core`'s device/access/config-cert + warrant claim shapes** (`typ`
  values, field names, `PublicKey` `{algorithm,publicKey}` JWK) so the hosted +
  RP verifiers accept it. Deploy via dokku. This is what lets
  `danmills@sandmill.org` log in through the real **primary** path — and unblocks
  the faithful primary demo (P11).
- **P11 — Faithful demo + conformance + live validation.** A **cold-start** demo
  RP (real discovery, no session shortcut) that logs in `danmills@sandmill.org`
  via the sandmill.org primary (P10) and a no-primary email via the fallback.
  Conformance test suite (issuance + mint + always-warrant + fail-closed on
  unknown purpose/subject + reject-fallback-for-primary). SBO signing relocation
  (`3b8m`) before deleting the hidden iframe.

Sequence: P0 → P1 → {P2, P3} → P4 → {P5, P6, P7} → P8 → P9 → P10 → P11.
(P10 mirrors P0/P1/P2's issuance+mint format; P11's primary demo depends on P10.)

## DB migration (explicit)

REMOVE `provisioning_certs`, `api_keys`. ADD `device_certs`; ADD `subject` +
config-cert ref on `warrants`. KEEP `emails`(+`email_type`/`parent_email`),
`warrants`, `warrant_requests`, `status_entries`. `status_entries.kind` gains a
`device`/`access` kind alongside `identity`/`warrant`. Update
`registrar_glue::BrokerRegistrarStore` (`store.rs:17-45`) to drop the
provisioning-cert trait methods + endorse path.

## Open questions / risks

- **Q5 — cookies at mint:** optional-only (never required, or ITP returns).
- **Q8 — transports:** confirm the WinChan popup carries the primary device-cert
  return leg; define the agent device-cert pairing hand-off (already
  `agent_provision.rs`-shaped).
- **Primary demo needs sandmill.org conformance (now planned as P10)** — a
  Laravel/PHP `BrowserIdController` change deployed via `dokku@sandmill.org:sandmill`.
  Cross-language risk: the PHP cert/JWS output must match `browserid-core`'s
  shapes exactly. Until P10 lands, faithful demos are fallback-only (no-primary
  emails) and MUST reject `@sandmill.org` (correct behavior).
- **Breaking:** warrants mandatory on every login → every RP/verifier processes a
  warrant (accepted, pre-GA).
- **Hidden-iframe deletion is gated by SBO signing relocation (`3b8m`).**
- **Not-yet-existing:** Python/Go verifier libs (only `sdk/js`); config-cert
  registry; device-cert registry — all net-new.
</content>

---

# Adversarial review results (2026-07-18) — findings & plan changes

Five code-grounded adversarial reviewers (security, migration/ops, completeness,
sequencing, correctness). Full inventories under
`docs/plans/2026-07-18-adversarial-review/`. Net: the auth core is sound; the real
holes are on the **authorization/consent side + rollout**. Changes below supersede
the phase list above where they conflict.

## A. Design-level fixes (genuine holes — applied to the design doc)

- **A1 [BLOCKER] Config-cert → identity-IdP binding.** The join was only
  `(identity, subject, audience)`; nothing pinned the config cert to the
  identity's IdP → an agent could self-issue a config cert from a rogue IdP and
  grant itself scopes (privilege escalation; today `warrant.rs:189-195` pins the
  delegator to the agent's own DNSSEC-rooted IdP). FIX (done in design):
  `config_cert.iss == domain(identity)`, DNSSEC-rooted, purpose==authorization,
  identity in its list — a **second conformance discovery** in verify. → P1, P6.
- **A2 [BLOCKER] Config-cert revocation.** The config cert is presented + signs
  warrants but had no status ref → no RP-visible kill switch. FIX (done in
  design): config cert carries a status ref; RP checks **three** fail-closed
  authorities (access→IdP, config→IdP, warrant→broker). → P1, P6.
- **A3 [BLOCKER→qualified] Server-side config cert.** Broker-held config cert =
  broker signs warrants autonomously; broker is also fallback IdP → silent
  impersonation. **DECIDED (user, 2026-07-18):** the concern is overstated — for a
  fallback identity the broker is the issuer anyway; for a primary identity a
  broker-held config cert can't obtain an access cert, so it can't log in. **We
  keep config certs CLIENT-SIDE and non-extractable (like access certs), issued
  alongside the user cert at every login (batch); the device signs its own login
  warrant locally, which syncs to the server registry for device-agnostic reuse.**
  Server-side config-cert storage is dropped. **BACKLOG:** withhold the config cert
  on less-trusted machines (login-only devices), for least privilege — deferred.

## B. Security controls to add

- **B1 Foreign status-list revocation is fail-open/unbuilt** in the hosted verifier
  (`verify.rs:72-103` checks only own_uri). New model needs federated revocation.
  Port `browserid-rp`'s `StatusCache` (`lib.rs:456-521`), **fail-closed**. → P6.
- **B2 Mint gate replaced.** Retiring registrar endorsement removes the two-party
  throttle/veto. Access-request tokens = **nonce + short expiry + single-use**;
  **mandatory per-device rate limiting** as conformance (none exists today,
  `cert.rs` has no rate limit). → P2, spec.
- **B3 Device-cert revocation granularity.** Give each device cert its own status
  index; access certs reference the issuing device's index (not the per-identity
  one), so "revoke one device" actually kills that device's access certs. → P3, P6.
- **B4** Enforce `subject`-equality in the join; `authentication`-only-mints /
  `authorization`-only-signs; absent purpose/subject ⇒ reject. → P1, P6.

## C. Rollout safety (the biggest structural change — was a hard cutover)

The plan assumed a hard cutover. There ARE live consumers (mingo CLI, sbo log,
guestbook, browserid.me accounts). Even under "no one else is using it," the
**data-loss** items below are real. New principles:

- **C1 Dual-support, don't cut over.** The verifier + broker accept BOTH old
  (`cert~assertion`, no warrant) AND new (4-object, warrant-mandatory) bundles for
  ≥1 release; **version-tag the bundle** so the verifier branches deterministically
  (not by parse failure); enforce warrant-mandatory only after old-bundle traffic
  ≈ 0. Otherwise deploy skew (www static, sandmill PHP, cached include.js) = total
  login outage.
- **C2 Additive, then one late cleanup.** Do NOT retire `provisioning.rs` in P1 or
  remove `/provision/{endorse,reserve}` in P2. Add the new model **alongside** the
  old; a single final **CLEANUP** phase (gated by SBO relocation `3b8m`) removes the
  chain types, endpoints, `provisioning_certs`/`api_keys`, and the hidden iframe —
  once nothing calls them.
- **C3 Deprecate-then-drop the DB.** Migrations are forward-only, DROP is
  irreversible. Do **ADDs** in P3 (device_certs table, warrant `subject` +
  config-cert-ref); defer **DROPs** to cleanup; take a verified pre-deploy snapshot.
  **NUMBERING FIX: schema is at v11, not v1–v10 — new work is `migrate_v12+`,
  bump `SCHEMA_VERSION` to 12** (`sqlite.rs:17`).
- **C4 Keep legacy parse in core.** sbo has old-format warrants embedded in its log
  forever; core `parse()` must keep the legacy `TYP_AGENT_WARRANT` path (stop
  issuing, don't stop verifying) + version the warrant `typ`. Existing broker
  `warrants` rows can't be backfilled with a config-cert ref → treat as expired,
  prompt re-consent (P8).
- **C5 mingo credential compat.** New `AgentCredential` fields `#[serde(default)]`
  + a "re-run `mingo login`" message (not a serde panic); ship the mingo release
  before the broker removes endorse.
- **C6 sandmill P10 gating.** Byte-compat-verify PHP conformance (golden vectors)
  BEFORE the broker rejects `@sandmill.org`, or primary logins black out.

## D. Sequencing (adopt the revised order)

- **D1 [CRITICAL] Freeze the wire format up front.** Add golden **test-vectors**
  (canonical claim JSON + signed JWS with a fixed key + accept/reject cases) as a
  **P1 deliverable** under `test-vectors/`, consumed by Rust + JS + PHP. Today the
  conformance test self-generates Rust-only vectors — nothing cross-language exists.
- **D2 Serialize the false-parallel braces.** `P3 (schema ADDs) → P2 (endpoints)`;
  `P6 (verifier) → {P5 dialog, P7 agent}` (P7 depends on P2+P6 in the crate graph);
  add an explicit **live-bundle × verifier integration checkpoint** after P5.
- **D3 Thin vertical slice first.** user-cert + fallback-IdP + a **client-side
  (device-resident) config cert issued alongside the user cert**, signing its own
  login warrant → ONE working cold-start login, as an early green milestone, before
  agents (P7) and primary/PHP (P10) layer on.
- **D4 Pull P10 forward** to run parallel with {P5,P6,P7} (it depends only on the
  frozen vectors). Split P4 into P4a (registry/issuance) + P4b (warrant flip +
  self-login auto-warrant).

**Revised sequence:** P0 spec → **P1 (types + fail-closed + golden vectors,
additive)** → **P3 (schema ADDs)** → **P2 (issuance/mint/config-cert, new routes
alongside)** → **P4a** → [THIN SLICE milestone] → **P4b** → **P6 (verifier/rp)** →
**P5 (dialog)** + **P7 (agent)** + **P10 (sandmill PHP)** in parallel →
**P8 (UI)** + **P9 (docs)** → **P11 (faithful demo + cross-language conformance
run + CLEANUP gated by 3b8m)**.

## E. Completeness gaps to add as phase work

- **E1 mingo is a full IdP, not a footnote.** `mingo-idp` mints identity + agent
  certs and runs the delegation chain — it needs the **same device-cert
  conformance as sandmill (a P10-sibling)**, plus mingo-web (client), the mingo CLI
  (agent SDK), and mingo-poster all migrate. Add **P10b — mingo conformance +
  consumer migration**. sbo (`sbo-core/attribution.rs` offline verifier +
  `sbo-capture`) migrates its parse/authority surface. All three repos pin
  browserid-ng revs → coordinated bumps.
- **E2 FedCM path** (`routes/fedcm.rs`, ~338 lines) mints `cert~assertion` — decide
  migrate vs retire. **Silent-assertion `communication_iframe`** + logout migrate/
  retire (with `3b8m`). **`rp_auth` token exchange** grant is a `cert~assertion`
  (`browserid-rp` + `browserid-agent` consume it) — define the new exchanged token.
- **E3 Device lifecycle.** No device concept exists today; the design assumes
  multi-device. `device_certs` needs enroll / list / **revoke-by-device** UI + API,
  not just a table.
- **E4 Key rotation.** Single static broker key, no `kid`/jwks (`well_known.rs:23`,
  `discovery.rs`). Long-lived device certs make rotation worse — consider `kid`/key-
  set now so rotation doesn't invalidate every device cert.
- **E5 SBO signing key.** `signSboEnvelope` signs with the **identity key** today;
  the device-cert model must decide what signs SBO envelopes (access-cert key?
  device key?) — folds into `3b8m`.
- **E6 Rate limiting + status-list scale** — see B2; status list is rebuilt-per-
  request over a monotonic index space (fine now, watch at scale).
