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
