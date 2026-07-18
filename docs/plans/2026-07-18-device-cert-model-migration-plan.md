# Migration plan — the device-cert model

**Epic:** browserid-ng-oup3
**Design:** `docs/design/browserid-end-to-end-flow.md` (protocol overview — the
source of truth for the model).
**Supersedes:** `docs/plans/2026-07-18-model-a-browser-first-agent-migration-plan.md`
and its subject-axis Phase 0–3 work. The "browser is the first agent" build
(user-signed provisioning cert + registrar endorsement + plain login cert) is the
**wrong shape** for this model and is superseded, not extended.

## The model in one paragraph

Two IdP-signed device-cert **purposes** (`authentication` → mints access certs;
`authorization` → signs warrants) crossed with a **subject** (`user` | `agent` |
any). An `authentication` device cert mints short-lived, **fresh-key access
certs** at the IdP (authentication). A **config cert** (`authorization`) signs
**warrants** over `(identifier, subject) → audience[+scopes]` — signed once,
stored, device-agnostic (authorization). The RP always receives **access cert +
assertion + warrant + config cert** and joins them by `(identity, subject,
audience)`. Every IdP MUST implement device-cert issuance + the mint API; the
fallback can't cover a domain that has a primary.

## What's superseded from the prior build (all on `main`, deployed)

- **`browserid-core` subject axis** (`Subject` on `Constraint`, `mint_self`) —
  the subject belongs on the **device cert**, not a user-signed constraint. Rework
  in Phase 1 (the enum survives; its home changes).
- **Broker `subject:self` mint + D2** (`/provision/mint` self-mode) — replaced by
  the device-cert issuance + access-cert mint APIs (no user-signed P_cert, no
  registrar endorsement). Phase 2–3.
- **`/demo-self-login`** (deployed) — a standalone artifact; will be rebuilt
  around the device-cert model (Phase 7). Harmless additive code; leave until the
  rebuild lands.
- The **subject-axis spec edits** (protocol §7, agent §4.1/§4.3) — re-cut in
  Phase 0 to the device-cert model.

None of this broke existing flows (all additive), so there is no urgent revert;
it is replaced as the new phases land.

## The RP-facing breaking change

Warrants become **mandatory on every login** (today a human login is a plain
`cert~assertion` with no warrant). Every RP/verifier must process a warrant. This
unifies the user and agent path but is **not backward-compatible** — pre-GA, this
is acceptable, but it is the single biggest downstream change and gates Phase 6.

---

## Phases

- **Phase 0 — Spec.** Rewrite `browserid-ng-protocol.md` + `agent-provisioning-
  and-grant-api.md` to the device-cert model: device certs (`purpose × subject`),
  the device-cert issuance API, the access-request-token + access-cert mint API,
  warrants over `(identifier, subject)` with revocation links, config certs,
  mandatory conformance, and the always-warrant RP presentation. Fold in Q5/Q8
  decisions. Supersede the subject-axis edits.
- **Phase 1 — Core types (`browserid-core`).** `DeviceCert { purpose, subject,
  identities, validity, key, iss }` (IdP-signed); `AccessRequestToken` (device-
  signed: identity, subject, fresh access pubkey); `AccessCert` (IdP-signed,
  fresh key, short-lived, revocation ref); `Warrant` re-cut to `(identifier,
  subject, audience, scopes)` + revocation ref; `purpose`/`subject` enums,
  fail-closed parsing. Retire the user-signed `ProvisioningCert` path.
- **Phase 2 — IdP device-cert issuance API.** Issue device cert(s) after auth
  (fallback SMTP / primary interactive), including **batch** (a user cert + one or
  more agent certs in one request) and config certs. IdP-signed.
- **Phase 3 — IdP access-cert mint API.** Verify an access request token + device
  cert; mint a fresh-key access cert; discretionary refusal. Replaces
  `/provision/mint` + `/provision/endorse` (no registrar/endorsement).
- **Phase 4 — Config certs, warrant issuance & registry.** Config-cert-signed
  warrants over `(identity, subject, audience, scopes)`; hosted-broker warrant
  **registry / status / revocation UI** (`jipx`); self-login auto-warrant; agent
  consent-scoped warrant.
- **Phase 5 — Client broker (keystore + flows).** Device keystore (non-extractable
  keys); cold bootstrap via the **WinChan popup** (RP login → email → discovery →
  device-cert issuance); access-cert minting; warrant fetch; RP presentation;
  **agent device-cert pairing** (device-grant). Retire the hidden-iframe /
  postMessage / session-cookie mint path.
- **Phase 6 — RP verification contract (breaking).** Always-warrant verification:
  access cert + assertion + warrant, joined by `(identity, subject, audience)`,
  both revocation links checked. Update `browserid-rp`, the JS/Python/Go verifier
  libs, and hosted `/verify`.
- **Phase 7 — Retire old path, rebuild demo, consumers.** Remove the superseded
  subject-axis/self-mint/`P_cert` code + old iframe path; **rebuild the demo**
  around device certs; **relocate SBO signing** (`browserid-ng-3b8m`, prereq for
  iframe deletion); migrate **mingo** (its own IdP + client) and **sbo** (verifier
  pin). 
- **Phase 8 — Docs/website, conformance tests, live validation.** README + site
  to the device-cert story; conformance suite (issuance + mint + always-warrant +
  fail-closed on unknown purpose/subject); live test on sandmill.org + mingo.

Sequencing: 0 → 1 → {2, 3} → 4 → 5 → 6 → 7 → 8. Phase 7's SBO relocation (`3b8m`)
gates the old-iframe deletion.

---

## Open build questions

- **Q5 — Cookies at mint.** Optional-only (never required, or cross-origin ITP
  returns). Decide what a cookie *adds* as a freshness/anti-abuse signal.
- **Q8 — Transports (no hidden iframe).** Confirm the WinChan popup covers the
  domain-primary device-cert return leg; define the agent device-cert pairing
  hand-off (device-grant based on `agent_provision.rs`).

## Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| Mandatory warrants break every existing RP | High (accepted) | Pre-GA; land Phase 6 + verifier libs before any RP cutover |
| Deleting the iframe breaks live SBO signing | High | `3b8m`: relocate `signSboEnvelope` first (Phase 7 prereq) |
| Non-conformant primaries lock out their users | Medium (by design) | Conformance is required; fallback only for no-primary domains |
| Fresh-key access certs + device-key possession proof done wrong | Medium | Access request token signed by the device key; IdP verifies before minting |
| Warrant privacy leak (aggregated site/service usage) | Medium | Warrants stored but not published/queryable; access-cert gate makes a leaked warrant unusable |
| mingo runs its own superseded iframe stack | Medium | Phase 7 parallel migration; mingo-idp already has a mint handler to evolve |

## Bean reconciliation

- **oup3** — re-scoped to the device-cert model (this plan).
- **Completed, now superseded (historical record, not reverted):** i32c (spec),
  54jz (core subject axis), wid3 (broker self-mint), 8fq2 (demo).
- **Superseded before starting → scrap:** the old todo phases (iframe-retirement,
  consumers, docs, conformance as previously scoped).
- **Still valid:** `3b8m` (SBO signing relocation).
- **New:** device-cert Phase 0–8 beans created under oup3.
