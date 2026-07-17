# Model A — "the browser is the first agent": migration plan

**Epic:** browserid-ng-oup3
**Date:** 2026-07-18
**Supersedes the "two independent tracks" conclusion of** `docs/plans/2026-07-17-agents-as-core-verb-and-fedcm.md` (Model A goes further: it unifies human login *into* the agent flow rather than running them as parallel tracks).

## 0. The model in one paragraph

Human login is reframed as **provisioning the browser's stable non-extractable key as an agent of the user**. A one-time interactive bootstrap (top-level, first-party — the mingo-ytrs `consent.html` same-tab handshake, not a hidden iframe) yields a **provisioning credential**: a `U_cert~P_cert` delegation authorizing the browser's key to mint certs for the user, ~90 days, held client-side (key in non-extractable WebCrypto, delegation in IndexedDB). Cert issuance and refresh then become a **cookie-free, signature-authed `POST /provision/mint`** — the *same* endpoint agents use — with login-mode vs agent-mode selected by a single request parameter. The ITP-dead hidden-iframe + `postMessage` silent-refresh path is deleted. Because login now rides the mint verb, **an IdP cannot serve login without serving the agent mint** — the structural entanglement we wanted.

This plan is the synthesis of five parallel audits (spec, implementation, website/README, consumer apps, verifier/security).

---

## 1. The two decisions that make or break Model A (settled)

### D1 — The login cert MUST be a plain, untyped user cert. (RP compatibility)
Confirmed by the verifier audit against `browserid-core`, `browserid-rp`, SBO (`sbo-core/attribution.rs`), and mingo-idp (`verify.rs`): a login cert with `typ:None`, `agent:None`, `principal = the human's real email`, `issuer == email domain` verifies **identically to today's `/wsapi/cert_key` cert**. Nothing on any RP keys on *how* a cert was minted.

Therefore, non-negotiable constraints:
- `login:bool` is a **mint-request parameter, never a cert claim**. If stamped into the cert, `Certificate::parse` (`certificate.rs:221`, fail-closed on the `(typ, agent)` table) rejects it at every pre-existing RP.
- **No `@self` sentinel in the `principal`.** It would break `issuer == domain` (`assertion.rs:336`) and `Principal::domain()`. The `@self` marker from spike A is a *constraint/mint-layer* convention only; the cert principal is the real email.
- Login-mode mint therefore calls the existing plain path `Certificate::create_with_status` (`certificate.rs:132`) — **no cert-struct change, byte-identical to a normal user cert.**

**Consequence for docs:** the "reject any `agent` presentation on a human login endpoint" guidance (verify-quickstart, sdk/js) is **not** a correctness risk under A — the browser presents a plain `cert~assertion`, not `agent_cert~warrant~assertion`. Add a clarifying note; change no RP code. (This is itself a third argument for D1.)

### D2 — Login must be an explicit, signed capability. (The #1 security gap)
Today `POST /provision/mint` → `ensure_agent_identity` (`routes/agent.rs:167`) unconditionally mints an **agent** cert for a derived `<name>@<domain>`, gated only by `constraint.authorizes(name)`. **There is no notion of a login-capable vs agent-only credential.** If we let any provisioning credential mint a plain cert for its delegator's real email, then *every agent-provisioning credential silently becomes an account-takeover credential*.

Required control: reframe `Constraint` (`provisioning.rs:97`) as a **typed capability descriptor** and add a **signed `kind` axis (login vs agent)** to it. It is set at P_cert creation (so it is signed by `U_priv` = user-consented), carried through `VerifiedRequest.constraint`, and **enforced at mint**: refuse to emit a plain/login cert for `verified.delegator` unless the verified P_cert grants the login kind. An agent-only credential (names/patterns only) must be provably incapable of minting a login cert.

**Framing (from design discussion 2026-07-18):** the constraint already carries axes — `names` (exact) and `patterns` (`foo+*@domain` wildcard). Login-vs-agent is simply a new axis on the same descriptor; validity is a partial axis (P_cert has its own ~90d exp; the minted-cert exp is the IdP's call, requestable/recommendable). Two rules make this safe and extensible:
1. **Who signs which half:** the IdP certifies *identity* (`U_cert`); the **user's key `U` signs the authorization + constraint** (`P_cert`) as an act of consent. So "what kind" is baked in at authorize time and cannot be widened later without re-signing with `U`.
2. **Fail closed on unknown axes:** the mint endpoint MUST reject a credential whose constraint carries a capability axis it does not understand — never ignore it (mirror the fail-closed `typ` table in `certificate.rs:221`). This is what lets us add axes over time: old verifiers safely refuse what they can't evaluate instead of over-granting.

These two decisions are the spine. Everything else is mechanical.

---

## 2. Additional required controls (security audit)

1. **Plain-cert-for-self issuance path.** The existing agent guardrails in `issue_certificate` (`cert.rs:108-144`: parent must be a verified, owned email; agent email == `<name>@<parent-domain>`) do **not** cover a plain-cert-for-the-delegator's-own-email path. A new branch must re-assert: delegator email is verified & owned by the account, `issuer == its domain`, and the login capability is present — to prevent minting a plain cert for a `victim@domain` the credential never proved.
2. **P_cert revocation at mint = "logout everywhere."** Today `verify_as_target_idp` (`agent.rs:72`) checks signatures + endorsement + expiry only — **no status check on the P_cert.** A stolen-but-revoked provisioning credential would keep minting fresh 24h certs until P_cert expiry (90 days). Required: a **provisioning-credential status ref consulted at mint / at endorsement time**, and a revoke endpoint that kills the P_cert (not just an identity). This is the durable "logout everywhere" guarantee; per-identity `StatusRef` (`cert.rs:99`) remains the ≤5-min RP-side kill for already-minted certs.
3. **Quota / identity-type separation.** A login cert is for the user's *own* real email — it must **not** consume `max_agent_identities_per_user` and must **not** create an `EmailType::Agent` row. Do not route login through `ensure_agent_identity`.
4. **CSRF is structurally gone (a win) — keep it that way.** The mint path is signature-authed, cookie-free, so a cross-site POST proves nothing. **Do not add a cookie fallback to mint.** (Relatedly retires the `y2ho` "CSRF generated but never enforced" concern for this path.)
5. **Replay hardening for login-mode (open).** `R` is 10-min-lived and the endorsement binds the bundle hash, but the endorsement is not tracked as consumed — within 10 minutes the same bundle can be replayed to re-issue certs. Idempotent/acceptable for agents; **reconsider a nonce/jti for login-mode.**
6. **Bootstrap handoff hygiene.** Only the *delegation* (`U_cert~P_cert`) may cross the popup/same-tab channel — never a private key or a minted cert. The browser's `P_priv` stays non-extractable (mitigates the new ~90-day client-side credential's theft surface).

---

## 3. Implementation surface (impl audit)

### Rust — `browserid-core`
- **CHANGE** `provisioning.rs`: add signed login-capability to `Constraint` (line 97); add `login` to `ProvisioningRequestClaims` (~284, `#[serde(default)]` for back-compat) + a `mint_login()` sibling or param on `mint()` (348); surface via `VerifiedRequest` (already carries `request` at 612, so the handler reads `verified.request.login`).
- **REUSE (no change)** `certificate.rs` — login-mode mint uses `create_with_status` (plain cert). `assertion.rs` — plain `cert~assertion` path, no warrant. Delegation chain `verify()` unchanged.

### Rust — `browserid-broker`
- **CHANGE** `routes/agent.rs::mint`: new login-mode branch — enforce login-capability (D2), route to the new plain-cert-for-self path, skip agent quota/`EmailType::Agent`.
- **CHANGE** `routes/cert.rs`: new plain-cert-for-self branch in `issue_certificate` (§2.1 checks).
- **CHANGE** `verify_as_target_idp` (`agent.rs:72`) + revoke: consult/kill the provisioning-credential status ref (§2.2).
- **CHANGE** `routes/well_known.rs`: advertise the `agent` capability block (`mint_endpoint`/`endorse_endpoint`/`self_delegation`) — currently hides `/provision/mint`. Makes login-via-mint discoverable.
- **REPLACE** `/wsapi/cert_key` (`cert.rs:175`) as the login path — kept only for the bootstrap ceremony if needed; the durable refresh is mint.

### Browser client — `browserid-broker/static/`
- **REUSE verbatim:** `common/js/keystore.js` (non-extractable keys + `putPending`/`getPending`/`clearPending` staging, lines 148-157); `consent.html` same-tab handshake (`startSameTabProvision` 112-133, `consumePendingProvision` 143-173); `winchan.js`; `dialog.js` response-exit (`returnAssertion`/`sendResponse`).
- **REPLACE the return-leg payload:** today `startSameTabProvision` → `/provision_return` deposits a **one-shot cert**. Change it to deposit a **reusable provisioning credential (delegation)**, and add the browser client that mirrors `browserid-agent`'s `mint`/`build_bundle`/`endorse` with `login=true`. (Note: `/provision/mint` does not exist in the static tree yet — new endpoint.)
- **REPLACE** `dialog.js` `generateCertificate` (227-253, the `/wsapi/cert_key` login mint) and `handlePrimaryIdP`/`tryPrimaryProvisioning` (545-643, the hidden-iframe provisioning) with credential-provision + cookie-free mint.
- **NEW (mostly assembly, not new crypto):** client-side `P_cert` (delegation) signing in JS **already exists** at `static/account.html:706-712`, and a complete browser mint driver (`endorse → reserve/mint`, signed with the provisioning key) exists at `account.html:670-719` — extract these to a shared module rather than writing them. The `/bootstrap` top-level page is an assembly of the existing `consent.html` + `account.html` pieces. Genuinely new: the explicit login-consent UI, the login:bool convention, and CSP inline-script hash updates (`INLINE_SCRIPT_HASHES` in `routes/mod.rs`; the guard test at `mod.rs:497-521` prints the new hashes — run broker tests before any dokku push). Note `/provision/mint` is already mounted in the route table (server-side); only the *browser client* doesn't call it yet.
- **DELETE (clean):** `static/provisioning.js`, `static/provisioning_api.js`, `static/common/js/provisioning.js` (all three are pure hidden-iframe cert plumbing).
- **DELETE (conditional — see §4):** `static/communication_iframe.html`, `static/communication_iframe/start.js`.
- **REWORK** `static/include.js`: the embedded `communication_iframe` injection (line ~1171) and `watch()` reliance are coupled to the deleted iframe. (Ties into bean `1sy5` — silent assertion via the comm-iframe is already dead under storage partitioning.)

---

## 4. The hard prerequisite: relocate SBO typed-signing before deleting the iframe

`communication_iframe/start.js:156-241` hosts the **live SBO envelope-signing capability** (`signSboEnvelope`, `loadSboWasm`) — a separate feature layered on the *same* hidden iframe as the dead silent-refresh. Deleting the iframe without relocating this **silently breaks SBO signing.** So iframe retirement is gated on: **relocate `signSboEnvelope` to the same-tab/popup transport first.** This is a sequencing dependency, not a clean delete, and it links this epic to SBO.

---

## 5. Consumer impact (consumers audit)

- **SBO — UNAFFECTED.** Pure verifier; blind to mint mechanism, cookies, key rotation, iframe. A login cert flows through the exact `message_attribution` path today. No `login:`/`@self` dependency. Only conceivable touch: bump the `browserid-core` pin *if* the cert JWS shape changed — and per D1 it does not. Effectively a no-op. (Keep the broker domain in `/sys/trust/brokers` for broker-issued login certs.)
- **mingo CLI — OPPORTUNITY / near-unaffected.** Already embodies Model A: holds a `U_cert~P_cert` `AgentCredential` and cookie-free re-mints against `/provision/mint` (`whoami` even says "re-mints automatically on next use"). Model A is the generalization of this to the browser. Only churn: endpoint unification when `browserid-agent` collapses login/agent onto one mint — a pin bump, not a rewrite.
- **mingo-idp / mingo-web — parallel migration (BREAKS + OPPORTUNITY).** mingo runs its *own* hidden-iframe + `postMessage` + `SameSite=None` + FedCM silent-refresh stack (`mingo-idp/static/provision.html`, `provisioning_api.js`, `routes.rs:279-291`/`set_session_cookie`; `mingo-web/app.js` silentLogin/FedCM/signer-popup). This is the same ITP-dead pattern and must undergo the same browser-as-first-agent migration. Good news: `mingo-idp/agent.rs` already implements the delegation-chain mint login should unify onto, and a partial same-tab fix (`/provision_return`) already exists. **Treat mingo as a second instance of this plan.**

---

## 6. Spec & docs (spec + web audits)

### Spec (`docs/specs/`)
- **§7 "Primary IdP & browser integration"** — REWRITE (the epicenter): browser provisions a stable key as an agent; the `/provision` iframe page + `provisioning_api.js` postMessage + `communication_iframe` silent-refresh are retired; `/auth` is repurposed as the one-time bootstrap.
- **§4.1 cert `typ`** — record D1: login-mode emits an untyped user cert (resolves contradiction **C1**).
- **§4.3 `/provision/mint`** — EXTEND: the shared core verb; login-mode → untyped user cert, agent-mode → `browserid-agent-cert-v1`; cookie-free for both.
- **§4.1 Constraint / "unconstrained key MUST be rejected"** — resolve **C2** (login-scoped constraint / login-capability field).
- **"agent identity MUST NOT serve as delegator"** — resolve **C3** (the login cert is the user's own identity, not agent-attributed).
- **§6.4 status/revocation** — EXTEND with provisioning-credential revocation = logout-everywhere.
- **§3.1 discovery table** — advertise the mint endpoint + agent capability block.
- **§9 conformance** — NEW: "browserid without the mint verb is non-conformant; conformant login MUST be cookie-free and iframe-free."
- **`browserid-ng-divergence-analysis.md` item #7** — flip KEEP → RETIRE for the iframe/postMessage transport (the `navigator.id` rejection stays).
- Feeds bean `v9rz` (write the canonical spec).

### Website / README
- **`README.md` §"Human sign-in"** — TECHNICAL fix only (most-linked, most-wrong: teaches `navigator.id.watch/request` + `include.js`). Replace the dead API snippet with the real mechanism (provisioning credential + cookie-free mint refresh). **Keep the agent-forward GTM positioning** — agent identity stays the headline; human login being first-class is a technical truth, not a co-headline. Do NOT re-pitch human login as "the first instance of the agent flow" in marketing copy (the web audit over-rotated here); just correct the stale technical content and the ASCII diagram's refresh path.
- **`marketing/index.html`** — UPDATE audience-toggle/hero copy ("human sign-in included" → "your browser is your first agent").
- **`marketing/fedcm-demo.html`** — REFRAME as the legacy path A retires, or rewrite.
- **verify-quickstart.md / sdk/js/README.md** — add the clarifying note (browser login is a *plain* presentation, agent-rejection guidance stays correct); no code change.
- **NEW memo** — "Model A — the browser is the first agent" (this doc is its working draft) superseding the two-track memo.

---

## 7. Phased rollout

- **Phase 0 — Spec & design.** Write the Model A spec sections (§6), resolve C1–C6, define the login-capability constraint, login-mode mint, logout-everywhere, discovery, conformance. Source of truth; unblocks the rest.
- **Phase 1 — Core types.** `browserid-core`: login-capability on `Constraint`; `login` on the request; thread to `VerifiedRequest`; login-mode → `create_with_status`; tests. (Hardened version of spike A's core.)
- **Phase 2 — Broker issuance security.** The load-bearing controls: login-mode mint branch + login-capability enforcement (D2); plain-cert-for-self path (§2.1); P_cert revocation at mint (§2.2); quota separation; discovery advertisement. **No cookie fallback.**
- **Phase 3 — Browser client.** Return-leg → provisioning credential; JS mint client (login=true); replace `dialog.js` login path; client-side P_cert signing; login-consent UI; CSP hashes.
- **Phase 4 — Iframe retirement.** *Prereq:* relocate SBO `signSboEnvelope` (§4). Then delete the iframe/postMessage files; rework `include.js`.
- **Phase 5 — Consumers.** mingo CLI endpoint unification (pin bump); **mingo-idp/mingo-web parallel migration**; SBO re-pin (no-op).
- **Phase 6 — Docs/website.** README + spec suite + marketing + fedcm-demo + clarifying notes.
- **Phase 7 — Conformance & live validation.** Guardrail tests (can't-mint-login-without-capability; revoked-P_cert-can't-mint; RP-unchanged); live test on sandmill.org + mingo.

## 8. Open questions to close in Phase 0

- **OQ1** — login-mode replay: add a nonce/jti to `R`, or accept the 10-min window? (§2.5)
- **OQ2** — how the browser obtains its provisioning credential at bootstrap: adapt the registrar device-grant `agent_provision.rs::complete` (binds a signed delegation to the agent pubkey) for in-browser same-tab, vs a dedicated bootstrap. The `consent.html` handshake is the browser leg; it must return a delegation.
- **OQ3** — provisioning-credential lifetime & rotation policy (90-day default) and the re-bootstrap UX when it expires.
- **OQ4** — SBO signing's new home (same-tab typed-signing surface) — coordinate with the typed-signing extension design (`2026-06-24-typed-signing-extension-design.md`).

## 9. Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| Login cert accidentally agent-shaped → breaks all RPs | Critical | D1: byte-identical plain cert; login:bool is a request param only |
| Agent credential mints a login cert (account takeover) | Critical | D2: signed login-capability on Constraint, enforced at mint |
| Stolen/revoked P_cert keeps minting for 90 days | High | §2.2: P_cert status ref at mint + kill-P_cert revoke |
| Deleting iframe breaks live SBO signing | High | §4: relocate `signSboEnvelope` first (hard prereq) |
| mingo's own iframe stack breaks | Medium | §5: mingo is a parallel migration, sequenced after the pattern lands here |
| ~90-day client-side credential exfiltration | Medium | non-extractable WebCrypto P_priv; delegation-only over the channel |
| login-mode replay within 10-min window | Low/Medium | OQ1: nonce/jti for login-mode |
</content>
