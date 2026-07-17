# Design memo — Agents as a core verb, and whether to adopt/extend FedCM

**Date:** 2026-07-17
**Status:** Research + design memo for review (no production code)
**Author:** design investigation for dan
**Context beans:** `browserid-ng-mr2n` (CLI-auth / agent-identity roadmap epic), `browserid-ng-3nsg` (primary-IdP agent-provisioning gap)
**Related design docs:** `docs/plans/2026-07-08-agent-native-browserid-design.md`, `docs/plans/2026-07-09-agent-delegation-chain-design.md`, `docs/plans/2026-07-17-label-self-delegation-agent-cert-design.md`

## The strategic goal (restated)

browserid should be a general-purpose identity protocol with **intrinsic, excellent agent support** — such that *it is not possible to be a conformant browserid IdP without supporting headless (delegated) agent cert issuance.* The framing to test: **"agents = delegated identity issuance," a core verb like HTTP `GET`, not a bolt-on.**

Three IdP situations exist today, and we want to collapse the middle one:

1. Domain supports the agent API → the client refreshes agent certs headlessly from that IdP. (Good.)
2. Domain has no browserid at all → the fallback IdP (`browserid.me`) handles agents end-to-end. (Good.)
3. Domain supports browserid **but not agents** (e.g. `sandmill.org`: classic interactive primary, `/provision/mint` → 404, see `browserid-ng-3nsg`) → **this is the case we want to make non-conformant.**

The problem dan flagged: classic browserid provisioning opens an **iframe** to the IdP where JS runs and talks to the dialog over **postMessage**. That is interactive and browser-bound. Making agent issuance a clean HTTP verb means either that machinery goes away, or we mandate HTTP agent endpoints alongside it without it feeling shoe-horned. This memo maps what is actually iframe-bound vs already-HTTP, sizes the "mandatory core verb" change, and analyzes FedCM (which — key find — the broker **already partially implements**).

---

## Part A — Current provisioning architecture

There are **three distinct cert-acquisition transports** in the tree today. Only the first is iframe/postMessage-bound. The other two are already plain HTTP.

### A.1 Interactive login (iframe + postMessage) — the browser-bound path

This is the classic BrowserID provisioning flow, used when a **classic primary IdP** provisions a user cert. It is genuinely iframe/postMessage-bound end to end:

- The dialog (running on the broker/`browserid.me` origin) discovers the user's home IdP via `/.well-known/browserid` and reads its `provisioning` path (`browserid-core/src/discovery.rs:29-35`, the `SupportDocument.provisioning` field).
- `browserid-broker/static/provisioning.js` (the dialog-side controller) creates a **hidden iframe** pointed at that provisioning URL: `document.createElement('iframe')`, `this._iframe.src = provisioningUrl`, appended to `document.body` (`provisioning.js:44-47`). A 30s timeout guards it (`provisioning.js:50-53`).
- Inside that iframe, the IdP's provisioning page loads `provisioning_api.js`, which shims `navigator.id.beginProvisioning`, `navigator.id.genKeyPair`, `navigator.id.raiseProvisioningFailure` onto a **postMessage channel to `window.parent`** (`provisioning_api.js:41-105`).
- The two windows converse over `postMessage`: `beginProvisioning` → dialog returns `{email, cert_duration_s}` (`provisioning.js:74-80`); `genKeyPair` → the **dialog** generates a non-extractable Ed25519 keypair via WebCrypto (`provisioning.js:82-90`, `_generateKeyPair` at `:135-154`) and returns only the public key; the IdP signs a cert and posts `registerCertificate` back with the cert (`provisioning.js:92-106`); failures come back as `raiseProvisioningFailure` (`provisioning.js:108-115`).
- The origin is pinned on both ends (`provisioning.js:59-66`), and there is a parallel `common/js/provisioning.js` (jschannel/`chan.bind` variant, `:88-116`) plus WinChan popup plumbing in `include.js`/`dialog.js` for the popup (vs iframe) case.

**This is exactly the transport that ITP / third-party-cookie deprecation breaks** — the same class of failure this project already hit ("ITP-dead iframe", commit `5759ed6` on the consent side). The key private material never leaves the dialog origin, but the *cross-origin iframe + postMessage + cookie* mediation is precisely what browsers are dismantling.

### A.2 Session-authenticated cert issuance (HTTP, but cookie-bound) — the secondary/broker path

When `browserid.me` (the broker/fallback) issues a cert for an email **it** is authoritative for, there is no iframe to a foreign origin — it is an HTTP POST — but it is gated on a browser **session cookie**:

- `POST /wsapi/cert_key` (`browserid-broker/src/routes/cert.rs:175-212`): reads the session from cookies (`get_session_from_cookies`, `cert.rs:186`), checks CSRF (`:188`), confirms the account owns the email, and calls the shared `issue_certificate` (`cert.rs:52-171`).
- The fallback IdP's SMTP-verified "primary-style" path is similar: `POST /cert_key` gated on a medium-lived, `SameSite=None` email-session cookie (`browserid-broker/src/routes/fallback_idp.rs:279-338`; module doc `fallback_idp.rs:8-16`). The dialog's `/provision` page still drives it via `beginProvisioning`/`genKeyPair`, so this path **rides the same dialog UI** but talks to same-origin HTTP + a cookie rather than a foreign iframe.

The private key here is generated in the dialog (client keystore); the server only ever sees a public key. `issue_certificate` is the **single issuance choke point** shared by browser and agent front doors (`cert.rs:47-52`).

### A.3 Agent (delegation-chain) issuance — already fully headless HTTP

**Confirmed: the agent path is already a clean, headless HTTP interface with no iframe and no postMessage, and it does not bootstrap off the interactive dialog at request time.** Its shape:

- The agent SDK `browserid-agent/src/lib.rs` holds a **provisioning credential** — a local provisioning key `P_priv` plus a `U_cert~P_cert` delegation bundle and the broker + IdP URLs (`lib.rs:92-105`). No user secret; no browser.
- `AgentIdentity::provision` (`lib.rs:215-260`) generates the agent's own keypair locally, then `mint` (`lib.rs:653-677`) does three ordinary HTTP calls: sign a `mint` request with `P_priv` → `POST {broker}/provision/endorse` for a fresh broker endorsement (`endorse`, `lib.rs:679-702`) → `POST {idp}/provision/mint` with `{request_bundle, endorsement}` (`idp_post`, `lib.rs:704-729`).
- The IdP side is `browserid-broker/src/routes/agent.rs`: `mint`/`reserve`/`list`/`revoke` (`agent.rs:121,222,276,310`), each `require_enabled` + `verify_as_target_idp` (`agent.rs:72-111`) then re-using the same `issue_certificate` as the browser path (`agent.rs:146-153`). Agent certs carry a `parent` attribution and require a user-signed **warrant** at presentation (`lib.rs:471-486`).
- Endpoints are registered flatly in the router: `/provision/reserve|mint|list|revoke` (`browserid-broker/src/routes/mod.rs:118-121`), gated by `agent_provisioning_enabled`.

So the "agents = HTTP verb" idea is **already true in implementation** for broker-rooted / fallback-rooted agent identities. What is missing is (a) making it **mandatory and discoverable**, and (b) covering the **classic-primary** case (`browserid-ng-3nsg`), where the home IdP simply doesn't serve `/provision/mint`.

### A.4 Discovery — what `/.well-known/browserid` advertises today

- The support document (`browserid-core/src/discovery.rs:17-36`) has exactly four fields: `public-key` (informational only — DNSSEC `_browserid` is the real key root, per the module doc `discovery.rs:1-8`), `authentication`, `provisioning`, `authority` (delegation). **There is no agent/mint capability field.**
- The broker serves it hard-coded to `authentication:/auth`, `provisioning:/provision` (`browserid-broker/src/routes/well_known.rs:23-27`) — notably it does **not** advertise its own `/provision/mint` capability even though it implements it.
- **Nothing in discovery today distinguishes agent-capable from not.** A client cannot structurally tell case (1) from case (3); it discovers the gap only by POSTing `/provision/mint` and getting a 404 (exactly the `browserid-ng-3nsg` failure).

### A.5 Part A conclusion

| Path | Transport | Browser-bound? |
|---|---|---|
| Classic-primary user login (A.1) | hidden iframe + `postMessage` (`navigator.id.*` shim) | **Yes — fully.** This is what ITP kills. |
| Broker/fallback secondary cert (A.2) | same-origin HTTP + session cookie; driven by the dialog UI | Partly — HTTP, but cookie- and dialog-gated |
| Agent delegation-chain mint (A.3) | plain HTTP: `endorse` + `POST /provision/mint`, dual-signed | **No — already headless.** |

The agent mint is already independent of the iframe. The iframe/postMessage machinery is confined to the **interactive human login** (A.1) and the dialog shell around A.2. Making agents a core verb therefore does **not** technically require touching the iframe at all — the two concerns are separable. The open question (Part B) is whether leaving the iframe in place is *coherent* given it's independently dying to browser-privacy changes.

---

## Part B — Making agents a mandatory core verb

Three sub-parts: (a) unify/mandate the endpoint, (b) make capability discoverable, (c) define conformance. Then the crux question: iframe goes or stays?

### B.1 (a) Mandate `/provision/mint` (+ endorse) as core endpoints

The endpoint already exists and already shares `issue_certificate` with the browser path. "Mandatory" is mostly a **spec + discovery + conformance** change, not a large code change *for IdPs that are already brokers*. The real work is the **classic-primary** case (case 3), which is the subject of the chosen `browserid-ng-mr2n` item-4 direction:

- The elegant path (already chosen on the epic): **name-constrained self-delegation** (`docs/plans/2026-07-17-label-self-delegation-agent-cert-design.md`). A base `user@domain` identity key self-issues a derived `user+label@domain` agent cert via a new constrained trust path in `browserid-core` + `sbo-core`. This means a classic primary needs **no new server endpoint at all** to be "agent-capable" — the *client* mints the agent cert from the user's existing cert/key, and RPs verify the self-delegation path. That is the cleanest way to make case (3) conformant without asking every legacy primary to deploy a mint endpoint.
- The fallback path (item 3 on the epic, `browserid-ng-3nsg`'s "real fix"): `browserid.me` mints agents for external-primary delegators it has authenticated, verifying the delegator's `U_cert` against the issuer's DNS-discovered `_browserid` key rather than its own. This keeps a live HTTP mint endpoint as the universal backstop.

So "one agent-capable endpoint" is really **two conformance stories**: (i) self-delegation the client can always do (no IdP cooperation) and (ii) an HTTP mint endpoint the IdP *may* run. Conformance should be satisfiable by **either**, so a classic primary can become conformant purely via the self-delegation spec rule + verifier support, with no deploy.

### B.2 (b) Add a mandatory agent-capability field to discovery

Concretely, extend `SupportDocument` (`browserid-core/src/discovery.rs:17-36`) with an agent-capability descriptor, e.g.:

```jsonc
{
  "public-key": "...",
  "authentication": "/auth",
  "provisioning": "/provision",
  "agent": {                       // NEW — mandatory for conformance
    "self_delegation": true,       // this IdP's certs may be self-delegated (spec rule honored by its RPs/verifiers)
    "mint_endpoint": "/provision/mint",   // OPTIONAL: a live headless mint endpoint
    "endorse_endpoint": "/provision/endorse"
  }
}
```

A client then structurally distinguishes conformant (has `agent`, with at least `self_delegation:true` or a `mint_endpoint`) from legacy (no `agent` block → non-conformant). The broker's `well_known.rs:23-27` would advertise its real capability instead of hiding it. This is a small, additive, backward-compatible change to the core type and one handler.

### B.3 (c) Define conformance so "browserid without agents" is non-conformant

Spec language: *A conformant browserid IdP MUST enable delegated (agent) identity issuance for its users, advertised via the `agent` block in its support document, satisfiable by either (i) honoring the self-delegation trust path for its certs, or (ii) serving the headless mint/endorse HTTP endpoints. An IdP advertising `authentication`/`provisioning` without an `agent` block is non-conformant (legacy).* Conformance is then testable by a probe: fetch `/.well-known/browserid`, assert the `agent` block, and for (ii) exercise `/provision/mint`.

### B.4 The crux: does the interactive iframe/postMessage login need to GO AWAY?

**Argument that it can STAY (agents mandated independently):**
- Part A proved the agent mint is already fully decoupled from the iframe. Mandating the HTTP/self-delegation agent verbs touches discovery, core trust paths, and conformance tests — **none of which live in the iframe code.** You can ship all of Part B and never open `provisioning.js`.
- The two flows serve genuinely different principals: *human interactive login* (needs UI, consent, a chooser) vs *headless agent mint* (needs a credential and a signature). Forcing them through one transport is the historical mistake, not the fix. Keeping them separate is *more* coherent, not less — "agents are a core verb" is satisfied by the verb existing and being mandatory, regardless of how humans log in.
- Lowest risk / smallest departure: no regression surface on the working human login.

**Argument that it must GO (or be replaced):**
- The iframe is **independently dying**. ITP and third-party-cookie deprecation break cross-origin-iframe + cookie mediation regardless of the agent work; this project already ate that pain on the consent side (commit `5759ed6`, "the ITP-dead iframe"). If interactive login stays on the iframe, the "excellent, intrinsic" identity protocol has a **rotting core for its most common flow (humans)** while agents are pristine. That's incoherent as a product story.
- Leaving A.1 in place means classic primaries keep provisioning **users** over the iframe even as they provision **agents** over HTTP — the very "shoe-horned" feeling dan wants to avoid, just relocated.
- The replacement for the interactive iframe already has an obvious shape — **FedCM** (Part C), which the broker has *already begun implementing*. So "the iframe goes away" is not a hypothetical cost; it's a migration that's partly underway.

**Recommendation for Part B:** Mandate the agent verbs **independently and now** (they don't need the iframe removed), *and* commit to **replacing** the interactive iframe with a browser-mediated model (FedCM) on a separate track — not because the agent work requires it, but because the iframe is failing on its own and a half-modern protocol is a worse story than a coherently-modern one. Sequence: (1) ship the mandatory `agent` discovery block + self-delegation conformance (small, unblocks case 3, no iframe work); (2) in parallel, mature the FedCM interactive path (already spiked) toward replacing A.1. The two tracks are independent but both point at the same end state: **all identity issuance is HTTP/browser-mediated, no cross-origin iframe.**

---

## Part C — FedCM: adopt and/or extend?

### C.1 What FedCM is, and the one thing it fixes

FedCM (W3C Federated Credential Management, [w3.org/TR/fedcm/](https://www.w3.org/TR/fedcm/)) replaces the cross-origin-iframe + postMessage + third-party-cookie federation pattern with a **browser-mediated** flow over fixed IdP HTTP endpoints: `/.well-known/web-identity` (anti-abuse allow-list of config URLs), a config file, an `accounts_endpoint` (GET, credentialed, `Sec-Fetch-Dest: webidentity`), and an `id_assertion_endpoint` (POST → `{ "token": … }`). The RP calls `navigator.credentials.get({ identity: … })`; the **browser** fetches the endpoints, renders native account/consent UI, and returns the assertion. Because the user agent is the mediator (native UI, explicit user choice, the `webidentity` fetch-dest the IdP must verify), the browser is willing to attach the IdP's cookies to that one request even though it originates RP-side — re-legitimizing the single cross-site cookie access federation needs while the tracking-shaped uses stay blocked. **This is exactly the transport that survives ITP / third-party-cookie deprecation — i.e. the fix for A.1's dying iframe.**

### C.2 It does NOT do agents (adopt ≠ extend)

Core FedCM is **architecturally human-in-the-loop**: an assertion is minted only after the user picks an account in native browser UI; there is **no supported way to get one headlessly** (auto-reauth fails silently and only for a returning approved user). It has **no delegation, no agent identity, no "key bearing a parent claim."** The in-incubation `w3c-fedid/delegation` proposal is **not** agent delegation — it targets **IdP unlinkability** for human logins (a `vc_issuance_endpoint` returning an SD-JWT VC holder-bound to a *browser* ephemeral key; the "holder" is the browser acting for a person). Its own README hedges it may go nowhere. And FedCM is **not universal**: shipped in Chrome/Edge (mandatory for Sign-in-with-Google since 2025), but **Safari has none and none planned, Firefox paused (~2025)** — so it can never be the *only* path. Sources: [Chrome IdP impl](https://developer.chrome.com/docs/identity/fedcm/implement/identity-provider), [FedCM architecture](https://privacysandbox.google.com/cookies/fedcm-architecture), [w3c-fedid/delegation](https://github.com/w3c-fedid/delegation).

**Conclusion: FedCM and the agent goal are orthogonal.** FedCM cannot carry a headless agent assertion; the closest primitive (SD-JWT holder-binding) is still gated by the interactive ceremony. So agents are **not** built on FedCM.

### C.3 The broker already spiked FedCM — for login, not agents

browserid-ng **already implements the FedCM IdP side**: `browserid-broker/src/routes/fedcm.rs` (`web_identity`, `config`, `accounts`, `assertion`, `reset`), wired at `routes/mod.rs:134-138` (`/.well-known/web-identity`, `/fedcm/config.json`, `/fedcm/accounts`, `/fedcm/assertion`), a `browserid_fedcm` session cookie + `fedcm_autologin` state (`session.rs:165-203`, `state.rs:82`), `tests/fedcm_test.rs`, `marketing/fedcm-demo.html`, and beans `browserid-ng-mhyp` (FedCM IdP support spike) / `browserid-ng-5qjf` (Chromium validation harness). So the interactive-login-over-FedCM migration is **partly underway** — the replacement for A.1's iframe already has running code.

---

## Bottom line

The agent goal and the iframe problem are **two independent tracks that happen to point at the same end state** (all issuance HTTP / browser-mediated, no cross-origin iframe), and FedCM belongs to only one of them.

**Track 1 — Agents as a mandatory core verb (do this now; small; unblocks case 3).** The agent mint (A.3) is *already* headless HTTP and decoupled from the iframe — mandating it touches **discovery, trust paths, and conformance, none of which live in iframe code** (Part B). Concretely: add the mandatory `agent` capability block to `/.well-known/browserid` discovery, make delegated (agent) cert issuance a required verb, and define conformance so "browserid without agents" is **non-conformant** — which converts case 3 from an awkward middle into a plain legacy/broken IdP, whose graceful degradation is "get an agent identity from a conformant domain you control" (not broker abuse). This is **not** built on FedCM. It is browserid's own HTTP verb, and for the not-yet-resolved *trust* shape of a self-hosted-key agent it reconnects to the parked self-derivation work (on the `selfderive-wip` branch) — but note the autonomous-renewal reality from that thread: self-derivation is interactive-only; **headless agents need an IdP-hosted mint endpoint**, which is precisely why mandating that endpoint as a core verb is the right lever.

**Track 2 — Replace the interactive iframe login with FedCM (separate track; already spiked; independently necessary).** Not because agents need it — they don't — but because A.1's iframe is **independently dying** to the same ITP/cookie deprecation this project already hit (commit `5759ed6`), and a protocol with a rotting core for its most common flow (humans) while agents are pristine is an incoherent story. The broker already has the FedCM endpoints (C.3); mature them toward replacing A.1. Keep a non-FedCM fallback for Safari/Firefox.

**What to NOT do:** don't try to carry agents over FedCM (it can't, C.2), and don't block the agent-verb mandate on the FedCM login migration (they're independent — Part B.4).

**Sizing.** Track 1 (agent-verb mandate: discovery field + conformance + the self-hosted-agent trust decision) is the smaller, higher-leverage piece and directly serves the "general-purpose, intrinsically agent-capable protocol" prize. Track 2 (FedCM login) is larger but already started and independently mandatory for survival. Sequence them in parallel; neither gates the other.
