---
# browserid-ng-mhyp
title: FedCM IdP support spike
status: in-progress
type: task
priority: normal
created_at: 2026-07-13T16:41:07Z
updated_at: 2026-07-13T17:23:48Z
---

Spike: add FedCM as a progressive-enhancement fast path over the existing popup, with **browserid.me as a FedCM IdP** (fallback identities only). Modernizes the human-login half; retires the dead cross-origin silent-assertion iframe ([[silent-assertion-communication-iframe-is-dead-for]] / browserid-ng-1sy5). Does not touch agents, /verify contract, or the trust model. Follows the origin split ([[origin-split]]) — endpoints live on browserid.me (auth origin).

## Verified FedCM status (2026-07)
- Core FedCM production-ready on **Chromium only** (Chrome/Edge 136+). Login Status API, Login/Domain Hint, custom Params, Button/Active mode, Continuation API all shipped. Firefox in development (not shipped); Safari none planned. => popup fallback is PERMANENT, not a bridge.
- IdP Registration API ("any" registered IdP, RP doesn't name the IdP) = Stage-1 / flagged only. This is the piece that would let PRIMARIES (each domain its own IdP, user declares identifier) work — deferred to a phase-2 experiment.

## Design (option B — fallback-only, browserid.me as IdP)
Endpoints on browserid.me:
- `GET /.well-known/web-identity` -> `{"provider_urls":["https://browserid.me/fedcm/config.json"]}`
- `GET /fedcm/config.json` -> `{accounts_endpoint, id_assertion_endpoint, login_url:/account, branding}`
- `GET /fedcm/accounts` (credentialed; check `Sec-Fetch-Dest: webidentity`) -> user's verified emails from the session, as FedCM accounts (`id`, `email`, `name`, `login_hints:[email]`).
- `POST /fedcm/assertion` (Origin=RP, body: client_id, account_id, disclosure_text_shown, is_auto_selected, params(nonce)) -> a browserid assertion scoped to audience=Origin, nonce bound; CORS `Access-Control-Allow-Origin: <RP origin>`, `Allow-Credentials: true`.
- **Login Status**: emit `Set-Login: logged-in` on session establishment, `logged-out` on logout (unlocks the silent/auto-reauthn path). `login_url:/account` handles out-of-sync recovery (account page calls `navigator.login.setStatus` + `IdentityProvider.close()`).

RP side (include.js): feature-detect FedCM; if present `navigator.credentials.get({identity:{providers:[{configURL:'https://browserid.me/fedcm/config.json', clientId:<rp-origin>, nonce, loginHint?}]}, mediation:'optional'})`; token -> /verify unchanged; else -> existing popup.

- **clientId = RP origin** (registration-free; no pre-registration). audience = Origin. Preserves browserid's no-RP-registration property.
- **Fallback-only** (see the whole discussion): browserid.me can only vouch for identities it's authoritative for. Primaries stay on the popup (or phase-2 IdP registration).

## THE key fork (server-signed vs client-signed) — needs a decision
FedCM's `/fedcm/assertion` is a browser->server POST with **no client-side hook** — the browser sends only (cookie, client_id, account_id, params); no IdP JS runs, so you cannot sign locally and pass it in. Two lanes, mutually exclusive:
- **Silent lane**: server mints the assertion. Zero-click. Requires browserid.me to hold the ephemeral key server-side (Option 1: reproduce an identical cert~assertion server-side -> /verify unchanged; Option 2: single IdP-signed token -> additive /verify extension). Acceptable ONLY for fallbacks (browserid.me already owns them). Loses IdP audience-blindness (FedCM concedes this anyway).
- **Continuation lane**: `/fedcm/assertion` returns `{continue_on}`; browser opens a first-party browserid.me popup that signs client-side with the keystore, then `IdentityProvider.resolve(token)`. Preserves key custody, but it's a popup (loses the silent win). Natural home for [[passkey-graduation-for-fallback-identities]].
There is NO silent + client-signed cell. Silent XOR client-custody.

## Decisions needed before building the assertion endpoint
- **D1 (primary):** which lane for MVP? Silent/server-signed (accept server custody for fallbacks) vs Continuation/client-signed (keep keys in browser, accept popup). This shapes everything downstream. Recommendation: prototype BOTH in the spike to feel the UX, but lean Continuation for MVP to preserve the "keys never leave the browser" invariant, with silent as an opt-in later.
- **D2:** `/fedcm/accounts` needs the IdP cookie sent on a cross-site credentialed GET => `SameSite=None`. Our `browserid_session` is `Lax`+host-only (deliberate). Recommendation: a SEPARATE minimal `SameSite=None; Secure; HttpOnly` FedCM cookie scoped to /fedcm/*, not loosening the main session.
- **D3:** assertion format if silent lane — Option 1 (identical cert~assertion, server-held ephemeral key, zero /verify change) vs Option 2 (single token + additive /verify format). Tied to D1.

## Spike plan
- [ ] Decision-independent: implement `/.well-known/web-identity` + `/fedcm/config.json` (pure, testable) and include.js feature-detect + branch.
- [ ] Stand up a local HTTPS FedCM IdP (browserid.me) + a cross-origin RP in Chromium; validate the native account chooser appears and a token round-trips to /verify.
- [ ] Prototype the Continuation lane (client-signed) end-to-end; measure UX vs the silent lane.
- [ ] Resolve D1/D2/D3 from what the prototype shows.
- [ ] Write up findings + recommendation; decide whether to productize.

## Success criteria
A returning fallback user on Chromium signs in via FedCM with fewer clicks than the popup, the token verifies at /verify unchanged, and we have a clear recommendation on the lane + cookie + format decisions.

## Decisions resolved (2026-07-13)

- **D1 — RESOLVED: no Continuation mode.** FedCM is used ONLY in the silent (server-signed) lane. The existing **popup dialog stays the sole fallback** and the path for passkey accounts — rather than maintain two popup variants, keep one. Passkey-enabled accounts simply **never use FedCM**: browserid.me omits them from `/fedcm/accounts`, so the browser won't offer FedCM for them and `include.js` falls to the dialog (which does the WebAuthn). Net: FedCM = zero-click return for email-only fallbacks; everything else = the one dialog.
- **D2 — RESOLVED: separate `SameSite=None; Secure; HttpOnly` FedCM cookie** scoped to `/fedcm/*`; the main `browserid_session` stays `Lax`. This is REQUIRED — a Lax cookie is not sent on FedCM's credentialed accounts fetch, so without it FedCM can't see the user at all. Safe because: the cookie is read only by `/fedcm/accounts` (read-only, gated by the browser-only `Sec-Fetch-Dest: webidentity` header, returns data only to the FedCM mediator, never to any RP/attacker page), and the CSRF-hardened main session is untouched. Keep the two cookies in sync on login/logout.
- **D3 — RESOLVED: identical `cert~assertion`, zero verifier changes.** Refinement: the ephemeral keypair is **generated per-assertion inside the `/fedcm/assertion` request and discarded** — no new persistent key to protect; only the existing IdP key (already server-held) signs the cert, a throwaway key signs the assertion. So "server-side signing" adds no long-lived key-custody surface.

## Simplified scope after decisions
Client code = just the `include.js` feature-detect + `get()`; no `/fedcm/finish`, no Continuation, no client-side FedCM signing. Everything else is server endpoints. Passkey accounts are filtered out of `/fedcm/accounts`.

## Spike plan (revised)
- [ ] `GET /.well-known/web-identity` + `GET /fedcm/config.json` (pure, testable)
- [ ] `GET /fedcm/accounts` (separate None cookie; filter passkey accounts later)
- [ ] `POST /fedcm/assertion` — per-request ephemeral key, identical cert~assertion, audience=Origin, nonce bound
- [ ] `Set-Login` on session establish/logout; separate FedCM cookie plumbing
- [ ] `include.js` feature-detect → FedCM → popup fallback (prototype, not shipped)
- [ ] Local HTTPS FedCM IdP + cross-origin RP in Chromium; confirm native chooser + token round-trips through /verify UNCHANGED
- [ ] Write up findings + recommend productize/not

## Spike progress (2026-07-13) — server-side IdP validated

Implemented `browserid-broker/src/routes/fedcm.rs` (+ `session.rs` FedCM cookie, routes in `mod.rs`) and `tests/fedcm_test.rs`.

Done + proven:
- [x] `GET /.well-known/web-identity` + `GET /fedcm/config.json` — live, correct shapes.
- [x] `GET /fedcm/accounts` — returns the user's **Secondary** (fallback) emails only (enforces fallback-only: Primary + Agent filtered out); gated by `Sec-Fetch-Dest: webidentity` (400 without), 401 with no session/no eligible account. Reads the dedicated `SameSite=None` FedCM cookie, falling back to the session cookie.
- [x] `POST /fedcm/assertion` — mints a standard `cert~assertion` via a **per-request throwaway ephemeral key** (broker key signs the cert, ephemeral signs the audience-bound assertion, discarded); audience = `Origin`; rejects accounts the session doesn't own (403); sets FedCM CORS headers (echo Origin + allow-credentials).
- [x] Separate `SameSite=None; Secure; HttpOnly` FedCM cookie (path `/fedcm`), set/cleared in lockstep with the session; main `Lax` session untouched. (D2)
- [x] **Proof (tests/fedcm_test.rs, 2 tests green):** the FedCM-minted token verifies through the UNCHANGED RP verifier (`verify_assertion_with_dns` + `accepted_fallbacks`), yields the right email, honors audience binding, and is rejected by an RP that doesn't accept this broker as a fallback. Zero verifier changes confirmed (D3). Full broker suite green — no regression from the cookie change.

Findings:
- The assertion format binds **audience + expiry only** (no nonce field), so the FedCM `nonce` isn't embedded — same replay model as the popup path today; an optional nonce claim is a future add, no verifier change.
- `Set-Login` deferred: FedCM defaults to "unknown" status and queries `/fedcm/accounts` anyway, so it works without it; adding `Set-Login: logged-in/out` is a productionization optimization (avoids the query when logged out) + enables silent auto-reauthn.

Remaining (browser-validation phase, needs an HTTPS harness):
- [ ] `Set-Login` header on login/logout; passkey-account filtering in `/fedcm/accounts`.
- [ ] `include.js` feature-detect → FedCM → popup fallback (prototype; NOT yet touching the shipped shim).
- [ ] Local HTTPS FedCM IdP + cross-origin RP in Chromium: confirm the native account chooser renders, the credentialed `None`-cookie accounts fetch works, and the token round-trips. This validates the CORS/cookie transport that a Rust test can't.
- [ ] Decide productize/not from the browser UX.

Not committed yet — working tree only.
