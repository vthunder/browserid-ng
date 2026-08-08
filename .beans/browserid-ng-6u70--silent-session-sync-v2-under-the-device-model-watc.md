---
# browserid-ng-6u70
title: 'watch() v2: explicit-trigger login/logout contract (silent minting rejected; FedCM-only automatic path)'
status: completed
type: feature
priority: high
created_at: 2026-08-05T00:52:12Z
updated_at: 2026-08-08T16:12:36Z
---

DECIDED 2026-08-08 (user + Claude session): silent cross-browser reconciliation is dead. watch() v2 is an **explicit-trigger contract**: login/logout signals always flow through watch() observers, but nothing mints silently — every login is user-triggered (button → popup/redirect), except FedCM where the browser mediates (automatic after first opt-in login, never 100% silent — the browser shows its own "signing in as…" UI).

## Background (what broke)

d9a6baf (2026-07-20) deleted the hidden communication_iframe and the silent-reconciliation contract went with it. Today include.js NEVER fires onmatch, onlogout, or onready (all assigned, none invoked — even explicit navigator.id.logout() doesn't fire onlogout; that's just a bug). The only automatic behavior is trySilentFedCM() (opt-in, FedCM browsers, login-only). Pre-deletion, the iframe path was already dead cross-origin from third-party storage partitioning (browserid-ng-1sy5).

## Rejected designs (do not re-litigate)

1. **Persist the presentation in RP-origin storage** — pointless: assertions expire in minutes; client-side verification decides nothing (a lying client fails at the RP verifier).
2. **RP-homed access keypair** (access cert minted over a key living in RP-origin IndexedDB) — the access cert has NO audience claim (AccessCertClaims: identity/holder/access_key/status; audience lives only in assertions), so the RP could mint assertions for ANY audience → the RP becomes a holder. Fatal.
3. **Audience-pinned "RP session cert"** — repairs (2)'s impersonation hole but dies structurally: pinning the audience at IdP mint time **discloses the RP to the IdP**, which the protocol goes out of its way to prevent; plus new cert type nobody else understands, new revocation surface (holder-shaped, would need broker UI), RPs must guard a powerful long-lived credential, burden on every verifier.
4. **Broker session probe from RP context (CORS)** — blocked by third-party cookie partitioning, same wall that killed the iframe.
5. **Storage Access API** — first grant needs a user gesture inside a VISIBLE broker iframe + a browser cookie-language permission prompt, grants silently lapse (Chrome ~30d, Safari ITP), per-RP per-browser. Strictly worse UX than the popup it replaces; first page-load can never be silent.

Bottom line: browsers deliberately removed silent cross-site login; FedCM is the only sanctioned replacement. There is no cross-browser silent path that doesn't hand the RP holder-shaped material or leak RP↔user associations.

## The v2 contract

- **watch() is the universal delivery channel**: however a presentation bundle arrives — dialog completion, redirect-mode return (pendingRedirectReturn; also the Arc/mobile same-tab fallback), FedCM token — it arrives via onlogin. (Already true in code; keep as the spec framing.)
- **request() (button → popup/redirect) is the normal login path.** No spontaneous login in non-FedCM browsers.
- **FedCM is the only automatic path**: trySilentFedCM() at watch() time, opt-in checkbox, server-enforced, browser shows its own UI moment.
- **onmatch is DROPPED** from the contract (it existed solely for silent reconciliation). loggedInUser survives with one small job: suppress FedCM auto-reauthn when the RP session already matches; a mismatched auto-reauthn account is delivered as a fresh onlogin.
- **onready = "the automatic phase is settled"**: fires after the FedCM attempt resolves (or ~immediately in non-FedCM browsers). Meaning: any later callback results from explicit user action. Un-flickers RP UI.
- **logout() stays, with two jobs**: (a) message to the identity layer — preventSilentAccess(), POST /fedcm/reset, clear the local auto-login flag — without which FedCM signs the user right back in on next load; (b) trigger onlogout in ALL same-origin tabs (BroadcastChannel/storage event). Same inversion-of-control as login (button → API call → observer): the RP writes teardown once, in the observer; the calling tab's firing is harmless idempotence, the other tabs' is genuinely new information.
- **onlogout triggers**: explicit logout() (all tabs); optionally a revocation signal (below). Nothing else.

## Remote logout / revocation ("logged out everywhere")

Status lists are public, cookie-less, bulk (per-IdP-domain, indexed by idx), served at /.well-known/browserid-status (registrar lib.rs:157) behind the broker's mirror-origin CORS layer — so both placements are technically live today:

- **SPECCED MECHANISM — RP-backend enforcement**: the RP's verifier already receives status refs when verifying the login bundle; it re-checks them on session activity and kills the RP session on revocation. Aggregate disclosure only ("rp.example uses browserid", not which user). Enforcement MUST be server-side anyway — a client that ignores a poll must not keep its session. Works with JS disabled. Verifier SDK should grow a check_status helper + guidance.
- **UX LAYER — client-side polling (user leaning yes, 2026-08-08: "adds to the system")**: include.js remembers only the status REF from the login bundle (a pointer — no keys, nothing holder-shaped) and polls so an open tab flips to logged-out without a reload — makes revocation VISIBLE (revoke a device in broker UI, watch open tabs drop). Privacy analysis: the status ref points at the ISSUING domain. Broker-issued chains ⇒ polling the broker leaks nothing new (its dialog already learned RP↔user at login). Primary-IdP-issued chains ⇒ direct polling leaks Origin + user IP to the primary IdP — exactly the party the protocol blinds. RECOMMENDED PLACEMENT: a caching **broker status proxy** (e.g. /status-proxy?uri=…) — page always polls the broker (no new info to broker), broker serves primary-IdP lists from cache (primary IdP sees only aggregate broker fetches; bulk lists + ETags make it ~free). RPs do zero work. Low frequency + jitter, pause when tab hidden. Never load-bearing — backend re-check stays the security boundary (a hostile client just doesn't poll).

## Semantics note (say it in the spec)

FedCM auto-reauthn means an onlogin can occur without fresh user gesture (browser-mediated, browser-visible). Assertions prove key possession + unexpired/unrevoked chain, not user presence. Persona's silent path had the same property.

## Implementation checklist

- [x] include.js: fire onlogout from logout() (currently never fired anywhere) + cross-tab propagation via BroadcastChannel/storage event
- [x] include.js: implement onready per the new semantic (fires once the FedCM attempt settles; ~immediately when FedCM unavailable/not opted in)
- [x] include.js: drop onmatch (decided: warn-and-ignore) from the API surface (decide: hard error vs warn-and-ignore for back-compat)
- [x] include.js: loggedInUser → suppress/correct FedCM auto-reauthn (skip when session matches; mismatch ⇒ fresh onlogin)
- [x] CSP (no inline-script changes; guard test green): any include.js/static inline-script edits need INLINE_SCRIPT_HASHES updates (routes/mod.rs guard test prints the hash)
- [x] Verifier/SDK: status-ref re-check helper + RP guidance for session-activity revocation enforcement
- [x] Confirm + implement client-side status polling (user confirmed 2026-08-08) via broker status proxy (recommended above; user leaning yes)
- [x] FedCM invisibility polish: fix stale comment at include.js:729 ("and the RP opted in" — no RP opt-in exists or should); consider stripping fedcm_optin from the dialog response before it reaches onlogin's second arg so RPs can't observe FedCM at all
- [x] Re-author the 12 test.fixme tests (silent-assertion ×7, include-api ×3, cross-origin-rp silent ×2) against THIS contract — they specified the silent behavior we just rejected; they are no longer the acceptance spec. Do not implement to them.
- [x] Spec docs: update watch()/logout() contract + the FedCM-presence semantics note

## Summary of Changes

Implemented 2026-08-08 (all tests green: broker suite + 7 new status-endpoint tests, sdk/js 17/17, e2e 19 passed / 1 pre-existing legacy skip).

- **include.js** — watch() v2: onmatch warn-and-ignored (never fires, no longer throws in stateless mode); onready fires once the page-load automatic phase settles (after FedCM auto-reauthn resolves, ~immediately otherwise); FedCM auto-reauthn suppressed when loggedInUser is a string; logout() now fires onlogout in the calling tab AND all same-origin tabs (BroadcastChannel + localStorage-ping fallback); every presentation (dialog/redirect/FedCM) delivers through one deliverLogin() which stashes the access cert's status ref and strips fedcm_optin so RPs cannot observe FedCM; revocation poll (5-min cadence + jitter, paused when hidden, fail-open, test hook window.BROWSERID_STATUS_POLL_MS) hits the broker proxy and fires onlogout + cross-tab broadcast + FedCM-autologin clear on a revoked bit.
- **Broker** — new routes/status.rs: GET /status/proxy?uri=… (307 to own /.well-known/browserid-status; foreign lists served only after full verification via the refactored verifier::fetch_foreign_status_list — cannot be an open proxy) and POST /status/check {refs} (fail-closed re-check for RP backends, ≤16 refs). /verify-access response now carries status_refs. Tests: browserid-broker/tests/status_endpoints_test.rs.
- **SDK (@browserid-ng/verify)** — verify() surfaces statusRefs; new checkStatus(refs) posting to /status/check (fail-closed); README guidance for session-activity re-checks.
- **e2e** — silent-assertion.spec.ts rewritten as the watch() v2 contract suite (onready-only page loads, logout same-tab + cross-tab, revoke-device→onlogout via poll); include-api.spec.ts + cross-origin-rp.spec.ts re-authored; zero fixmes remain from the original 12.
- **Spec** — protocol §7.3 session-signals contract (no silent minting; FedCM the only automatic path; logout symmetry; advisory revocation polling) and §6.3 distribution endpoints incl. the privacy rationale for the proxy.

Not committed yet — working tree holds all changes.
