---
# browserid-ng-71vt
title: 'Unify on /api/v1: migrate the web dialog off cookie /wsapi, retire the duplicated surface'
status: in-progress
type: feature
priority: normal
created_at: 2026-08-28T21:00:26Z
updated_at: 2026-08-28T22:40:49Z
parent: browserid-ng-9yyk
blocked_by:
    - browserid-ng-d0xb
---

Target architecture (Dan, 2026-08-28, option iii from the convergence analysis): the web wallet (browserid.me dialog) uses the SAME standardized /api/v1 registry APIs as any other wallet, authenticated with a real DPoP token — not a parallel cookie /wsapi surface. Principle: /api/v1 = the browserid standard surface every wallet uses; /wsapi retains ONLY broker-implementation-specific endpoints that are not part of any /api/v1 spec (a wallet's private glue to services it's tightly coupled with — legitimately outside the browserid specs). The duplicated cookie versions of standardized operations are REMOVED once the dialog migrates.

## Feasibility (analysis 2026-08-28): feasible, no protocol change
The dialog already holds every ingredient to mint a DPoP token: non-extractable Ed25519 config keys + JWS signing (dialog.js:342-388,236-239), and it ALREADY builds a broker-audience presentation with the registry scope for the session-join (dialog.js:485-486,1068) — exactly what POST /api/v1/token wants (self-presentation grantor==grantee, registry scope, binds to the config key: api.rs:281-337). Work = token-acquire+cache, a browser buildProof() (twin of api.rs:427), and a token-mode apiCall threading Authorization: DPoP + DPoP headers. Subtlety: token is config-key-bound (api.rs:337) and mintable only AFTER login, so sequence is cookie-login(C) → mint token → registry calls(A/B); re-exchange on identity/holder switch.

## Endpoint classification (from the analysis)
(A) already share a *_core with /api/v1 — migrate the dialog's caller, then delete the /wsapi route:
- allocate_warrant_status → /api/v1/warrants/allocate_status (allocate_status_core)
- register_warrant → /api/v1/warrants/register (register_warrant_core)
- device_certs → /api/v1/devices (device_certs_core)
- holder_assignment → /api/v1/holders/assignment (holder_assignment_core)
- account-page: warrant_respond / warrant_requests / list_warrants / revoke_warrant / forget_warrant (all shared cores already)

(B) need a thin new /api/v1 route (reuse existing store/core), then migrate + delete /wsapi:
- browser_holder (default browsers-namespace prefix getter — no token route yet)
- record_device_cert → the new devices/register (d0xb §4) covers this
- parent_of (read-only identity-graph lookup)

(C) STAY cookie-only in /wsapi — credential/session/issuance-rooted, no token-lane analog by design (d0xb): authenticate_user, stage/complete_signin_code, set_password, stage_email/complete_email_addition, complete_handle_claim, session_context, address_info, list_emails, device/issue, auth_with_presentation. These are the broker's private auth+issuance surface; /device/issue specifically is how browserid.me's own fallback ceremony page reaches its backend — the web-native embodiment of the ceremony-page contract a native wallet hits, not a cross-wallet API.

## Retirement policy
For each (A)/(B) endpoint: migrate the dialog (and account page) to /api/v1, verify, THEN remove the /wsapi route + its handler (the shared core stays; only the cookie wrapper goes). (C) endpoints remain. Net end-state: /api/v1 is the whole standard wallet surface; /wsapi is a short list of broker-private auth/issuance/lifecycle endpoints.

## Sequencing
After native-wallet convergence (d0xb) proves token-lane ergonomics on the simpler client. Incremental + reversible: each (A) op moves independently with cookie fallback intact until its route is deleted. CI does not run e2e — run Playwright locally before deploying any dialog change (memory: ci-does-not-run-e2e).

## Risks
Every dialog change is the dialog.js class green-CI won't catch; migrate one operation at a time behind local e2e. Account page shares the (A) cores' envelopes — migrate it in lockstep or it breaks on the deleted routes.

## Correction (Dan, 2026-08-28): /device/issue is not a wallet API — it's the ceremony page's backend

Earlier framing wrongly listed /device/issue among 'broker-private endpoints the web wallet keeps calling'. It is not a wallet-facing API for ANY wallet. Issuance has no wallet API in the specs — only the device-authorization ceremony-page CONTRACT (pubkeys in fragment → certs via return_url). How the issuer mints behind that page (session check, authorize_mint, /device/issue) is issuer-internal and unspecified, same as a primary's internal minting.

The current web dialog calls /device/issue directly only because it FUSES two roles: wallet (keys, identity choice) + issuer ceremony page (human auth, mint trigger). That fusion is an implementation artifact.

**Target = separate the roles (option a):** the web dialog becomes a PURE wallet. For a fallback identity it drives the same-origin device-authorization ceremony page exactly as a native wallet does, gets certs via the return contract, registers via /api/v1. It then never calls /device/issue — issuance is fully internal to the ceremony page (possibly not even a distinct route, just the page's POST handler). One issuance implementation for all wallets; one place issuance security lives (9it0, mint bar, verification freshness).

**Revised surface model — three surfaces, not two:**
1. Standard WALLET APIs: /api/v1 (registry) + the device-authorization ceremony contract (issuance). Every wallet, identical.
2. Ceremony-PAGE-internal endpoints: the issuer page's own human-auth + mint (authenticate_user, stage/complete_signin_code, set_password, stage_email/complete_email_addition, complete_handle_claim, /device/issue, and the auth/session primitives it needs). NOT wallet-facing; issuer-implementation-private even when browserid.me runs it. A clean wallet calls NONE of these.
3. address_info / list_emails / session_context etc. are ceremony-page/discovery concerns, likewise not wallet APIs.

So a clean wallet has ZERO broker-private endpoints — it uses only surface 1. Whatever remains under /wsapi belongs to the issuer's ceremony-page role, not the wallet role. This makes 'the web wallet uses the same APIs as any wallet' literally true. Adds scope to this bean: dialog restructure to split wallet-role (chooser + keystore + /api/v1 + ceremony driver) from ceremony-page-role (login/mint UI behind device-authorization).

## Progress (2026-08-29, autonomous run)

**Landed + deployed:** shared browser token client common/js/registry-token.js (self-presentation mint → /api/v1/token exchange, DPoP proofs signed with the config key, per-config-cert token cache, 401 re-exchange). Dialog wallet-role calls migrated: warrants/allocate_status + warrants/register (login + SBO-grant ceremonies), record_device_cert self-heal → devices/register (verified pair + move guard), device_certs keystore hygiene → GET /api/v1/devices (now runs post-identity-selection; state.proofs stashed at startup). No /wsapi routes deleted yet (cookie fallback intact). Full e2e green.

**Reclassification during migration:** holder_assignment is NOT a wallet-role migration target for the dialog — it serves move-HEALING for a device whose certs were revoked at move time, which can never mint a token; it belongs to the ceremony role (like /device/issue). The /api/v1/holders/assignment route still exists for valid-cert wallets. parent_of deferred (read-only; needs a spec section before any /api/v1 route).

**Open question for Dan (blocks consent/account/authorize migration):** the cookie lane authenticates the SESSION account; the token lane authenticates the account owning the PAIR the token was minted from. On consent.html/account.html a multi-account browser could hold a pair from account X while the session is account Y — migrated pages would show X's inbox/warrants where today they show Y's. Options: (a) accept pair-account semantics (single-account browsers unaffected; deep-linked ?code= lane already cross-account by design); (b) classify the broker-hosted consent/account PAGES as hosted-convenience surfaces that legitimately stay on the cookie lane (the native wallet + dialog already use /api/v1 — 'duplicated surface' then means only the DIALOG's usage, which is now migrated); (c) migrate but pin the token pair to an identity the session owns (needs a cheap 'session owns X' check). Route deletions wait on this call.

**Also remaining:** the option-a role split (dialog as pure wallet driving /device-authorize instead of calling /device/issue directly) — sequenced last per the bean.
