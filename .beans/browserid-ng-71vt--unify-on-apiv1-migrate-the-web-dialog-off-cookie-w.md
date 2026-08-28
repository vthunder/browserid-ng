---
# browserid-ng-71vt
title: 'Unify on /api/v1: migrate the web dialog off cookie /wsapi, retire the duplicated surface'
status: todo
type: feature
priority: normal
created_at: 2026-08-28T21:00:26Z
updated_at: 2026-08-28T21:00:26Z
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
