---
# browserid-ng-dw35
title: '[M7] Phase 1: fix address_info oracle + enumeration-safe sign-in UX'
status: completed
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-08-20T14:19:32Z
parent: browserid-ng-wre6
---

Phase 1 of the M7 account-enumeration fix (docs/security-audit-2026-07-29.md). Closes the sharpest leak — the unauthenticated `address_info` account-state oracle — and makes the sign-in dialog enumeration-safe. The four remaining lifecycle oracles are Phase 2 (browserid-ng-8gqm, blocked by this).

This body is the build spec: it is self-contained enough to start from directly.

## The leak

`GET /wsapi/address_info` (browserid-broker/src/routes/email.rs, handler ~line 634) is unauthenticated and returns an account-level `state` field (email.rs ~771-786) computed from `has_password(user_id)` and `email.last_used_as` via `compute_state` (~605-630). A single query reveals: (1) the account exists, (2) whether it is password-backed, (3) its primary/secondary transition history. The dialog's cold sign-in (browserid-broker/static/dialog.js ~608-704) branches on this `state`, so the leak is structural — the client asks the server "what should I do with this account?" before the user has proven anything.

## Decision — branch on domain-level facts only

`type` (primary/secondary) and `proof` (smtp/oidc/atproto/none) are properties of the DOMAIN's DNS/authority config, independent of account existence, so branching on them leaks nothing. Rebranch the whole flow on those instead of on `state`:

- primary domain -> its own IdP issues certs. Unchanged.
- proof==oidc (Gmail-hosted) or proof==atproto (Bluesky handle) -> prove-first UNCONDITIONALLY. The bridge often reuses a live Google/Bluesky session (one tap). No password screen; existence/password get resolved server-side AFTER the proof, where distinguishing them leaks nothing.
- proof==smtp (plain mailbox, the residual) -> optimistic password screen with an "email me a code" escape hatch for people without an account/password.
- proof==none (unprovable) -> refuse ("can't sign in with this email"). Domain-level, no leak.

This confines the one cost (showing a password box to people who may not have an account) to plain-mailbox domains only; everyone on a bridge-provable domain gets clean prove-first for free.

## Build tasks

- [x] address_info (email.rs ~634): stop returning the account-level `state` field to unauthenticated callers. Return domain discovery only (type, proof, claim, issuer, auth, prov, device_auth, access_mint, agent_device_auth). Move compute_state / has_password behind the session-authenticated or post-proof path where the UX actually needs it and it can't be probed.
- [x] dialog.js cold sign-in (~608-704): rebranch on type + proof instead of state. Drop the `state`-gated conditions at ~635-649 so oidc/atproto domains prove-first unconditionally. Implement the smtp optimistic-password + code-escape screen. Keep the primary path unchanged.
- [x] password-verify endpoint: make wrong-password and no-such-account responses IDENTICAL in body, status, and timing (constant-time compare against a dummy hash when the user is absent). This is what makes the optimistic password screen enumeration-safe.
- [x] Tests: assert address_info returns byte-identical responses for an existing vs non-existing address on the same domain (per proof type). Assert password-verify is existence-indistinguishable. Add a SqliteStore test, not just memory-store.

## Constraints (project memory)

- Editing the broker's static inline scripts requires updating INLINE_SCRIPT_HASHES in browserid-broker/src/routes/mod.rs; the guard test prints the new hash. Run broker tests before any deploy. (memory csp-inline-script-hashes)
- Run cargo through `ssh localtest '...'` — avoids the macOS per-binary notarization stall. (memory macos-gatekeeper-test-binary-stall)
- e2e is NOT run by CI. Build + warm the broker on :3000 first, then run Playwright locally before considering this done — a green CI proves nothing for dialog.js. (memories ci-does-not-run-e2e, e2e-needs-a-warm-broker)
- memory-store tests hide sqlite-only constraints; add a SqliteStore test for any store/schema behavior. (memory sqlite-only-constraints-invisible-to-memory-store-tests)

## Done when

Unauthenticated address_info and password-verify do not distinguish account existence (test-proven), the sign-in dialog branches only on type+proof, and Playwright passes locally against a warm broker for primary / oidc / atproto / smtp sign-in. Then unblock browserid-ng-8gqm (Phase 2).

## Summary of Changes

Shipped Phase 1 of M7; all broker tests (334) and Playwright e2e (104, warm broker) green locally.

**Server (browserid-broker):**
- `address_info` (routes/email.rs): `state` is now `Option` and computed ONLY when the calling session owns the address. Cold callers get domain facts only; the existence lookup is skipped entirely, so existing vs non-existing addresses produce byte-identical responses. A session that does not own the address also gets no state.
- `authenticate_user` (routes/auth.rs): no-such-account, password-less account (empty/unparsable hash — previously a 500 oracle!), and wrong-password now return identical status+body, and every failure path burns one bcrypt verify against a process-static dummy hash (timing-uniform).
- **New unified sign-in code endpoints** (routes/signin_code.rs): `POST /wsapi/stage_signin_code {email, pass}` + `POST /wsapi/complete_signin_code {email, token}`. This is the smtp escape hatch done enumeration-safe by construction: staging responds identically whether the account exists; completion resolves create-vs-reset server-side AFTER the mailbox proof. The reset branch carries complete_reset's fences verbatim (kgb9 sibling unverify, H2 session eviction) and re-checks existence to never duplicate an account. New `VerificationType::SigninCode` (own type so the reset/creation status oracles never see these pendings; sqlite TEXT mapping added).
- routes/test.rs accepts `type=signin_code` for e2e code retrieval.

**Dialog (static/dialog.js + dialog.html):**
- `handleEmailChosen` rebranched on type+proof; the typed email-form path now delegates to it (one state machine). oidc/atproto prove-first unconditionally (stored device pair still short-circuits to completeSignIn); proof=none refuses on the domain fact; smtp cold shows the optimistic password screen (`showPasswordScreen({optimistic})`: neutral heading, forgot-link hidden, "No password, forgot it, or new here? Email me a code" hatch). State-present (session-owned) branches keep the precise routing (transition_*, unverified, known).
- The create screen is repurposed as the sign-in-code screen (neutral copy, `stage_signin_code`); the verify screen completes via `complete_signin_code` + authenticate. The old dialog reset flow (forgot-password link) is only reachable from state-present screens; the classic stage_user path is no longer used by the dialog.
- Password auth success now re-checks address_info under the fresh session to route kgb9 re-verification (replaces the reverifyAfterAuth flag, which a cold flow could no longer set).

**Account page (static/account.html)** — collateral in scope: its cold sign-in also branched on `state`. Now: optimistic login screen + the same unified code hatch; create/create-code modes use the signin_code endpoints; the stage_reset/reset-code lane removed from reachable flow. INLINE_SCRIPT_HASHES updated (routes/mod.rs).

**Tests:** address_info suites rewritten to owner-session semantics + byte-identical-per-proof-lane assertions (smtp + atproto + unprovable); authenticate_user indistinguishability test (incl. the password-less 500 case); new signin_code_test.rs (stage indistinguishability, create branch, reset branch with fences, wrong code, authority refusal, race re-check, and a SqliteStore pending roundtrip for the new enum value). e2e: DialogPage gained `openSigninCodeScreen`/`emailCodeLink`; new-user-signup, reset-password (rewritten to unified flow), cancel-account, remove-email, sign-in updated to the enumeration-safe UX.

**Notes for Phase 2 (8gqm):** the dialog and account page no longer call stage_user/stage_reset cold, which frees Phase 2 to normalize those endpoints without UX coupling; password_reset_status / user_creation_status remain as oracles to fix there. docs/security-audit-2026-07-29.md M7 row still lists all five endpoints — update it when Phase 2 lands.
