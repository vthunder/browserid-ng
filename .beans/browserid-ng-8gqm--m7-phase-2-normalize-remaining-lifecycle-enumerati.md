---
# browserid-ng-8gqm
title: '[M7] Phase 2: normalize remaining lifecycle enumeration oracles (reset/creation/email-status/stage_user)'
status: completed
type: bug
priority: normal
created_at: 2026-08-20T13:41:25Z
updated_at: 2026-08-20T20:58:22Z
parent: browserid-ng-wre6
blocked_by:
    - browserid-ng-dw35
---

Phase 2 of the M7 enumeration work (browserid-ng-dw35 is Phase 1: address_info + sign-in UX). This bean covers the four remaining unauthenticated lifecycle oracles that independently leak account existence. Decision philosophy is the same as Phase 1: normalize responses so existence is not distinguishable; where a UX branch is unavoidable, key it on domain-level facts (type/proof), never on account state. See docs/security-audit-2026-07-29.md (M7) and the dw35 decision note.

## Decided plan (2026-08-20, with Phase 1 shipped)

Phase 1 left all four oracles with ZERO production consumers (dialog, /account,
and /authorize all use the unified signin_code lane), so the decision — made
with the user — is to DELETE the redundant surface rather than normalize it.
signin_code is the single cold code-mailing lane, enumeration-safe by
construction; the classic reset lane and the persona-era polling endpoints are
retired outright.

## Original oracle list (superseded by the plan above)

- [ ] stage_reset (browserid-broker/src/routes/reset.rs:45-48): drop the EmailNotFound 404. Always return the same "if that address exists, we've sent a code" response shape whether or not the user exists. Keep the existing require_smtp_authority / throttle checks but ensure they run in a way that does not reintroduce an existence-distinct branch (currently they sit after the existence check — restructure so the response is constant).
- [ ] user_creation_status (browserid-broker/src/routes/account.rs:300-304): stop returning "complete" distinctly for an existing email vs pending/unknown.
- [ ] email_addition_status (browserid-broker/src/routes/email.rs ~768, oracle ~777-795): normalize the existence-distinct response.
- [ ] stage_user 409 EmailAlreadyExists (browserid-broker/src/routes/account.rs ~70-72, error.rs:161): the sign-UP existence tell. Needs a non-distinct response, which interacts with the sign-up UX the same way the sign-in screen did in Phase 1 — do this as a considered pass, not a blind status swap.
- [ ] Cross-cutting: uniform timing + rate limiting across the remaining branches of these endpoints.

## Constraints (same as Phase 1)

- Run cargo via `ssh localtest '...'` (memory macos-gatekeeper-test-binary-stall).
- Add a SqliteStore test for any store/schema behavior — memory-store tests hide sqlite-only constraints (memory sqlite-only-constraints-invisible-to-memory-store-tests).
- If any broker static inline script changes, update INLINE_SCRIPT_HASHES in routes/mod.rs (memory csp-inline-script-hashes).
- e2e is not run by CI: warm the broker on :3000 and run Playwright locally before considering it done (memories ci-does-not-run-e2e, e2e-needs-a-warm-broker).

## Done when

All five M7 oracles (the four here + address_info in Phase 1) return responses that do not distinguish account existence to an unauthenticated caller, verified by a test per endpoint asserting identical response (body/status) for an existing vs non-existing address.

## Build tasks (decided plan)

[x] Delete routes + handlers: stage_user, complete_user_creation,
user_creation_status (account.rs); stage_reset, complete_reset,
password_reset_status (reset.rs — retire the module); email_addition_status
(email.rs). Remove now-dead store surface (has_pending_reset) if unused.
[x] Dialog: forgot-password link routes to the sign-in-code screen; delete the
reset-email / reset-password screens + forms + API entries;
handleNoPasswordTransition cold branch (stageReset) → code screen (its
state-present precondition means the session owns the email, so the
setPassword path stays primary).
[x] Per-IP throttle on stage_signin_code (the one remaining unauthenticated
mail-sender): ~10 stagings per IP per hour, LOGIN_MAX_FAILURES pattern,
fail-closed 429. Reuse client_ip().
[x] Migrate tests off the deleted endpoints: broker common::create_user →
signin_code; direct stage_user/stage_reset users (authority_hierarchy,
password_length, verification, reset_reverify run_reset, forgotten_pass);
delete registration_status_test + email_addition_status_test (endpoint gone);
e2e test-helpers (stageUser/createVerifiedUser/getUserCreationStatus) + specs
posting stage_user directly; transition-no-password-reset.spec expectations
(reset screens gone → code screen); browserid-agent merged_provision_sdk_test.
[x] Update docs/security-audit-2026-07-29.md M7 row: Phase 1 + Phase 2 both
landed, endpoints deleted rather than normalized.
[x] Full broker suite + local Playwright against a warm broker before done.

## Summary of Changes

All seven retired endpoints are gone; signin_code is the single cold code-mailing lane. Broker suite 319 green, Playwright 104 green (warm broker), agent SDK test green.

**Server:** deleted stage_user / complete_user_creation / user_creation_status (account.rs), the whole reset.rs module (stage_reset / complete_reset / password_reset_status), and email_addition_status (email.rs); removed the routes and the now-dead UserStore::has_pending_reset from the trait + both stores. admin_pending_code defaults to type=signin_code (legacy types still parseable for old pendings). Added a per-IP fixed-window throttle on stage_signin_code (10/hour, signin_code_attempts in AppState, counted before any account-dependent work, skipped in dev/test mode where the whole suite shares one IP). complete_signin_code now clears the per-address send cooldown on success — a redeemed code shouldn't block a legitimate follow-up staging.

**Dialog:** forgot-password link and the no-password transition's non-owning branch both route to the sign-in-code screen (new showSigninCodeScreen helper); the reset-email / reset-password screens, their forms, and the stageReset/completeReset API entries are deleted. A session that owns the address keeps the direct set-password screen (iudv). No inline-script/CSP changes this pass (dialog.html has no inline scripts).

**Tests:** common::create_user + e2e createVerifiedUser/specs migrated to stage/complete_signin_code (completion mints no session, so cookie-dependent tests now take it from authenticate_user); forgotten_pass_test and reset_reverify_test rewritten around the unified lane (kgb9/H2 fences still pinned); verification_test's 409 test inverted into a no-conflict-restage test; authority_hierarchy's gate tests re-pointed at signin_code (including reset-of-a-handle-domain-identity refusal); registration_status_test + email_addition_status_test deleted; new retired_endpoints_test pins 404 on all seven routes; new per-IP throttle test; session_level_test pins completion-mints-no-session; transition-no-password spec rewritten (non-owning → code screen, owning session → set-password via the chooser); returning-user's session-persistence check moved to the browser context it actually tests.

**Docs:** security-audit M7 marked closed with a dated remediation-update section (endpoints deleted rather than normalized).

With dw35 (Phase 1), all five M7 oracles are closed: address_info and authenticate_user are existence-indistinguishable, and the other four endpoints no longer exist.
