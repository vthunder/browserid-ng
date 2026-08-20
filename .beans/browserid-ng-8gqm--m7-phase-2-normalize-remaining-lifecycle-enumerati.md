---
# browserid-ng-8gqm
title: '[M7] Phase 2: normalize remaining lifecycle enumeration oracles (reset/creation/email-status/stage_user)'
status: todo
type: bug
priority: normal
created_at: 2026-08-20T13:41:25Z
updated_at: 2026-08-20T13:42:33Z
parent: browserid-ng-wre6
blocked_by:
    - browserid-ng-dw35
---

Phase 2 of the M7 enumeration work (browserid-ng-dw35 is Phase 1: address_info + sign-in UX). This bean covers the four remaining unauthenticated lifecycle oracles that independently leak account existence. Decision philosophy is the same as Phase 1: normalize responses so existence is not distinguishable; where a UX branch is unavoidable, key it on domain-level facts (type/proof), never on account state. See docs/security-audit-2026-07-29.md (M7) and the dw35 decision note.

## Oracles to normalize

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
