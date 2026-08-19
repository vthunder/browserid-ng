---
# browserid-ng-kgb9
title: Password reset re-verifies other E3 addresses; force password on first E3
status: completed
type: task
priority: high
created_at: 2026-08-19T13:34:19Z
updated_at: 2026-08-19T15:54:29Z
parent: browserid-ng-shyj
blocked_by:
    - browserid-ng-ca29
    - browserid-ng-iudv
---

Close the E3-inbox -> reset -> pivot-to-another-E3 attack, and guarantee E3 accounts have a password.

## Reset flow (reset.rs complete_reset, :136-150)
- After update_password: for every Secondary+Smtp (E3) email on the account EXCEPT the address used for this reset, call unverify_email (the existing unused trait method, mod.rs) to mark it for re-verification.
- The reset address itself: keep/confirm verified (the user just proved control via the SMTP code).
- E1/E2 emails untouched (their trust doesn't rest on the broker password).
- Reset already deletes sessions (reset.rs:147) and grants a fresh full session — keep that.
- Dialog: a re-verification-pending E3 selected under a full session must trigger a fresh SMTP challenge before minting.

## Force-password-on-first-E3
- Adding the first E3 (SMTP) email to an account must require setting an account password. No passwordless accounts holding E3 addresses; no cookie-only no-account E3 cert issuance (removes the fallback_idp.rs:338-345/:378 no-account path).
- Passwordless accounts created by E1/E2 cold-claim stay valid until they gain an E3.

## Tests
- Attacker controlling old-E3 resets password -> can mint old-E3 but NOT other-E3 until other-E3 is re-verified.
- First E3 add without a password is rejected / forces password set.
- Sqlite + memory store coverage.

## Verified current behavior (2026-08-19) — correction
Add-email does NOT force a password at add-time. account.html add flow (stage_email:1240 -> complete_email_addition:1305 -> reloadAccount:1308) and the server handler (email.rs:417-467, add_email verified=true) leave a verified E3 on a still-passwordless account. The password is forced later, at USE time: dialog transition_no_password (compute_state email.rs:581; dialog.js:635-638; account.html:1527-1528 'Set a password to sign in') sends a code then sets a password.

Implication: 'force password on first E3' does NOT need a new enforcement point at add-time — it falls out of the chokepoint (browserid-ng-u4xz): an E3 mint on a passwordless account returns NeedPassword. So the interactive dialog path already forces it; the chokepoint closes the non-dialog paths (/device/issue, /auth/device_cert). Drop the earlier framing of this as a distinct 'sharp edge'.

## The double-SMTP-roundtrip issue -> split out as bug browserid-ng-iudv
The two-codes-on-a-passwordless-account problem is a regression (in-session /wsapi/set_password was removed) and is now tracked separately as browserid-ng-iudv. This bean depends on that landing so 'first E3 forces a password' is a single-roundtrip, set-on-add flow rather than a second code.

## Summary of Changes (2026-08-19)

**Reset re-verification fence (invariant 4)**
- reset.rs complete_reset: after update_password, every OTHER Secondary+Smtp (E3) email on the account is unverify_email'd (first production caller of that trait method); the reset address itself is re-verified (just proven). E1/E2/agent identities untouched. Session eviction kept.

**Re-verification plumbing (was all dead/broken — nothing ever became unverified before)**
- address_info now reports state 'unverified' for an existing-but-unverified email (before, compute_state never returned it). Bridge-proven addresses re-prove at the bridge via the existing claim branches; SMTP ones fall through to the new roundtrip.
- stage_email: owner-only carve-out — an account may RE-stage its own existing address; anyone else's still 409s.
- complete_email_addition: an address already on the account is verify_email'd instead of add_email'd (no duplicate row / no sqlite INSERT conflict).
- dialog 'unverified' branch (was dead code pointing at the wrong completion route): stages the code and completes through the addEmailVerify flow, which chains into iudv's set-password and the u4xz chokepoint. Cold case (no session): password screen first via a reverifyAfterAuth flag, then re-enters the chooser flow on the fresh full session.

**Force-password-on-first-E3**
- Falls out of the composed epic, per this bean's 2026-08-19 note: the interactive path forces it via transition_no_password → in-session set_password (iudv), and the chokepoint (u4xz) closes non-dialog paths — an E3 mint needs a Full session, which a passwordless account cannot have. The fallback_idp no-account cookie-mint path is removed in the 7ww7 slice.

## Tests (tests/reset_reverify_test.rs)
- Reset unverifies ONLY sibling E3s (E2/E1/agent zoo untouched; reset address stays verified).
- End-to-end pivot block: reset via inbox A → full session → mint A ok, mint B refused → address_info 'unverified' → re-stage+complete (one row, no dup) → mint B ok.
- Owner-only re-staging (intruder 409).
- SqliteStore unverify/verify round trip. Full broker suite green.
