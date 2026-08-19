---
# browserid-ng-iudv
title: 'Regression: passwordless set-password costs a second SMTP code (in-session set_password removed)'
status: completed
type: bug
priority: high
created_at: 2026-08-19T14:13:15Z
updated_at: 2026-08-19T14:37:34Z
parent: browserid-ng-shyj
---

On a passwordless account (E1/E2 only), setting a password when adding/using the first E3 now costs a SECOND SMTP code. Intended flow: verify the E3 via SMTP once, then set a password in the same step — one roundtrip.

## Root cause
The in-session /wsapi/set_password shortcut was removed with the old protocol (dialog.js:567-570 comment) and everything now routes through the RESET flow:
- dialog handleNoPasswordTransition (dialog.js:571-576) calls API.stageReset -> mails a reset code -> resetPassword screen. That is a second code on top of the add code from stage_email.
- No /wsapi/set_password route exists anymore; set_password is in the store trait (mod.rs:121) with NO route caller.
- /account add is worse: stage_email (1 code) -> complete_email_addition (email.rs:417-467, add_email verified=true) -> reloadAccount (account.html:1305-1308). No set-password step at all; the account stays passwordless until a later sign-in triggers transition_no_password (then a 2nd code).

## Intended behavior (owner)
Passwordless account: click add (or use a different email in the dialog) -> enter E3 -> verify via SMTP ONCE -> set password, email verified. Set-on-add, not set-on-use. If someone goes to /account and adds an E3 outside a sign-in, that should also trigger the set-password flow.

## Fix
- Restore in-session set-password for a signed-in passwordless account (session already proves control; the just-completed add proves the new address). Add a /wsapi/set_password route wired to the existing store method, session+CSRF gated, only when has_password==false.
- account.html add-email completion: when the account has no password, chain into a set-password prompt and call set_password (no second code).
- dialog transition_no_password: when a SESSION exists, set the password in-session instead of stageReset. Keep the mailed-code path only for the COLD case (no session).

## Tests
- Passwordless account adds an E3: exactly ONE SMTP code sent; ends verified + password set.
- /account add on a passwordless account triggers set-password.
- Cold transition_no_password (no session) still uses the reset code.

## Summary of Changes (2026-08-19)

Restored the in-session set-password shortcut — one SMTP roundtrip, set-on-add.

**Server**
- New `POST /wsapi/set_password` (routes/auth.rs): session + CSRF gated, length-validated, refused with 400 once a password exists (change = update_password or reset); wires the previously caller-less `UserStore::set_password`.
- `/wsapi/list_emails` now returns `has_password` (session-gated own-account info) so both UIs can branch.

**Dialog (dialog.js + new set-password-screen in dialog.html)**
- `handleNoPasswordTransition`: if the session owns the selected email (guarded via session_context + list_emails, since set_password acts on the SESSION's account) → new setPassword screen → `/wsapi/set_password` → completeSignIn. Cold case (no session) unchanged: stageReset → mailed code.
- add-email-verify: after complete_email_addition on a passwordless account, chains into the setPassword screen instead of a second code.

**/account (account.html)**
- reloadAccount captures `has_password`; the add-address rail gains an `addr-pass` step: after verifying the code on a passwordless account it prompts for a password and calls `/wsapi/set_password`. INLINE_SCRIPT_HASHES updated for the edited inline script.

**Tests** — new tests/set_password_test.rs (7 tests, all green; full broker suite green):
- auth/CSRF/length gates; refusal when a password exists (original password still works).
- Passwordless account: set_password succeeds with ZERO mail sent; authenticate_user works after; has_password flips in list_emails.
- Headline flow: passwordless account adds an E3 → exactly ONE mailed code → password set in-session → sign-in with new password.
- SqliteStore-level set_password/has_password test (method had no production caller; memory-store tests miss sqlite constraints).
- Test harness: TestContext now exposes session_store so tests can mint sessions for passwordless accounts (production analogue of E1/E2-established sessions).

Cold-path server code is untouched (stage_reset/complete_reset unchanged; existing forgotten_pass tests cover it).
