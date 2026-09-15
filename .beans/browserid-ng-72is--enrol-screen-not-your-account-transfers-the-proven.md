---
# browserid-ng-72is
title: 'Enrol screen: ''Not your account?'' transfers the proven address to a new account'
status: completed
type: feature
priority: normal
created_at: 2026-09-15T14:04:54Z
updated_at: 2026-09-15T14:08:24Z
parent: browserid-ng-0vdu
---

Dan, 2026-09-15: when adding a device, allow 'this address is mine, that account is not' — create a new account around the fresh certs with confirm_takeover (registry §4.1 rule 1, §5.2.1); the old account holds the identity. Copy: 'Not your account? <email> is currently connected to a browserid account. If it's not your account, you can transfer this email to a new account. The previous owner will no longer be able to sign in with it. Is it your account but you forgot your password? <link>'. No hold details in the UI. Never a default; only after the address is proven. Native wallet: login page returns login_error=new_account, the wallet creates the account.

## Summary of Changes

Dialog: 'Not your account?' link on the enrol screen → a screen with Dan's copy and 'Transfer to a new account'; the registry client creates the account with confirm_takeover around the certs just proven and remembers it as the wallet's account. Login page: the same link/screen answers login_error=new_account; the native wallet then creates the account itself (identity passed in the fragment for the copy). Forgot-password link goes to /account. Playwright: login page path; Rust: takeover via accounts already covered.
