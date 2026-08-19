---
# browserid-ng-7ww7
title: '[M1] Fallback /auth/device_cert password-bypass for password-backed emails'
status: todo
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-08-19T13:34:31Z
parent: browserid-ng-shyj
blocked_by:
    - browserid-ng-u4xz
---

docs/security-audit-2026-07-29.md (M1). /auth/device_cert (broker/routes/fallback_idp.rs:282) issues 90-day auth+config certs gated only on the fb_email cookie — no password/session/CSRF. Intended fallback trust model (mailbox≈recovery), certs ARE status-revocable + expire 90d, cookie SameSite=Lax. Sharp residual: password BYPASS for an email that also backs a password-protected account.
- [ ] Require account password or session before issuing certs for an email with a password account

## Re-verification 2026-08-17 — STILL VALID, widened

Verified against current code. `device_cert()` (fallback_idp.rs:282) still gated on the `fb_email` cookie alone (:296-305); no password/session check exists in the file (grep password → 0 hits; password verify lives only in auth.rs:109/:215). Account lookup at :337/:382 binds the mailbox-only prover into the password-backed account's namespace.

Worse since audit:
- Config (warrant-signing) cert now issued for `local+*@domain` wildcard sub-addresses (fallback_idp.rs:344-350) → mailbox control now grants authority over all the account's +tag agent identities.
- NEW parallel bypass: OIDC/Google bridge (routes/oidc.rs). `attach_verified` (oidc.rs:317-395) cold-claims (no session) an existing email into its owning account when proof matches (:358-363), with no password; on mismatch it TRANSFERS the email to a fresh passwordless account (:364-367). Does not set fb_email, so not a second door into device_cert, but same trust-model bypass. TTL still 90d (DEVICE_CERT_VALIDITY_DAYS, core/device.rs:49).

Decision needed: should mailbox/Google-account control outrank the account password? Options — (A) require password/session before issuing certs for a password-backed email (+ same for OIDC cold-claim); (B) keep mailbox-as-recovery, narrow blast radius (drop +* wildcard, notify on issuance, shorten TTL); (C) both.

## Resolution direction (2026-08-19, owner)
Folded into epic browserid-ng-shyj. Design agreed:
- Inbox (SMTP) control is a legitimate authenticator, but for a password-backed account its channel is the RESET flow, not a silent cert mint.
- /auth/device_cert must go through the central authorize_mint chokepoint (browserid-ng-u4xz): a Secondary+Smtp (E3) email that backs an account requires a FULL (password) session. Fresh fb_email cookie alone no longer mints E3 certs for a password-backed address.
- No account / cookie-only issuance path is removed: first E3 add forces a password (browserid-ng-kgb9).
- OIDC/Google (E2) is accepted as sufficient (owner: 'similar to a primary') — but E2 minting is delegated to a live bridge proof, not the fb_email cookie (browserid-ng-pr3a). The OIDC cold-claim path (oidc.rs attach_verified) establishes only a LIGHTWEIGHT session (browserid-ng-ca29).
- Drop the local+*@domain wildcard from the config cert here unless separately justified (blast-radius narrowing).
This bean = the fallback-surface slice: rewire /auth/device_cert onto authorize_mint once the chokepoint lands.
