---
# browserid-ng-7ww7
title: '[M1] Fallback /auth/device_cert password-bypass for password-backed emails'
status: completed
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-08-19T16:02:23Z
parent: browserid-ng-shyj
blocked_by:
    - browserid-ng-u4xz
---

docs/security-audit-2026-07-29.md (M1). /auth/device_cert (broker/routes/fallback_idp.rs:282) issues 90-day auth+config certs gated only on the fb_email cookie — no password/session/CSRF. Intended fallback trust model (mailbox≈recovery), certs ARE status-revocable + expire 90d, cookie SameSite=Lax. Sharp residual: password BYPASS for an email that also backs a password-protected account.
- [x] Require account password or session before issuing certs for an email with a password account

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

## Summary of Changes (2026-08-19)

/auth/device_cert rewired onto the chokepoint, per the agreed resolution direction:
- Gate 1 unchanged: the fb_email cookie must authorize exactly the requested address (SMTP freshness).
- Gate 2 (new): the address must belong to a broker account (no account → 403; the old cookie-only/no-account issuance path is REMOVED — first E3 forces a password via iudv/kgb9), the caller must hold THAT account's broker session, and authorize_mint decides: E3 needs a FULL session (fb cookie + lightweight session → 401 'password required'), E1/E2 → 403 (delegated to primary/bridge). A fresh mailbox proof alone no longer mints anything — mailbox control is recovery-channel material (the reset flow), closing the M1 password bypass.
- The OIDC cold-claim parallel noted in the re-verification: attach_verified now establishes only a LIGHTWEIGHT session (ca29) and E2 minting requires a live bridge proof (pr3a) — the second bypass is closed by the same machinery.
- Wildcard: the explicit local+*@domain glob is dropped from the config cert data (both certs exact-address). Investigation note: identity_matches (core/device.rs:60) makes base-covers-+tags a PROTOCOL rule regardless of cert data, with the warrant's exact-grantee pinning as the containment — so the glob was redundant data; the real M1 fix is the password gate above.
- No CSRF added: both cookies are SameSite=Lax and the surface's external (support-doc-discovered) clients have no csrf channel; documented in the handler.

## Tests (fallback_idp_test.rs reworked + guard)
- Full happy path now requires fb cookie + full session; fb-cookie-only → 401 'password required'; full-session-only (no fb cookie) → 401; cookie for a different email → 401.
- No-account SMTP dance → 403 'no account'.
- Lightweight session + fb cookie → 401 'password required'.
- Cert data carries the exact address only (no +* entry).
- mint_chokepoint_test's source-scan guard now requires authorize_mint in fallback_idp.rs too. Full broker suite + workspace build green.
