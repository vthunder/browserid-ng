---
# browserid-ng-uboq
title: Time-expire SMTP email verification (verified_at is write-only; EmailVerificationExpired never raised)
status: completed
type: task
priority: normal
created_at: 2026-08-28T09:39:04Z
updated_at: 2026-08-28T22:30:46Z
parent: browserid-ng-9yyk
---

Dan's policy call (2026-08-28, d0xb review): an address must not stay verified forever — it needs occasional re-verification. Today the mint chokepoint checks only the boolean verified flag; verified_at is recorded but read by nothing, and the EmailVerificationExpired error variant (error.rs:47) has zero raise sites. Only kgb9 (password reset unverifies siblings) re-triggers verification for SMTP addresses; bridge proofs have their own staleness machinery. Implement: lazy max-age check on verified_at at the chokepoint (finally raising EmailVerificationExpired), dialog-lane re-verify UX for the same case, and the fallback device-authorize page (d0xb §3.4) demanding a fresh mailbox code when stale. Window TBD with Dan (90/180 days — d0xb §6 Q2).

Window decided (Dan, 2026-08-28): 90 days for browserid.me. Issuer policy, not spec-mandated.

## Summary of Changes

verified_at is now read: mint::verification_stale + MintDecision::Reverify (E3 only, checked after the password gate so lightweight sessions can't trigger inbox codes; verified_at=NULL legacy rows are stale — one fresh code heals them). /device/issue maps Reverify to EmailVerificationExpired (first raise sites); FedCM silently refuses; address_info reports stale as state=unverified so the dialog's existing kgb9 lane runs the re-verify UX unchanged. The fallback ceremony page stages a fresh code (stage_email/complete_email_addition) and retries issuance. Window: 90 days (SMTP_VERIFICATION_MAX_AGE_DAYS, issuer policy). Test hooks: UserStore::set_email_verified_at (memory+sqlite) + POST /wsapi/test/set_verified_at; unit matrix in mint.rs + end-to-end Playwright proof. NOTE deploy effect: any prod row with verified=1 but verified_at NULL now requires one re-verification code on next mint — handled automatically by the dialog/page UX.
