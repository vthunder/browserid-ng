---
# browserid-ng-uboq
title: Time-expire SMTP email verification (verified_at is write-only; EmailVerificationExpired never raised)
status: todo
type: task
priority: normal
created_at: 2026-08-28T09:39:04Z
updated_at: 2026-08-28T19:35:49Z
---

Dan's policy call (2026-08-28, d0xb review): an address must not stay verified forever — it needs occasional re-verification. Today the mint chokepoint checks only the boolean verified flag; verified_at is recorded but read by nothing, and the EmailVerificationExpired error variant (error.rs:47) has zero raise sites. Only kgb9 (password reset unverifies siblings) re-triggers verification for SMTP addresses; bridge proofs have their own staleness machinery. Implement: lazy max-age check on verified_at at the chokepoint (finally raising EmailVerificationExpired), dialog-lane re-verify UX for the same case, and the fallback device-authorize page (d0xb §3.4) demanding a fresh mailbox code when stale. Window TBD with Dan (90/180 days — d0xb §6 Q2).

Window decided (Dan, 2026-08-28): 90 days for browserid.me. Issuer policy, not spec-mandated.
