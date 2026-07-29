---
# browserid-ng-7ww7
title: '[M1] Fallback /auth/device_cert password-bypass for password-backed emails'
status: todo
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-07-28T23:54:23Z
parent: browserid-ng-wre6
---

docs/security-audit-2026-07-29.md (M1). /auth/device_cert (broker/routes/fallback_idp.rs:282) issues 90-day auth+config certs gated only on the fb_email cookie — no password/session/CSRF. Intended fallback trust model (mailbox≈recovery), certs ARE status-revocable + expire 90d, cookie SameSite=Lax. Sharp residual: password BYPASS for an email that also backs a password-protected account.
- [ ] Require account password or session before issuing certs for an email with a password account
