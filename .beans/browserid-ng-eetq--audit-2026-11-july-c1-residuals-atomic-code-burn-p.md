---
# browserid-ng-eetq
title: '[Audit 2026-11] July C1 residuals: atomic code burn, per-IP cap on completion, longer codes'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:42:08Z
parent: browserid-ng-ag1l
---

July 2026 residuals found by the WS5 and WS7 re-verification (no new ids). Severity: Low. Decision: none needed.

C1 residual (browserid-broker/src/code_guard.rs:21, :43-88; crypto.rs:19; signin_code.rs:90-109): codes are still 6 digits; the read-compare-increment of the attempt counter is not atomic (two parallel guesses can both see 4); the completion endpoint has no per-IP cap (staging has 10/IP/h); the IP cap inherits W5-6. Change: make the burn atomic (single UPDATE ... WHERE attempts < 5 RETURNING), add a per-IP window on completion, consider 8-digit codes.

M8 residual is tracked in the W7-8 Dockerfile bean (OpenOptions::mode(0o600) and assert the mode on load).

H2 residual (password change does not retire login keys) is the W5-4 bean. M3 residual (future iat) is the clock-rule bean. M4 residual (inflate before cap) is the W6-3 bean. M6 residual (hosted IdP) is the W5-2 bean. M7 residuals are the W5-3/W5-12 bean. H1 residuals are the D15 and W6-5 beans.

Acceptance: add tests to browserid-broker/tests for the atomic burn (parallel guesses) and the completion IP cap.

Reports: ws5 §4, ws7 §4. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.



## Summary of Changes

- routes/code_guard.rs: the check-and-burn is atomic — the attempt-counter mutex is held across the pending lookup, the compare and the increment (the store calls are synchronous; never across an await), so two parallel wrong guesses cannot both read "four so far" and both get a fifth try. `record_wrong` takes the held guard. Unit test `parallel_wrong_guesses_burn_atomically` (8 threads behind a barrier).
- Per-IP cap on completion: new `code_guard::completion_ip_allowed(state, headers)` (30 attempts per 15 min per client IP, counted on every attempt so it is not an existence oracle; 429 at the cap), backed by a new `AppState.code_completion_attempts` window (per rig, like `signin_code_attempts`). Called first in `/wsapi/complete_signin_code` (routes/signin_code.rs) and `/wsapi/complete_email_addition` (routes/email.rs). The IP is the trusted proxy hop (bean gajq). Integration test `completion_is_rate_limited_per_ip` in tests/signin_code_test.rs.
- Code length: left at 6 digits. The burn-after-5 per address plus the per-IP cap bound an online guess to 5 of 900k per address and 30 attempts per IP per 15 min; 8 digits would also touch dialog.html/dialog.js/account.html/authorize.html (pattern/maxlength/copy, with account.html's inline-script CSP hash) and the e2e, so it is noted as a follow-up rather than done here.
- No new env var.
