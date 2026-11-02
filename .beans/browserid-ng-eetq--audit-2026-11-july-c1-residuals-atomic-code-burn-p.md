---
# browserid-ng-eetq
title: '[Audit 2026-11] July C1 residuals: atomic code burn, per-IP cap on completion, longer codes'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

July 2026 residuals found by the WS5 and WS7 re-verification (no new ids). Severity: Low. Decision: none needed.

C1 residual (browserid-broker/src/code_guard.rs:21, :43-88; crypto.rs:19; signin_code.rs:90-109): codes are still 6 digits; the read-compare-increment of the attempt counter is not atomic (two parallel guesses can both see 4); the completion endpoint has no per-IP cap (staging has 10/IP/h); the IP cap inherits W5-6. Change: make the burn atomic (single UPDATE ... WHERE attempts < 5 RETURNING), add a per-IP window on completion, consider 8-digit codes.

M8 residual is tracked in the W7-8 Dockerfile bean (OpenOptions::mode(0o600) and assert the mode on load).

H2 residual (password change does not retire login keys) is the W5-4 bean. M3 residual (future iat) is the clock-rule bean. M4 residual (inflate before cap) is the W6-3 bean. M6 residual (hosted IdP) is the W5-2 bean. M7 residuals are the W5-3/W5-12 bean. H1 residuals are the D15 and W6-5 beans.

Acceptance: add tests to browserid-broker/tests for the atomic burn (parallel guesses) and the completion IP cap.

Reports: ws5 §4, ws7 §4. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
