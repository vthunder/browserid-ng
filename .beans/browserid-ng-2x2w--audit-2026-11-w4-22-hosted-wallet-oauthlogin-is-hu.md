---
# browserid-ng-2x2w
title: '[Audit 2026-11] W4-22: hosted wallet /oauth/login is human-only (grantee == email, login scope required)'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W4-22 (July M2 recurrence in the hosted wallet). Severity: Medium. WS8 reproduced: POST /oauth/login with a delegated presentation whose grantee differs from email returns 200, and a presentation without the login scope is admitted too. Decision: Q16 settled 2026-11-02: (a) the hosted wallet is human-only; reject delegated and non-login presentations.

Where: wallet-service/src/server.mjs:33-35, :116-120: the tenant is keyed on email and grantee is never compared; scopes are never checked. @browserid-ng/verify dropped allowAgent (July M2 fix) and tells RPs to do the comparison; this RP never did. One human-approved consent card for the wallet origin lets an agent take over the custodied key.

Change under (a): at /oauth/login require grantee === email and "login" in scopes; refuse otherwise with 401. Under (b): document that an as-you agent may own a tenant (and then the tenant must be keyed on grantee).

Acceptance: un-skip wallet-service/test/audit_2026_11_ws4.test.mjs "W4-22: a delegated presentation (grantee != email) does not open the human's tenant"; flip the pin "…without the login scope is still admitted today" to assert refusal.

Reports: ws4 §2 and §4 (M2 row), ws8 §1.4. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
