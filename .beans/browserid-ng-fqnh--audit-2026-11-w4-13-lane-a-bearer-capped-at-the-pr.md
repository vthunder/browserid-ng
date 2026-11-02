---
# browserid-ng-fqnh
title: '[Audit 2026-11] W4-13: Lane A bearer capped at the presented warrant''s expiry (/verify returns expires_at)'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:44:00Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-oa6s
---

Findings: W4-13. Severity: Low. Decision: Q23 settled 2026-11-02 (yes: fold the /verify expiry field into the D7 scope-parameter work). Blocked by the D7 bean (the verifier must return expires_at).

Where: sdk/mcp-auth/index.mjs:266 and python handle_token: a jwt-bearer (Lane A) bearer lives tokenTtlS (1 h) regardless of warrant or access-cert expiry; /verify returns no expiry for presentations so the AS cannot cap.

Change: /verify returns expires_at (min of access cert, warrant, config cert exp); JS and Python cap the bearer TTL at min(tokenTtlS, expires_at - now).

Acceptance: un-skip sdk/python-mcp-auth/tests/test_audit_2026_11_ws4.py test_bearer_never_outlives_the_presented_warrant; add the JS twin.

Reports: ws4 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
