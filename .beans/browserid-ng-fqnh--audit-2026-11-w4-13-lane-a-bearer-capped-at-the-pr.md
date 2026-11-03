---
# browserid-ng-fqnh
title: '[Audit 2026-11] W4-13: Lane A bearer capped at the presented warrant''s expiry (/verify returns expires_at)'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:24:20Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-oa6s
---

Findings: W4-13. Severity: Low. Decision: Q23 settled 2026-11-02 (yes: fold the /verify expiry field into the D7 scope-parameter work). Blocked by the D7 bean (the verifier must return expires_at).

Where: sdk/mcp-auth/index.mjs:266 and python handle_token: a jwt-bearer (Lane A) bearer lives tokenTtlS (1 h) regardless of warrant or access-cert expiry; /verify returns no expiry for presentations so the AS cannot cap.

Change: /verify returns expires_at (min of access cert, warrant, config cert exp); JS and Python cap the bearer TTL at min(tokenTtlS, expires_at - now).

Acceptance: un-skip sdk/python-mcp-auth/tests/test_audit_2026_11_ws4.py test_bearer_never_outlives_the_presented_warrant; add the JS twin.

Reports: ws4 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Lane A (jwt-bearer) bearers never outlive the presented warrant, in JS and Python.

- sdk/mcp-auth/index.mjs `redeemPresentation`: the bearer's `exp` is `min(now + tokenTtlS, verified.expires_at)` when the hosted `/verify` returns `expires_at` (the field bean oa6s adds: the earliest of access cert, warrant and config cert); a presentation whose `expires_at` is already past is refused with `invalid_grant`; `expires_in` reports the capped lifetime. Without the field (a verifier predating oa6s) the 1 h `tokenTtlS` cap applies as before.
- sdk/python-mcp-auth `handle_token`: the same cap and refusal (`expires_at` numeric, bool excluded).
- READMEs note the cap next to `tokenTtlS` / `token_ttl_s`.

Tests: un-skipped `test_bearer_never_outlives_the_presented_warrant`; the "lifetime is token_ttl today" pin became the no-`expires_at` fallback test, plus an already-expired refusal test. JS twin added in sdk/mcp-auth/test/audit_2026_11_ws4.test.mjs ("W4-13: a jwt-bearer bearer is capped at the verifier's expires_at …"). Both SDKs are forward-compatible: the tests inject `expires_at` through the stubbed verifier, so this bean no longer waits on oa6s to be green, but the cap only bites in production once the hosted `/verify` ships the field.
