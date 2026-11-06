---
# browserid-ng-oawf
title: '[M8] Deferred rate-limit/enumeration items: /api/v1 429, hosted-IdP throttle, residual oracles (ytjn/dw35/7ww7 fixed)'
status: todo
type: bug
priority: normal
created_at: 2026-08-07T16:03:44Z
updated_at: 2026-11-02T22:50:45Z
parent: browserid-ng-8g49
blocking:
    - browserid-ng-7x4x
---

Re-confirmed open in code: authenticate_user has no rate-limit/lockout (routes/auth.rs, bean ytjn); unauthenticated account enumeration (bean dw35); fallback /auth/device_cert password-bypass (bean 7ww7). Consciously deferred for product/infra decisions; this just verifies no regression. See audit M8. Cross-ref epic browserid-ng-wre6.


## WS5 resolution (2026-11-02, docs/security-audit-2026-11-ws5-http-surface.md §5)

The "re-confirmed open" claim above is stale: ytjn (login throttle, auth.rs:37-107 + test), dw35/8gqm (address_info owner-only, indistinguishable password failures, oracle endpoints deleted) and 7ww7 (/auth/device_cert lane removed; issuance behind authorize_mint) are all FIXED; their completed status stands. Remaining deferred items this bean now tracks: D8 no 429 on /api/v1; W5-2 /idp/login + /idp/password unthrottled with bcrypt timing oracle; W5-3 record_device_cert existence oracle; S11 generic refusals; W5-6 X-Forwarded-For first-hop trust (confirm proxy behaviour in sandmill-infra). Tests: browserid-broker/tests/authz_matrix_test.rs (ignored AUDIT-2026-11 tests).



## WS9 (2026-11-02)

Each remaining item now has its own remediation bean under browserid-ng-ag1l: D8 -> browserid-ng-4r2j, W5-2 -> browserid-ng-i4kj, W5-3 + S11/W5-12 -> browserid-ng-imn6, W5-6 -> browserid-ng-gajq (broker) and browserid-ng-zthh (sandmill-infra). Close this bean when those are done. Ledger: docs/security-audit-2026-11.md.
