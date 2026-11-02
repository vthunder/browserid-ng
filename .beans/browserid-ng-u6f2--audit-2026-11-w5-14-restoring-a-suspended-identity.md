---
# browserid-ng-u6f2
title: '[Audit 2026-11] W5-14: restoring a suspended identity held elsewhere needs confirm_takeover and a recorded config cert'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-02T22:43:59Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-0fy3
---

Findings: W5-14 (code side of S10, accepted 2026-11-01). Severity: Medium. Decision: settled (reg §5.2.4 amended: restoring a suspended identity that another account now holds needs a config cert and confirm_takeover, else 409 identity_held).

Where: browserid-registrar/src/account.rs:704-709: the suspended -> Transfer branch requires only fresh certs; no config cert, no confirm_takeover. A suspended identity returning silently pulls the identity off the account that now holds it.

Change: in the Transfer branch, when another account holds the identity, require confirm_takeover and a config cert for the identity that passes the shared recorded_config_cert helper (D2 bean), else 409 identity_held. Blocked by the D2 bean (the helper).

Acceptance: no encoded test (needs two accounts and a suspension); add one to browserid-broker/tests/authz_matrix_test.rs following §5.2.4: restore without confirm_takeover -> 409 identity_held; with confirm_takeover + valid config cert -> transfer; with a config cert the issuer never signed -> refused.

Reports: ws5 §2a, ws1 §2 (S10). Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
