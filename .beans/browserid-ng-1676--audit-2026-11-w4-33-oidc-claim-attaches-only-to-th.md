---
# browserid-ng-1676
title: '[Audit 2026-11] W4-33: OIDC claim attaches only to the session that began the flow'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W4-33. Severity: Low (no login-CSRF vector found: JSON + preflight). Decision: none needed.

Where: browserid-broker/src/oidc/mod.rs:180-186, :206-233 and routes/oidc.rs:338-345, :377-393: FlowState.session_id is stored and never read; the flow attaches to the callback-time session, and the double-submit cookie proves the same browser, not the same account.

Change: enforce flow.session_id == the callback session (refuse otherwise), or delete the field. Enforcing is the fail-closed choice.

Acceptance (un-ignore): browserid-broker/tests/audit_2026_11_ws4.rs: w4_33_oidc_attaches_to_the_session_that_began_the_claim.

Reports: ws4 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
