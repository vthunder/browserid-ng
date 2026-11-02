---
# browserid-ng-dobu
title: '[Audit 2026-11] W4-30: pending hosted-tenant rows expire and a DNSSEC-validated owner can replace a squat'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W4-30. Severity: Medium (DoS on onboarding only; activation still needs DNS control). Decision: Q17 settled 2026-11-02: (a) expire pending rows (e.g. 7 days) and let a DNSSEC-validated record for a different key replace a pending row.

Where: browserid-broker/src/routes/hosted_idp.rs:782-880 (tenant_create), store/memory.rs:1116, store/sqlite.rs:3129-3144: any broker account opens a PendingDns tenant for any domain; a second attempt gets 409; pending rows never expire; only the squatter may check or delete. The real domain owner can never onboard.

Change: add created_at expiry to pending rows (sweep or check-on-read); on tenant_create for a domain with a pending row, if the live _browserid record validates for a key that is not the pending row's, replace the row with the caller's; otherwise 409 only while the pending row is young. Add a SqliteStore test (memory-store tests do not see sqlite constraints).

Acceptance (un-ignore): browserid-broker/tests/audit_2026_11_ws4.rs: w4_30_pending_tenant_squat_does_not_block_the_domain_owner (pin pin_pending_tenant_issues_nothing keeps passing).

Reports: ws4 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
