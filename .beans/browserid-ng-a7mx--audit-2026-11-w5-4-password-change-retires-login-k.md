---
# browserid-ng-a7mx
title: '[Audit 2026-11] W5-4: password change retires login keys enrolled by password and ends their sessions'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-02T22:43:19Z
parent: browserid-ng-ag1l
---

Findings: W5-4 (July H2 class for a password change rather than a reset). Severity: Medium. Decision: Q4 settled 2026-11-02: (a) a password change retires login keys whose enrolled_by is password and ends their sessions; keys enrolled by proofs or approval stay.

Where: browserid-broker/src/routes/auth.rs:265-280 (update_password evicts cookie sessions only) versus signin_code.rs:280-317 (the reset lane also revokes login keys). Every enrolled registry login key and its bearer sessions survive a password change, so a wallet an attacker enrolled with the old password keeps the account.

Change: in update_password, after the cookie-session eviction, revoke every login key with enrolled_by = password except the one making the change (if any) and end its sessions; keep proof- and approval-enrolled keys. Show the device list after the change.

Acceptance (un-ignore): browserid-broker/tests/authz_matrix_test.rs: password_change_ends_registry_sessions_enrolled_by_password. Wallet e2e: relogin must still work (memory: the relogin path forgets the key, never revokes).

Reports: ws5 §2 and §4 (H2 row). Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
