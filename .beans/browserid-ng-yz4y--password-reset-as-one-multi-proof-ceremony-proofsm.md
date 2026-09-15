---
# browserid-ng-yz4y
title: 'Password reset as one multi-proof ceremony: proofs>=min(2,n), approval never; completion sets password, unverifies unproven mailboxes, suspends agents, revokes all login keys'
status: todo
type: feature
priority: normal
created_at: 2026-09-15T00:12:21Z
updated_at: 2026-09-15T00:12:21Z
parent: browserid-ng-0vdu
blocked_by:
    - browserid-ng-d26p
---

Replace the reset branch of complete_signin_code with a recovery-attempt record that collects proofs (mailed code first, enumeration-safe; then masked hints + mediator/bridge proofs) and applies effects only on completion. New: agent identity suspension until parent re-proven (closes dksx gap 3); revoke all login keys (closes hkaz). Single-mailbox accounts: k=1, today's behaviour. Tests: signin_code_test, a SqliteStore test, Playwright reset flows for the three shapes.
