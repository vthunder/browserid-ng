---
# browserid-ng-yz4y
title: 'Password reset as one multi-proof ceremony: proofs>=min(2,n), approval never; completion sets password, unverifies unproven mailboxes, suspends agents, revokes all login keys'
status: completed
type: feature
priority: normal
created_at: 2026-09-15T00:12:21Z
updated_at: 2026-09-15T01:19:29Z
parent: browserid-ng-0vdu
blocked_by:
    - browserid-ng-d26p
---

Replace the reset branch of complete_signin_code with a recovery-attempt record that collects proofs (mailed code first, enumeration-safe; then masked hints + mediator/bridge proofs) and applies effects only on completion. New: agent identity suspension until parent re-proven (closes dksx gap 3); revoke all login keys (closes hkaz). Single-mailbox accounts: k=1, today's behaviour. Tests: signin_code_test, a SqliteStore test, Playwright reset flows for the three shapes.

## Summary of Changes

Built 2026-09-15. complete_signin_code: existing account → begin_reset: applies at once when the rule wants one proof, else a RecoveryAttempt (schema v46) with masked hints; POST /wsapi/recovery_proofs takes presentations and applies the reset when enough identities are proven. apply_reset: password, unverify unproven SMTP mailboxes, unverify agents of unproven parents (reverify_agents_of on complete_email_addition), delete sessions, revoke all login keys. Dialog continueRecovery/maybeFinishRecovery; account page shows what is left to prove. Tests: registry_api_test two-proof reset; reset_reverify_test waits on baseline; older multi-identity reset tests pinned to proofs=1.
