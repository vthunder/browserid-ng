---
# browserid-ng-dksx
title: 'Password-reset channel hardening: planted or compromised addresses yield account-shell control + DoS'
status: todo
type: task
priority: normal
created_at: 2026-08-30T00:12:46Z
updated_at: 2026-08-30T00:13:13Z
parent: browserid-ng-9yyk
---

Dan's severity ruling (2026-08-30, from the 1sb3 Q1 discussion): a reset via a planted (or compromised existing) address is NOT identity takeover — kgb9 unverifies the sibling E3 addresses, primaries/bridges need proofs the attacker lacks — but it IS a real temporary denial of service: the attacker holds the account shell (password, sessions, registry state) until the rightful owner resets back via their own mailbox. Explore mitigations; note the attacker-controls-an-EXISTING-confirmed-email path means new-address fencing alone is not sufficient.

Candidate mitigations to evaluate:
1. Recovery eligibility delay/blessing: a newly added address (via cookie add-email OR registry §5.6 attach) cannot trigger password reset for a period, or until confirmed under the account password — severs 'member of account' from 'recovery channel' (the §5.6.2 deployment note direction).
2. Reset visibility: on reset, notify ALL of the account's addresses out-of-band naming WHICH address initiated — Dan explicitly wants the owner able to identify and cut off the attacker's address when regaining control. (Does the shipped reset notify siblings today? verify.)
3. Agent-mint fence gap: kgb9 unverifies Secondary+Smtp rows only; EmailType::Agent rows stay verified and authorize_mint(Agent, Full)=Allow, so a post-reset attacker can mint and act as the account's agent identities until reclaimed. Consider suspending agent mints after a reset until any sibling re-verifies (or unverify agent rows too and re-verify them off the parent).
4. Reset-war dampening: cooldown or step-up when resets alternate rapidly, so the rightful owner's reclaim sticks long enough to detach the attacker's address and revoke its devices.

Related: registry-api-v1 §5.6.2 deployment note (registry attach must not silently confer recovery eligibility — candidate 1 covers both add lanes); the shipped cookie add-email lane has the same planted-address exposure (session thief plants an address today). Severity per Dan: DoS/inconvenience, worth mitigating, not takeover-critical.
