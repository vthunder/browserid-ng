---
# browserid-ng-1dy0
title: '[Audit 2026-11] W5-13/W5-15: claim accepts a pending agent request; membership reason renamed holders_differ'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:47:41Z
parent: browserid-ng-ag1l
---

Findings: W5-13 and W5-15 (registry-api-v1 wire conformance after the WS1 amendments). Severity: Low. Decision: settled (spec text).

Where: browserid-registrar/src/consent.rs:337-343 (claim_core answers 404 for every agent-kind request; reg §5.3 says claim also claims a pending agent request: binds it to the account, allocates indices); browserid-registrar/src/account.rs:124 and consent.rs:771 (membership reason still emitted as holder_mismatch; reg §7.1 renamed it holders_differ).

Change: claim_core handles kind agent (bind to the account, allocate status indices, same response shape); rename the reason to holders_differ everywhere it is emitted and in sdk/agent, the wallet and docs that match on it.

Acceptance (un-ignore): browserid-broker/tests/authz_matrix_test.rs: claim_accepts_a_pending_agent_request. Add an assertion for holders_differ on accounts/lookup/attach.

Reports: ws5 §2a. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

- `claim_core` accepts a pending `agent` request (reg §5.3): it was bound to the delegator's account at filing with indices allocated, so the claim re-states that binding for the same account (allocating any missing index) and answers the item; another account's claim stays `404`. Notices remain unclaimable.
- Membership reason renamed: `attach`/`accounts` with two certs of different holders answer `422 invalid_cert/holders_differ` (was `holder_mismatch`, which collides with the `invalid_warrant` reason). No SDK, wallet or doc matched the old membership string; the warrant-side `holder_mismatch` is unchanged.
- Tests: `authz_matrix_test::claim_accepts_a_pending_agent_request` un-ignored and extended (item shape, idempotence, 404 for another account); `registry_api_test` asserts `holders_differ` on attach.
