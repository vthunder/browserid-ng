---
# browserid-ng-cjh3
title: '[Audit 2026-11] D5/W2-2: mcp-auth and gate admission must evaluate policy-row bindings (or refuse non-{holder,*} rows)'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:13:41Z
parent: browserid-ng-ag1l
---

Findings: D5 (= W2-2), WS1/WS4/WS2/WS8. Severity: Medium. Decision: Q15 settled 2026-11-02: (a) refuse to store any policy record whose binding is not exactly {holder, "*"}; (b) full binding evaluation later, when a wallet actually authors narrowed records.

Where: sdk/mcp-auth/index.mjs:1040, :1051 (conjoinPolicy filters policy rows with granteeCovers only; pv.binding never read); sdk/gate/src/gateway.mjs:121 and src/mount.mjs:82 (same, and the stored row keeps no binding). WS8 reproduced: a policy row narrowed to one holder admits a holder-less connection subject, a row carrying a requester entry admits, and at the gate a jwt-bearer login with a different holder is admitted. Core's matches_login rejects all five.

Change under (a): persist binding at requestAuthoring; refuse (at store time and at admission) any policy row whose binding set is not exactly one holder entry with matcher "*". Under (b): port matches_login (§6.4 step 3): refuse requester entries, refuse connection entries for login subjects, require the holder matcher to cover the subject's holder (connection subjects have none, so only "*" passes; jwt-bearer subjects pass vctx.holder).

Acceptance:
- un-skip sdk/mcp-auth/test/audit_2026_11_ws4.test.mjs: "D5: a policy row narrowed to one holder must not admit a holder-less connection subject", "D5: a policy row carrying a requester entry is unsatisfiable in operation A and must refuse"
- un-skip sdk/gate/test/audit_2026_11_ws4.test.mjs: "D5: a policy row narrowed to another holder must not admit a jwt-bearer login with a different holder"
- delete the D5 rows (A-REJ-01..05) from EXPECTED_FAIL in sdk/mcp-auth/test/conformance-vectors.test.mjs and sdk/gate/test/conformance-vectors.test.mjs

Reports: ws4 §1.2, ws2 §2 (W2-2), ws8 §1.5. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Decision Q15 (a) implemented: a held policy record is admitted only with exactly one `{kind:"holder", matcher:"*"}` binding entry; anything else is refused with an error naming the entry.

- sdk/mcp-auth/index.mjs: new exported `assertPolicyBinding(binding)` (McpAuthError invalid_grant, names the unsupported entry / entry count). `requestAuthoring` asserts it before a row is stored and persists `binding` on the row; `createPolicyStore().put` refuses rows carrying any other binding (rows without a binding field, stored before this change, are kept and judged at admission); `conjoinPolicy` asserts it on the fresh `/validate-record` result and throws the binding error when it was the only covering row.
- sdk/gate/src/mount.mjs: the single-server default `entitlementFor` now revalidates every covering row at the broker (`liveRow`: exp, `/validate-record` fail-closed, `assertPolicyBinding`, validated grantee re-checked; scopes taken from the validation; positive results cached ≤ statusCacheS). This also lands the single-server half of D6 (bean 0og2), which the D5 gate test depends on.
- sdk/gate/src/gateway.mjs: `isRowLive` asserts the binding after validation. sdk/gate/src/policystore.mjs: the file store refuses to store, and skips on load (logged), rows with an unsupported binding.
- Types/README updated (`assertPolicyBinding`, `PolicyRow.binding`).

Tests: un-skipped the two D5 tests in sdk/mcp-auth/test/audit_2026_11_ws4.test.mjs and the D5 test in sdk/gate/test/audit_2026_11_ws4.test.mjs. Conformance runners: A-REJ-01..05 un-listed in both; the gate runner's op-A driver now answers `/validate-record` with the recorded hosted verdict (the gate validates held rows now), which also flipped A-REJ-20, A-REJ-22..31 (un-listed; A-REJ-13 and A-REJ-21 relabelled as the inherited S3/D16). New expected-fail under Q15 (a): A-OK-02 and A-OK-10 (narrowed holder matchers `br.*` / `agents.*` are refused, not evaluated, until Q15 (b)).
