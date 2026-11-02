---
# browserid-ng-cjh3
title: '[Audit 2026-11] D5/W2-2: mcp-auth and gate admission must evaluate policy-row bindings (or refuse non-{holder,*} rows)'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
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
