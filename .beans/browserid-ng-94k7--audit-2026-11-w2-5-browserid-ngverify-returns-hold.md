---
# browserid-ng-94k7
title: '[Audit 2026-11] W2-5: @browserid-ng/verify returns holder and grantee_issuer'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W2-5 (conformance). Severity: Low (an RP cannot decide wrongly on a field it never sees; §6.1 step 9 lists them as part of the verifier's answer and the gate's attribution line wants holder). Decision: none needed.

Where: sdk/js/index.mjs:116-125: the result omits holder and grantee_issuer that the hosted response carries.

Change: add holder and grantee_issuer to the result type and pass them through; update the README and the TypeScript types.

Acceptance: vector P-OK-01 in sdk/js/conformance.test.mjs compares the fields once present (today they are "absent, not compared"); add the comparison to the runner.

Reports: ws2 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
