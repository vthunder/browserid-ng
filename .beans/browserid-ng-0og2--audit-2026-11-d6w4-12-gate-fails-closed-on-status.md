---
# browserid-ng-0og2
title: '[Audit 2026-11] D6/W4-12: gate fails closed on status (single-server validates; unreachable is not live; 5xx is temporarily_unavailable)'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:15:17Z
parent: browserid-ng-ag1l
---

Findings: D6 (two halves) and W4-12 (Low, shapes D6). Severity: Medium. Decision: Q14 settled 2026-11-02: (a) fail closed on any status failure, keep last-known rows only for the console diff, never delete a row on 5xx; spec §6.4. (b) would allow last-known-good admission for a bounded window. The 5xx row deletion must go either way.

Where: sdk/gate/src/mount.mjs:76-85 (single-server entitlementFor reads policy rows with granteeCovers only: no /validate-record, no status, no exp, so a broker-revoked or expired row keeps admitting jwt-bearer subjects); sdk/gate/src/gateway.mjs:216, :221 (isRowLive returns cached?.ok ?? true when the validator throws: connection refused, DNS); sdk/mcp-auth/index.mjs:318 (validateRecord maps any non-2xx, including 503, to a definitive invalid_grant, so grantsDiff deletes signed policy rows during an outage). WS1's wording ("keeps a row live on a 503") was corrected by WS4: a thrown fetch fails open, an HTTP 503 fails closed but deletes rows.

Change: route the single-server entitlementFor through isRowLive-style validation with exp; in isRowLive drop the ?? true and treat unreachable as not-live for enforcement (last-known only for the console view); in validateRecord map 5xx and 429 to temporarily_unavailable before the generic branch so conjoinPolicy's 503 rethrow fires and grantsDiff never deletes on an outage.

Acceptance:
- un-skip sdk/gate/test/audit_2026_11_ws4.test.mjs: "D6: single-server — a policy row the broker reports REVOKED must stop admitting a jwt-bearer subject", "D6: single-server — an EXPIRED policy row must not admit", "D6: gateway signed mode — an UNREACHABLE validator must fail closed"
- un-skip sdk/mcp-auth/test/audit_2026_11_ws4.test.mjs: "W4-12: an HTTP 5xx from /validate-record is 'temporarily_unavailable', not a definitive invalid_grant"
- delete the D6 rows (A-REJ-13, -20..-31 in policy mode) from EXPECTED_FAIL in sdk/gate/test/conformance-vectors.test.mjs

Reports: ws4 §1.3 and §2 (W4-12), ws2 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Decision Q14 (a): the gate fails closed on any status failure; last-known rows serve only the console diff; a 5xx never deletes a signed row.

- sdk/gate/src/mount.mjs (landed with bean cjh3): the single-server default `entitlementFor` revalidates every covering policy row at `/validate-record` before admitting a jwt-bearer subject (exp checked, status fail-closed, binding asserted; positive results cached ≤ statusCacheS). A broker-revoked or expired row stops admitting.
- sdk/gate/src/gateway.mjs: liveness split into two readers. `rowVerdict(row)` returns `{ok, definitive}`: an unreachable validator or a 5xx is non-definitive (last-known `ok` for the console, `false` when none). `isRowLive` (enforcement) is live only on a definitive OK — the `cached?.ok ?? true` fail-open is gone, and "no mount to validate with" is not live. `grantsDiff` deletes a signed row only on a definitive invalidity, never during an outage.
- sdk/mcp-auth/index.mjs: `validateRecord` (and `redeemPresentation`'s `/verify` call) classes HTTP 5xx and 429 as `temporarily_unavailable` (503) before the generic non-2xx → `invalid_grant` branch, so `conjoinPolicy`'s 503 rethrow fires and the gate's diff keeps the row.

Tests: un-skipped the three D6 tests in sdk/gate/test/audit_2026_11_ws4.test.mjs (revoked row, expired row, unreachable validator) and W4-12 in sdk/mcp-auth/test/audit_2026_11_ws4.test.mjs; the "today an unreachable validator ADMITS" pin was deleted and the "503 reads as invalid_grant" pin flipped. The D6 vectors (A-REJ-20, A-REJ-22..31) were un-listed from the gate runner in the cjh3 commit; A-REJ-13 / A-REJ-21 remain listed as the inherited hosted S3 / D16.
