---
# browserid-ng-g4gs
title: '[Audit 2026-11] D20: mcp-auth indexes binding.id 1:1 across records'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: D20. Severity: Low (defence in depth; needs a double-minting registry). Decision: none needed.

Where: sdk/mcp-auth/index.mjs:364, :1296: bindingId is stored on bearer and refresh records but never indexed, so two validated records naming one binding.id both mint (§6.6 invariant 5 not held resource-side).

Change: a bindingId -> record map in the lane; on code release and on every mint/refresh refuse (and optionally burn the existing family) if the id is bound to a different record.

Acceptance: un-skip sdk/mcp-auth/test/audit_2026_11_ws4.test.mjs "D20: a second record naming an already-bound binding.id must be refused".

Reports: ws4 §1.8. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
