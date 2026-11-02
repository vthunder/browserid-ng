---
# browserid-ng-25lq
title: '[Audit 2026-11] W4-20: native wallet prompt names auto vs prompt mode and renders parameters'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W4-20. Severity: Low. Decision: none needed (spec §5 / §7.5: the consent card says auto-mode scopes are standing authority).

Where: wallet/src/request.js:116-120 and main.js approveRequest: the native warrant prompt renders bare scope names; a page requesting sign:sbo:post (default auto) gets silent repeated signing after a prompt that never said so; parameters are invisible too (the safe direction). Related, code-read only: prompt-mode signature summaries (request.js:233-241) render four fields while signingBytes signs every envelope field (owner is identity-pinned, so clarity rather than forgery).

Change: feed entries through BrowserIDScopeLabels, call out auto entries as standing authority and prompt entries as per-use, render parameters, and show every signed envelope field in the prompt-mode summary.

Acceptance: un-skip wallet/test/audit_2026_11_ws4.test.mjs "W4-20: the native warrant prompt distinguishes a standing (auto) grant from a prompt-mode one" (run with node --test wallet/test/...; not in npm test). GUI check must be done by Dan locally (memory: dev box renders on an unobserved display).

Reports: ws4 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
