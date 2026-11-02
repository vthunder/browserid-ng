---
# browserid-ng-hp8k
title: '[Audit 2026-11] S5: amend §4.7 to name core as implementing aud/scopes/max-ttl; flip P-CONS-01/06'
status: todo
type: task
priority: normal
created_at: 2026-11-02T22:43:21Z
updated_at: 2026-11-02T22:43:21Z
parent: browserid-ng-ag1l
---

Spec edit, not code. Findings: S5 (refuted as a code gap by WS6: core already fails closed on unknown constraint keys and enforces aud, scopes, max-ttl; WS2 confirms the spec/code divergence on P-CONS-01/06). Decision: Q24 settled 2026-11-02: (a) amend §4.7 to name browserid-core (and everything built on it) as implementing those three keys; the two vectors flip to accept. (b) would strip the core implementation.

Under (a): edit docs/specs/browserid-ng-protocol.md §4.7; in browserid-core/tests/audit_2026_11_ws2_generate.rs flip P-CONS-01 and P-CONS-06 to accept and regenerate (WS2_REGEN=1 for core and hosted); delete the S5 rows from EXPECTED_FAIL in every runner (core, hosted, sdk/js, python, mcp-auth, gate). The S5 corner (a scopes allowlist never restricts a scope-less login; use aud) is already settled by the spec edits and pinned by s5_scope_allowlist_is_vacuous_for_a_scope_less_login_warrant.

Reports: ws6 §1.7, ws2 §2 and §6. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
