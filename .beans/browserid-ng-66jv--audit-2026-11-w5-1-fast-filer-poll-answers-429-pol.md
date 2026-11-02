---
# browserid-ng-66jv
title: '[Audit 2026-11] W5-1: fast filer poll answers 429 PollTooFast'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W5-1 (I18). Severity: Low. Decision: none needed.

Where: browserid-registrar/src/consent.rs:1868-1872: a fast filer poll answers bad(...) -> RegistrarError::ValidationError -> 400 slow_down; RegistrarError::PollTooFast (429) exists at error.rs:107 and is unused here.

Change: return PollTooFast with Retry-After. Check sdk/agent and the wallet poll loops handle 429 (WS1 class D noted sdk/agent expects 410/429 already).

Acceptance (un-ignore): browserid-broker/tests/authz_matrix_test.rs: poll_too_fast_is_429.

Reports: ws5 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
