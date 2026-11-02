---
# browserid-ng-la0k
title: '[Audit 2026-11] W4-14: python-mcp-auth handles object scope entries (refuse or relay, never 500)'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W4-14 (confirmed by WS2 with the entries probe). Severity: Low. Decision: settled by S7 (relays pass entries verbatim or refuse what they cannot represent).

Where: sdk/python-mcp-auth/browserid_mcp_auth/__init__.py:235: an object scope entry (what a D7-fixed verifier returns) makes handle_token raise TypeError from " ".join(scopes): an unhandled 500 rather than a refusal or a verbatim relay. mcp-auth renders [object Object] in the string form but keeps the objects.

Change: refuse entries the AS cannot represent, or render the string form (entry.scope) for the OAuth scope string and keep the full entry in ctx for the tool gate. Same review in mcp-auth for the rendered string.

Acceptance: un-skip sdk/python-mcp-auth/tests/test_audit_2026_11_ws4.py test_parameterised_scope_entries_fail_closed; delete the W4-14 row (P-OK-08/entries) from EXPECTED_FAIL in sdk/python-mcp-auth/tests/test_conformance_vectors.py.

Reports: ws4 §2, ws2 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
