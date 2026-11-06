---
# browserid-ng-la0k
title: '[Audit 2026-11] W4-14: python-mcp-auth handles object scope entries (refuse or relay, never 500)'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:22:17Z
parent: browserid-ng-ag1l
---

Findings: W4-14 (confirmed by WS2 with the entries probe). Severity: Low. Decision: settled by S7 (relays pass entries verbatim or refuse what they cannot represent).

Where: sdk/python-mcp-auth/browserid_mcp_auth/__init__.py:235: an object scope entry (what a D7-fixed verifier returns) makes handle_token raise TypeError from " ".join(scopes): an unhandled 500 rather than a refusal or a verbatim relay. mcp-auth renders [object Object] in the string form but keeps the objects.

Change: refuse entries the AS cannot represent, or render the string form (entry.scope) for the OAuth scope string and keep the full entry in ctx for the tool gate. Same review in mcp-auth for the rendered string.

Acceptance: un-skip sdk/python-mcp-auth/tests/test_audit_2026_11_ws4.py test_parameterised_scope_entries_fail_closed; delete the W4-14 row (P-OK-08/entries) from EXPECTED_FAIL in sdk/python-mcp-auth/tests/test_conformance_vectors.py.

Reports: ws4 §2, ws2 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

S7 relay rule in the Python port: object scope entries are relayed verbatim and never crash the token endpoint.

- sdk/python-mcp-auth/browserid_mcp_auth/__init__.py: new `_scope_name(entry)` (a bare string, the `scope` of a `{"scope": name, ...}` wire entry, or the key of a `{name: {params}}` entry; None otherwise). `handle_token` refuses a non-list `scopes` or an entry it cannot name with a clean `invalid_grant` (no more `TypeError` → 500), keeps every entry verbatim in the grant / `ctx.scopes` (type now `List[object]`), and renders the OAuth `scope` string by entry name. Narrowing (`scope=` on the token request) and `require_warrant` keep comparing string-to-entry, so an object entry never satisfies a string tool scope (fail closed). README documents the shape.

Tests: un-skipped `test_parameterised_scope_entries_fail_closed`; the "crash the token endpoint today" pin is replaced by one asserting the rendered scope string and the refusal of an unnameable entry. Conformance: `P-OK-08/entries` un-listed in sdk/python-mcp-auth/tests/test_conformance_vectors.py (P-OK-07/P-OK-08 stay D7 until the hosted responses are re-recorded by bean oa6s).
