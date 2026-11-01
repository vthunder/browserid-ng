---
# browserid-ng-p1ao
title: 'Audit WS2: conformance test-vector suite run by every verifier'
status: todo
type: task
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-01T15:43:06Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-7k3p
---

Expand test-vectors/ from one file to accept+reject cases derived from WS1 invariants (bad sig, wrong aud, expired, widened scope in chain, revoked intermediate, malformed TXT, etc). Runner for Rust verifier, sdk/js, sdk/python-mcp-auth, wallet. Any disagreement between verifiers is a finding. Lands in CI.

## From WS1
Build vectors from threat-model I1-I11. Missing vectors called out in docs/security-audit-2026-11-ws1-spec-review.md §4: array-form bindings, malformed identities (a@b@c, @x), mixed-case local parts, future iat, refless v1 warrant, constraints present, scope entries with parameters. Run all six verifiers (core, hosted /verify, sdk/js, python, mcp-auth, gate). Expect D5, D7, D17 to show as cross-verifier disagreement.
