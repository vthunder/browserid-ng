---
# browserid-ng-p1ao
title: 'Audit WS2: conformance test-vector suite run by every verifier'
status: completed
type: task
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-02T22:05:42Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-7k3p
---

Expand test-vectors/ from one file to accept+reject cases derived from WS1 invariants (bad sig, wrong aud, expired, widened scope in chain, revoked intermediate, malformed TXT, etc). Runner for Rust verifier, sdk/js, sdk/python-mcp-auth, wallet. Any disagreement between verifiers is a finding. Lands in CI.

## From WS1
Build vectors from threat-model I1-I11. Missing vectors called out in docs/security-audit-2026-11-ws1-spec-review.md §4: array-form bindings, malformed identities (a@b@c, @x), mixed-case local parts, future iat, refless v1 warrant, constraints present, scope entries with parameters. Run all six verifiers (core, hosted /verify, sdk/js, python, mcp-auth, gate). Expect D5, D7, D17 to show as cross-verifier disagreement.

## Checklist (2026-11-02)
- [x] Deterministic generator + drift check: `browserid-core/tests/audit_2026_11_ws2_generate.rs` → `test-vectors/conformance-2026-11.json` (177 vectors: 116 P, 43 A, 18 TXT)
- [x] Covers every WS1 §4 / lead-listed family: bad sig, wrong aud, expired, future iat, iat>exp, widened scope in chain, revoked intermediate, malformed TXT, array bindings, malformed identities (a@b@c, @x), mixed-case local parts, v1 warrant, constraints present, scope parameters, ≠4 objects, unknown typ/purpose, grantee matcher / connection / missing holder in P, requester in A, req_origin mismatch
- [x] Runners: Rust core, hosted (in-process, records `conformance-2026-11.hosted.json`), sdk/js, python-mcp-auth, mcp-auth (P + A with its own subject match), gate (mount over HTTP + allowlist case probes). Wallet has no verifier.
- [x] CI: test.yml (generate + core + hosted, drift-gated) and sdk-tests.yml (js, mcp-auth, gate, python)
- [x] Expected-fail tables per runner tagged `AUDIT-2026-11 <id>`; un-listing is the acceptance test
- [x] Report `docs/security-audit-2026-11-ws2-conformance.md`

## Summary of Changes
Suite of 177 accept/reject vectors derived from threat-model I1–I11 (+I12/I13 chain cases), one runner per verifier, all green in CI with per-runner expected-fail ledgers. Findings: W2-1 (SDKs strip the audience's trailing slash, Low), W2-2 = D5 confirmed (mcp-auth admission ignores binding entries, Medium), W2-3/W2-4 = D17 confirmed (mcp-auth malformed-identity coverage; gate allowlist case folding, Low), W2-5 (sdk/js drops holder/grantee_issuer, Low), W2-6 (TXT parser keeps the last duplicated field, Low). D7, D16, S3, S5, W6-1, W6-4 confirmed across the whole stack. Needs Dan: S5 direction (amend §4.7 to name core vs strip core), W2-1 (stop normalizing `resource`), W2-4 (byte-exact allowlists vs normalize-at-config).

