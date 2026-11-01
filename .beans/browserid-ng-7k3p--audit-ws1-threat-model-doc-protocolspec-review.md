---
# browserid-ng-7k3p
title: 'Audit WS1: threat model doc + protocol/spec review'
status: completed
type: task
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-01T15:43:06Z
parent: browserid-ng-ag1l
---

Write docs/design/threat-model.md: adversaries (malicious RP, malicious primary IdP, compromised broker, compromised agent, malicious MCP server, network attacker, hosted-IdP co-tenant), what each sees/sends. Review docs/specs/browserid-ng-protocol.md, registry-api-v1.md, fallback-idp-api-v1.md, request-kinds/*: assertion binding (aud/nonce/exp/DPoP), delegation-chain narrowing semantics, revocation/status timing, DNSSEC anchoring + fallback downgrade, holder/subject isolation, scope grammar incl. / * @ + and min_reputation. Spec-vs-code divergence list. Output: threat model + list of testable invariants feeding WS2/WS3.

## Summary of Changes
- docs/design/threat-model.md: flows F1-F5, adversaries A1-A10, assets, boundaries B1-B8, invariants I1-I28.
- docs/security-audit-2026-11-ws1-spec-review.md: 20 class-A divergence candidates (D1-D20, unverified, routed), spec findings S1-S13, B/C/D drift summary, handoff list.
- Method: full spec read + three parallel read-only divergence agents (verification, registry, issuance). No skeptic pass yet; that is WS4-6.
