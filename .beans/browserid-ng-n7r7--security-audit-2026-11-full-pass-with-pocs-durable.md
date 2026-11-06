---
# browserid-ng-n7r7
title: 'Security audit 2026-11: full pass with PoCs, durable tooling'
status: scrapped
type: epic
priority: normal
created_at: 2026-11-01T12:40:27Z
updated_at: 2026-11-01T12:41:04Z
---

Full-pass security audit of browserid-ng (not differential: July-29 baseline is not trusted as complete). Ordering: never-audited surface first, July ledger re-verified as a checklist. PoCs against a LOCAL broker only for High+ findings. Fuzz harnesses, test vectors, and authz matrix land in repo + CI; the report is one-off at docs/security-audit-2026-11.md. Fold in open items: oawf (deferred July findings), jvcl (skipped cert-leak e2e), d259 (on-chain verifier conformance).

Workstreams (children) in dependency order:
1. Threat model + spec review (oracle for everything else)
2. Conformance test vectors (multi-verifier)
3. Fuzz + property tests (parsers, delegation-chain narrowing)
4. Code review: agent/MCP + wallet + hosted IdP (never audited)
5. Code review: broker HTTP + authz matrix
6. Code review: crypto core + verifiers (re-verify July)
7. Supply chain / build / deploy / secrets
8. Red-team scenario walkthroughs + PoCs
9. Report + remediation beans

## Reasons for Scrapping
Duplicate from a failed scripted create; superseded by browserid-ng-ag1l.
