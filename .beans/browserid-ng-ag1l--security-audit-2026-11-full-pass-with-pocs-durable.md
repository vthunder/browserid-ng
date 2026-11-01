---
# browserid-ng-ag1l
title: 'Security audit 2026-11: full pass with PoCs, durable tooling'
status: todo
type: epic
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-01T19:34:52Z
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

## Prior-finding checklist
Still-open August findings to fold in: 25kf (spec describes superseded trust model), kh0j (RP trusts Web-PKI .well-known keys), 97jn (mingo.place unrevocable certs), 16i2 (golden-vector test passes when file absent -> WS2), fpcc (audience raw-string match, no canonicalizer -> WS6).
Discrepancy to resolve in WS5: oawf says ytjn/dw35/7ww7 are still open in code, but those beans are marked completed. Verify in code which is true; treat every 'completed' July remediation as a claim to re-verify, not a fact.

## WS1 done 2026-11-01
Threat model: docs/design/threat-model.md. Report: docs/security-audit-2026-11-ws1-spec-review.md. Spec decisions needed from Dan before code changes: S1 (login_page return-origin gating), S10 (restore path confirmation), S3 (v1 refless sunset), S4 (warrant status.uri constraints), S7 (who enforces scope parameters).

## Spec decisions 2026-11-01
Accepted S1 S2 S5 S6 S9 S10 S13 -> bean browserid-ng-kgjr. S3 decided: drop v1 warrants outright (in kgjr). S4 decided: no registry allowlist, safe-fetch + list-signer rule (in kgjr). S7 decided: generic mechanism in core, pay params move to browserid-pay (in kgjr). S8 decided: doc drift, editorial (in kgjr). S11 decided: same-answer fixes, low (in kgjr). Open: S12.
