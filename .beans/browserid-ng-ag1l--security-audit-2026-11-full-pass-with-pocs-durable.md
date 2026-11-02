---
# browserid-ng-ag1l
title: 'Security audit 2026-11: full pass with PoCs, durable tooling'
status: todo
type: epic
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-02T22:50:45Z
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
Accepted S1 S2 S5 S6 S9 S10 S13 -> bean browserid-ng-kgjr. S3 decided: drop v1 warrants outright (in kgjr). S4 decided: no registry allowlist, safe-fetch + list-signer rule (in kgjr). S7 decided: generic mechanism in core, pay params move to browserid-pay (in kgjr). S8 decided: doc drift, editorial (in kgjr). S11 decided: same-answer fixes, low (in kgjr). S12 deferred as accepted risk (threat-model §6). All spec findings decided.


## WS9 done 2026-11-02: ledger, decisions, remediation beans

- Ledger: docs/security-audit-2026-11.md (July format; post-verification severities: 3 High, 29 Medium, 44 Low, 5 Info; refuted leads in §2; cross-verifier summary §3; July re-verification §4; remediation order §5).
- Decisions: docs/security-audit-2026-11-decisions.md, Q1-Q29 all settled 2026-11-02, so every remediation bean is todo.
- Remediation beans (63, all children of this epic, bug unless noted), by group:
  1. Chokepoints: D2 0fy3 -> W5-14 u6f2; S1/W5-10 rw5q; D3 2lgy; D4/D18 jvfr; W5-7 o1zy; W5-4 a7mx; W4-31/32 cn3f; W4-30 dobu.
  2. Resource exhaustion: W6-3/W5-8/W3-4 rn46; W6-5/W5-5 2tyx; W5-6/W4-23 gajq -> D8 4r2j, W5-2 i4kj; infra task zthh (XFF declaration).
  3. Clock rule: gdo0 (D16/S6/W3-1/W3-2) -> W4-40 b18d; W6-2 hgxv.
  4. Identity rule: D1 v8s0 -> W6-1 j84h; D17/W2-3/W2-4 4y7y; W2-1 0vk8; W3-3/W5-11 lu7i.
  5. Verifier conformance: D7 oa6s -> W4-13 fqnh; W4-14 la0k; W6-4 lnf7; D14 rq5b; D15 ll22; S3 3zpa; W2-5 94k7; W2-6 zsi1; S5 spec task hp8k.
  6. MCP/wallet layers: D5 cjh3; D6/W4-12 0og2; W4-22 2x2w; D13 3k53; D20 g4gs; W4-10/11 1x50; W4-20 25lq; W4-21 hynd; W4-34 whxv; W4-33 1676; W4-41/42 lh3i; D12 7ith; W4-44 g5qz; D19 vpdi.
  7. Supply chain/ops: R7-1..3 task j0rh; W7-2 s6ya; W7-12 t7pa; W7-10/11 fy1k; W7-8 4c8h (blocked by infra task u3q7); W7-5/6/7 9jle; W7-9 infra task afn5; PostHog salt jxhb; fuzz cadence task yk2z.
  8. Broker Lows: D9 cd6r; D11 uphh; W5-1 66jv; W5-3/W5-12/S11 imn6; W5-13/15 1dy0; C1 residual eetq.
- Prior-finding checklist: oawf stale claim corrected (ytjn/dw35/7ww7 fixed); its remaining items are D8/W5-2/W5-3/S11/W5-6 above. 16i2 is superseded by the WS2 suite (drift check fails on a missing file); fpcc is covered by I4 vectors (byte-exact audience, pinned); 25kf/kh0j/97jn were not re-examined by WS9 and stay open on their own beans.
