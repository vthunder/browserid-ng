---
# browserid-ng-tx5r
title: 'Audit WS8: red-team scenario walkthroughs + PoCs (local broker only)'
status: completed
type: task
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-02T22:32:54Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-n6nn
    - browserid-ng-t25u
    - browserid-ng-p5vc
---

Trace end-to-end: evil RP phishing an assertion; evil MCP server escalating a
warrant; co-tenant on hosted IdP; stolen session cookie / recovery cannot
evict attacker; stale status list defeating revocation; key compromise ->
can everything be revoked? Build PoCs for every High+ candidate from WS4-6
against a local :3000 broker. Never against prod.

## Checklist
- [x] D1 base identity speaks as +tag subaddress — reproduced (core, in-process)
- [x] D2 respond accepts a non-IdP-signed config cert — reproduced (broker, full HTTP)
- [x] D3 caller-chosen holder on hosted IdP — reproduced (existing WS4 test, --include-ignored)
- [x] W4-22 hosted wallet admits a delegated presentation as the human — reproduced (wallet-service)
- [x] D5 narrowed policy row admits any holder — reproduced (mcp-auth + gate)
- [x] D8 approval-code brute force — takeover refuted; no-limiter exposure quantified (~20k req/s, zero 429)
- [x] W6-3/W5-8 zlib bomb via status-list decoder — reproduced (~1 MB -> 845 MiB RSS)
- [x] S1 login-page token to attacker return_url — design finding, written walkthrough
- [x] Report docs/security-audit-2026-11-ws8-pocs.md

## Summary of Changes
All seven PoC targets exercised against a local :3000 broker or an in-process
harness; no production host; identities @example.com only. Six reproduced; D8's
takeover stays refuted (quantified as a missing-limiter exposure instead).

New #[ignore]d PoC tests (AUDIT-2026-11 convention):
- browserid-core/tests/audit_2026_11_ws8_d1.rs (D1)
- browserid-core/tests/audit_2026_11_ws8_w6_3.rs (W6-3/W5-8)
- browserid-broker/tests/audit_2026_11_ws8_d2.rs (D2)
D3, W4-22, D5 use the existing WS4 encoded tests; D8 is a measurement; S1 a walkthrough.

Report: docs/security-audit-2026-11-ws8-pocs.md (method, results table, D8
quantification, S1 phishing-shape walkthrough). No production code changed;
JS audit tests restored unchanged. WS9 (remediation beans) can now proceed.
