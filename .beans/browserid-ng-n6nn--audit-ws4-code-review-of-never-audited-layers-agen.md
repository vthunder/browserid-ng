---
# browserid-ng-n6nn
title: 'Audit WS4: code review of never-audited layers: agent/MCP, wallet, hosted IdP'
status: completed
type: task
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-02T21:59:42Z
parent: browserid-ng-ag1l
---

sdk/mcp-auth + sdk/gate (OAuth 2.1 AS, 7521 assertions, per-call status, audience confusion, warrant scope enforcement, what an MCP server can induce an agent to sign); wallet extension + wallet-service (key storage, origin checks on messaging, WinChan/popup trust, request-lanes consent clarity); browserid-agent SDK + mingo CLI key custody; hosted primary IdP tenancy (custodial keys, tenant isolation, DNS delegation checks); OIDC bridge; signing grants; cookie session admission. Reviewer-then-skeptic method as in July.

## From WS1 — candidates to confirm/refute
D3 hosted_idp holder passthrough; D5 mcp-auth/gate ignore bindings; D6 gate fails open on 503 and single-server mode never re-checks; D12 wallet signs under unverified stored grants; D13 wallet-service drops status refs; D17 local-part case folding; D19 FedCM server-side warrant with no refs; D20 binding.id not 1:1 in mcp-auth. See docs/security-audit-2026-11-ws1-spec-review.md §1.

## Checklist
- [x] MCP layer (mcp-auth, gate, python-mcp-auth): D5, D6, D17, D20 + W4-10..14
- [x] Wallet layer (Electron wallet, extension, wallet-service): D12, D13, D17 + W4-20..23
- [x] Broker layer (hosted IdP, OIDC bridge, session_admit, FedCM): D3, D19 + W4-30..34
- [x] Agent SDK + mingo custody: W4-40..44, July M2/L10
- [x] Tests per harness, failing-today ones skipped/ignored with AUDIT-2026-11 markers
- [x] Report docs/security-audit-2026-11-ws4-layers.md

## Summary of Changes
Report: docs/security-audit-2026-11-ws4-layers.md. Verdicts: D3 confirmed (Medium), D5 confirmed (Medium), D6 confirmed in two halves (Medium; HTTP 503 actually fails closed, only a thrown fetch fails open), D12 refuted (Low d-i-d residue), D13 confirmed (Low), D17 confirmed in mcp-auth/gate only (Low), D19 confirmed bounded to 5 min (Low, decision), D20 confirmed (Low). New findings: W4-22 (Medium, wallet-service admits delegated presentations as the human), W4-30 (Medium, tenant onboarding squat), W4-31, W4-10..14, W4-20/21/23, W4-32..34, W4-40..42/44 (Low/Info). Tests: broker 13 pass / 7 ignored; mcp-auth 12/8; gate 11/6; python 7/2; wallet 6/2(+2 env); wallet-service 7/3; agent 5/5. No production code changed. 12 decisions listed for Dan in report §5.
