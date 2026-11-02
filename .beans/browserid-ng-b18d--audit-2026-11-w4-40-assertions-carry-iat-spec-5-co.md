---
# browserid-ng-b18d
title: '[Audit 2026-11] W4-40: assertions carry iat (spec §5, core, agents, SDKs)'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:44:00Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-gdo0
---

Findings: W4-40 (spec gap). Severity: Low. Decision: Q19 settled 2026-11-02: (a) add iat to assertions (spec §5, core, Rust agent, JS SDK); one rule for every object. (b) would scope §6.1's lower bound to objects that carry iat.

Where: docs/specs/browserid-ng-protocol.md §5 assertion table lists only aud/exp/req_origin while the amended §6.1 time-bounds paragraph (S6) rejects every checked object unless iat <= exp; sdk/agent/src/protocol.mjs:45-48, browserid-core/src/assertion.rs:14-28 and the JS SDK emit no iat, so no implementation can satisfy §6.1 as written.

Change under (a): add iat to AssertionClaims (core), the Rust agent, sdk/js and sdk/agent signers, and the dialog; verifiers check it through the clock-rule helper (the clock bean) with iat optional during a transition window, then required. Under (b): spec edit only.

Acceptance: the pin "W4-40 (pin): the assertion ... carries no iat" in sdk/agent/audit_2026_11_ws4.test.mjs flips; add P-TIME vectors for assertions (future iat, iat > exp) to the WS2 generator and regenerate.

Reports: ws4 §2, ws6 §1.6. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
