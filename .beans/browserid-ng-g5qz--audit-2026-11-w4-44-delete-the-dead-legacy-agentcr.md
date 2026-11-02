---
# browserid-ng-g5qz
title: '[Audit 2026-11] W4-44: delete the dead legacy Agent/Credential lane from @browserid-ng/agent'
status: todo
type: bug
priority: low
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W4-44. Severity: Info. Decision: Q23 settled 2026-11-02 (delete at the next major).

Where: sdk/agent/src/agent.mjs:259-262, :281-285: the legacy Agent / Credential lane posts {request_bundle} the registrar does not accept, reads json.warrants where the server sends grants, /provision/endorse and /provision/mint 404, and keeps the cleartext secret_key format alive. Dead but exported (WS1 class D confirmed).

Change: delete Agent, Credential and the provisioning helpers from @browserid-ng/agent at the next major (breaking export) and note it in the changelog; or leave documented as dead.

Acceptance: the pin "W4-44 (pin)" in sdk/agent/audit_2026_11_ws4.test.mjs is deleted with the code.

Reports: ws4 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
