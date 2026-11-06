---
# browserid-ng-g5qz
title: '[Audit 2026-11] W4-44: delete the dead legacy Agent/Credential lane from @browserid-ng/agent'
status: completed
type: bug
priority: low
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:46:31Z
parent: browserid-ng-ag1l
---

Findings: W4-44. Severity: Info. Decision: Q23 settled 2026-11-02 (delete at the next major).

Where: sdk/agent/src/agent.mjs:259-262, :281-285: the legacy Agent / Credential lane posts {request_bundle} the registrar does not accept, reads json.warrants where the server sends grants, /provision/endorse and /provision/mint 404, and keeps the cleartext secret_key format alive. Dead but exported (WS1 class D confirmed).

Change: delete Agent, Credential and the provisioning helpers from @browserid-ng/agent at the next major (breaking export) and note it in the changelog; or leave documented as dead.

Acceptance: the pin "W4-44 (pin)" in sdk/agent/audit_2026_11_ws4.test.mjs is deleted with the code.

Reports: ws4 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Breaking: @browserid-ng/agent 1.0.0 (package.json bumped from 0.6.1; NOT published).

- Deleted sdk/agent/src/agent.mjs and src/credential.mjs (the legacy provisioning-cert lane: `Agent`, `Credential`, bootstrap/provision/endorse/mint/revoke over endpoints the broker no longer serves, the cleartext `secret_key` credential format) and their test file agent.test.mjs (its known-answer Ed25519 vector moved to device.test.mjs). src/protocol.mjs keeps only the device-path artifacts (`assertion`, `accessRequest`, `accessPresentation`, `nowS`, `ASSERTION_VALIDITY_S`); the provisioning request builders, `bundle`, `backedPresentation`, `parseCert`, `parseWarrant`, `generatedName` are gone. src/errors.mjs drops `NeedCredentialError`, `InvalidCredentialError`, `AmbiguousNameError`.
- `scopeName` / `scopeEntryEq` keep their export, now from the new src/scopes.mjs.
- index.mjs, index.d.ts and README rewritten for the device-only surface; new sdk/agent/CHANGELOG.md records the break and the W4-41/W4-42 hardening.
- The "W4-44 (pin)" and the legacy 0600-file pin were deleted with the code from sdk/agent/audit_2026_11_ws4.test.mjs.

Consumers in this repo (mcp-auth, gate, wallet-service) import only `DeviceAgent` / `requestProvision` / `requestWarrants` / the kept errors and stay green. Their package.json ranges still say `@browserid-ng/agent ^0.4.1` / `^0.6.1` (local symlinks here); bump to `^1.0.0` when publishing.
