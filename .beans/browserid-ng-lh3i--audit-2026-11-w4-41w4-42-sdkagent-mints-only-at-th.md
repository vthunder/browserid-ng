---
# browserid-ng-lh3i
title: '[Audit 2026-11] W4-41/W4-42: sdk/agent mints only at the cert''s iss over https; key seeds are not inspectable'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:44:11Z
parent: browserid-ng-ag1l
---

Findings: W4-41 and W4-42 (sdk/agent hardening). Severity: Low. Decision: none needed.

Where: sdk/agent/src/device.mjs:143-150, :297, :384-385: the mint endpoint and IdP are taken verbatim from the registrar's poll body, never cross-checked against the device cert's iss, and https is not required (a lying registrar redirects every device-key-signed access request to itself; no key leaves the process and the signed request is unusable at the real IdP, so attribution/availability only). sdk/agent/src/device.mjs:291, src/crypto.mjs:33, :43: private key seeds sit on public properties, so console.log(agent), util.inspect or JSON.stringify prints the seed (log aggregators and crash dumps become a key-leak path; the in-memory counterpart of July L10).

Change: derive idpDomain from deviceCertClaims.iss, refuse a mismatching credential.idp, require https: (loopback exempt); make seeds private fields with toJSON and util.inspect.custom redaction on DeviceAgent and KeyPair. mingo CLI (mingo-app/src/login.rs) wraps this SDK; check its logging after the change.

Acceptance: un-skip sdk/agent/audit_2026_11_ws4.test.mjs: "W4-41: the agent mints only at the IdP that signed its device cert", "W4-41: a poll-supplied access_mint on another host or a cleartext scheme is refused", "W4-42: inspecting a DeviceAgent does not print the device key seed", "W4-42: inspecting a KeyPair does not print its seed".

Reports: ws4 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

- W4-41, sdk/agent/src/device.mjs: `DeviceAgent.idpDomain` is now the SIGNED device cert's `iss` (a cert without `iss` is refused at construction); a credential `idp` is accepted only when its host (with or without port) equals that `iss`, and the mint endpoint (`access_mint`, else `<idp>/access/mint`, else `https://<iss>/access/mint`) must sit on the `iss` host and use https — loopback hosts (`localhost`, `127.0.0.1`, `::1`) may be http for dev brokers. A lying registrar can no longer redirect device-key-signed access requests elsewhere.
- W4-42: `KeyPair` keeps its seed in a private field; `seed` is an explicit getter returning a copy; `toJSON` and `util.inspect.custom` print the public key only. `DeviceAgent` keeps the credential in a private field behind a `credential` getter, with `toJSON` / inspect redaction (email, holder, idp, cert, warranted audiences). Types updated (`readonly credential`, `readonly idpDomain`, `readonly seed`).

Tests: un-skipped the four W4-41/W4-42 tests in sdk/agent/audit_2026_11_ws4.test.mjs. Fixture device certs in sdk/mcp-auth (authcode, authcode-integration) and sdk/gate (admin, gate, multimount, local-grants, lifecycle, roles) now carry `iss: new URL(BROKER).host`, as a real cert would. mingo CLI (mingo-app/src/login.rs) wraps the Rust agent, not this SDK — nothing to re-check there for the inspect change; any JS consumer that logged `agent.credential` directly still can (explicit read), only incidental dumps are redacted.
