# @browserid-ng/agent changelog

## 1.0.0 (unreleased)

Breaking (audit 2026-11, W4-44): the legacy provisioning-cert lane is gone.
`Agent`, `Credential`, `NeedCredentialError`, `InvalidCredentialError`,
`AmbiguousNameError` and the provisioning helpers (`mintRequest`,
`revokeRequest`, `warrantRequest`, `bundle`, `backedPresentation`,
`parseCert`, `parseWarrant`, `generatedName`) are no longer exported. That
lane spoke a protocol the broker stopped serving (`/provision/endorse` and
`/provision/mint` 404; `/warrant/request` expects `device_cert`+`identity`+
`grants`, and the poll answers `grants`, not `warrants`), and it kept the
cleartext `secret_key` credential file format alive. Migrate to
`requestProvision` + `DeviceAgent` (the only lane since 0.5).

Hardening (audit 2026-11):
- W4-41: `DeviceAgent` takes its IdP from the SIGNED device cert's `iss`;
  a credential `idp` or `access_mint` on another host, or a non-https mint
  URL off the loopback, is refused.
- W4-42: `KeyPair` seeds and the `DeviceAgent` credential live in private
  fields; `util.inspect`, `console.log` and `JSON.stringify` never print
  key material. `kp.seed` and `agent.credential` remain explicit reads.

`scopeName` / `scopeEntryEq` stay exported (now from `src/scopes.mjs`).
