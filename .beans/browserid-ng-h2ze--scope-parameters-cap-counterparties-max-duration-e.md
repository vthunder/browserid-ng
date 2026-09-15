---
# browserid-ng-h2ze
title: Scope parameters cap / counterparties / max_duration end to end (for browserid-pay-8nxm)
status: completed
type: feature
priority: normal
created_at: 2026-09-15T14:44:37Z
updated_at: 2026-09-15T15:08:56Z
---

Warrants carry payment/agreement scope parameters on both lanes: core ScopeParams (cap, counterparties, max_duration), registrar accepts scope entries in filed requests and preserves them verbatim, signing surfaces pass them through, wallet-owned labels render them, SDKs accept entries, specs updated. Audience-enforced (a custodian), never wallet-enforced.

- [x] core ScopeParams + tests
- [x] registrar entries end to end
- [x] signing surfaces (consent.html, authorize.html, dialog.js, wallet)
- [x] labels
- [x] SDKs + request-kinds schema + protocol spec
- [x] tests (cargo, node, e2e)

## Summary of Changes

Core: ScopeParams gains cap {amount, currency, window?}, counterparties, max_duration + parsers + stricter-wins. Registrar: filed/record/provision/allocate_status take scope entries; fingerprints key by scope string; both respond lanes compare entries exactly (agent lane previously checked no scopes at all). Pages: common/js/scope-labels.js is the one label table (dialog, consent, authorize, account); CSP hashes bumped. Wallet/SDKs/specs updated. Tests: 553 cargo passed; sdk/agent 22; e2e request-kinds/sbo-signing-grants/paired-provisioning/connection-sharing 9 passed. Not pushed, not deployed.
