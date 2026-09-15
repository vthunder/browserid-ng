---
# browserid-ng-h2ze
title: Scope parameters cap / counterparties / max_duration end to end (for browserid-pay-8nxm)
status: in-progress
type: feature
created_at: 2026-09-15T14:44:37Z
updated_at: 2026-09-15T14:44:37Z
---

Warrants carry payment/agreement scope parameters on both lanes: core ScopeParams (cap, counterparties, max_duration), registrar accepts scope entries in filed requests and preserves them verbatim, signing surfaces pass them through, wallet-owned labels render them, SDKs accept entries, specs updated. Audience-enforced (a custodian), never wallet-enforced.

- [ ] core ScopeParams + tests
- [ ] registrar entries end to end
- [ ] signing surfaces (consent.html, authorize.html, dialog.js, wallet)
- [ ] labels
- [ ] SDKs + request-kinds schema + protocol spec
- [ ] tests (cargo, node, e2e)
