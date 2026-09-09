---
# browserid-ng-jo0m
title: 'Native wallet approvals: host the consent page in the wallet with a signing bridge'
status: todo
type: feature
priority: high
created_at: 2026-09-09T23:14:37Z
updated_at: 2026-09-09T23:14:37Z
parent: browserid-ng-9yyk
---

Today the native wallet's inbox poll notifies on a new request and opens /consent/<code> in the system browser, which has no signing key on a wallet-only machine — approval is impossible there. A native rebuild of the consent UI is the wrong fix: the page renders seven card shapes (agent, on-behalf with chooser, agent re-asking with its own address, foreign agent, connection admission, authoring admission, deny-only unknown agent) plus notices, and two UIs would drift.

Design (Dan, 2026-09-10): the wallet HOSTS the real consent page. Clicking the notification opens `/consent/<code>` in a BrowserWindow in the wallet's partition (like the login page today) with a preload bridge the page feature-detects:
- `browseridWallet.identity`, `browseridWallet.configCert`
- `browseridWallet.signWarrant(claims)` → JWS by the wallet's config key (keys never enter the page)
- `browseridWallet.registryCall(method, path, body)` → proxied to wallet/src/registry.js apiCall (the wallet's session + login key; the page opens no session of its own)

consent.html uses the bridge at its three seams — `localConfig`, `signWarrant`/`signWarrantV2`, and `reg` — and skips its own registry setup / sign-out logic when the bridge is present. The browser wallet keeps the keystore path; one UI for both.

- [ ] Preload bridge (contextBridge) + window host in wallet/src (bootstrap.js has the partition window pattern)
- [ ] consent.html: bridge detection at the three seams; no keystore, no page session, no sign-out when bridged
- [ ] Notification click → hosted window; window closes on the page's 'All set' / return
- [ ] Wallet e2e: file an agent request against the local broker, approve through the hosted page, assert the warrant lands in the requester's poll; deny path; notice path
- [ ] CSP: consent.html hash; the preload must not need inline script changes beyond that

Out of scope (stay on e98a): the login page's later methods, the general mediator in the embedded browser, deferred attach, re-entrancy, identity choice.
