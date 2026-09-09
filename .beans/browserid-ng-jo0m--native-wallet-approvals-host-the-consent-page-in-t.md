---
# browserid-ng-jo0m
title: 'Native wallet approvals: host the consent page in the wallet with a signing bridge'
status: completed
type: feature
priority: high
created_at: 2026-09-09T23:14:37Z
updated_at: 2026-09-09T23:25:14Z
parent: browserid-ng-9yyk
---

Today the native wallet's inbox poll notifies on a new request and opens /consent/<code> in the system browser, which has no signing key on a wallet-only machine — approval is impossible there. A native rebuild of the consent UI is the wrong fix: the page renders seven card shapes (agent, on-behalf with chooser, agent re-asking with its own address, foreign agent, connection admission, authoring admission, deny-only unknown agent) plus notices, and two UIs would drift.

Design (Dan, 2026-09-10): the wallet HOSTS the real consent page. Clicking the notification opens `/consent/<code>` in a BrowserWindow in the wallet's partition (like the login page today) with a preload bridge the page feature-detects:
- `browseridWallet.identity`, `browseridWallet.configCert`
- `browseridWallet.signWarrant(claims)` → JWS by the wallet's config key (keys never enter the page)
- `browseridWallet.registryCall(method, path, body)` → proxied to wallet/src/registry.js apiCall (the wallet's session + login key; the page opens no session of its own)

consent.html uses the bridge at its three seams — `localConfig`, `signWarrant`/`signWarrantV2`, and `reg` — and skips its own registry setup / sign-out logic when the bridge is present. The browser wallet keeps the keystore path; one UI for both.

- [x] Preload bridge (wallet/src/consent-preload.js) + window host (wallet/src/consent.js); IPC handlers verify the sender is a live consent window on the broker's /consent page; signing limited to warrant typs, registry calls to /api/v1 paths
- [x] consent.html: bridge at localConfig / signWarrant(V2) / reg; bootBridged (no cookie, no keystore, no page session); loadInbox shared; claim only for record kinds
- [x] Notification click → hostConsent; the page calls bridge.done and the wallet closes the window
- [x] Wallet e2e: agent request approved through the hosted page → requester's poll carries the wallet-signed warrant; a second one denied → poll denied (POST /test/consent {code, action} drives the hidden window). Notices unchanged (notification only).
- [x] CSP: consent.html hash updated; no other change

Out of scope (stay on e98a): the login page's later methods, the general mediator in the embedded browser, deferred attach, re-entrancy, identity choice.

## Summary of Changes

The native wallet hosts the broker's consent page in its own window (partition persist:browserid) with a contextBridge (`browseridWallet`: info, signWarrant, registryCall, done). The page detects the bridge and uses it at its three seams, so every card shape works from a wallet-only machine and the browser wallet's keystore path is untouched. Notification click opens the hosted window instead of the system browser. Verified: wallet e2e (approve + deny end to end), 122 Playwright, cargo test --workspace.
