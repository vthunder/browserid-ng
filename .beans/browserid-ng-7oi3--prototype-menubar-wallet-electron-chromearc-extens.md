---
# browserid-ng-7oi3
title: 'Prototype: menubar wallet (Electron) + Chrome/Arc extension — native login + approval push'
status: in-progress
type: task
priority: normal
created_at: 2026-08-26T23:52:02Z
updated_at: 2026-08-27T00:12:50Z
parent: browserid-ng-7v5l
---

Overnight prototype build (2026-08-27 → 28), decisions made with Dan before bed:

- **Stack:** Electron menubar/tray app (reuses JS SDKs)
- **Transport:** app listens on 127.0.0.1 with a pairing token + Origin checks; MV3 extension talks to it (no native messaging — Arc-safe)
- **Bootstrap:** one-time browser pairing — app opens browserid.me, user authenticates and approves; app registers its own device key/holder
- **Scope:** (1) login flow — Arc → demo RP → click sign in → native approval from the menubar app → logged in, no popup; (2) approval push — native macOS notifications for pending agent-warrant approvals. Local wallet MCP explicitly out of scope tonight.
- **Ground rules:** branch proto/menubar-wallet + new top-level dir, nothing deploys, build/test against prod browserid.me with a test identity; Dan's real account only for the morning demo. Playwright + Chromium-with-extension for e2e; Arc validated by Dan in the morning.

## Todo

- [x] Recon: map the dialog.js login ceremony (endpoints, session requirements, presentation shape, include.js delivery)
- [x] Recon: map bootstrap/pairing lanes + pending-approval visibility for notifications (finding: agent-provision lane yields no config cert, so session-lane bootstrap chosen; no external approvals endpoint, so cookie-session polling)
- [x] Scaffold Electron app: tray, keystore, localhost server, ceremony client
- [x] Scaffold MV3 extension: navigator.id shim content script + service worker bridge (accessor-with-swallowing-setter beats include.js reinstall)
- [ ] Bootstrap pairing flow working against prod: interactive BrowserWindow lane built but only exercised via the password test lane against the local broker; Dan walks it on prod in the morning
- [x] Login e2e: demo RP signs in via the app under Playwright (e2e.mjs green: shim owns navigator.id on the real broker-demo, no popup, /verify okay)
- [x] Approval-push notifications: wired via persisted-Electron-session polling of /wsapi/warrant_requests (test-approvals.mjs green); no external endpoint exists, clean fix documented in README (device-cert-authed inbox)
- [x] Write-up: README.md with morning Arc instructions, design notes, and protocol findings

**Overnight status (2026-08-28 early):** all automated lanes green against a local broker: ceremony unit test (bootstrap, device/config certs, self-signed warrant, cookie-free access mint, /verify okay, warrant reuse, wrong-audience rejected), approvals-path test, and the full Playwright e2e (Chromium + unpacked extension + real broker-demo page: no popup, page logs in). Remaining: the morning walk-through by Dan (interactive bootstrap window against prod browserid.me + the same click-through in Arc). Code on branch proto/menubar-wallet under prototypes/menubar-wallet/.
