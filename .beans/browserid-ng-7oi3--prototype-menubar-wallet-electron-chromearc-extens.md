---
# browserid-ng-7oi3
title: 'Prototype: menubar wallet (Electron) + Chrome/Arc extension — native login + approval push'
status: in-progress
type: task
created_at: 2026-08-26T23:52:02Z
updated_at: 2026-08-26T23:52:02Z
parent: browserid-ng-7v5l
---

Overnight prototype build (2026-08-27 → 28), decisions made with Dan before bed:

- **Stack:** Electron menubar/tray app (reuses JS SDKs)
- **Transport:** app listens on 127.0.0.1 with a pairing token + Origin checks; MV3 extension talks to it (no native messaging — Arc-safe)
- **Bootstrap:** one-time browser pairing — app opens browserid.me, user authenticates and approves; app registers its own device key/holder
- **Scope:** (1) login flow — Arc → demo RP → click sign in → native approval from the menubar app → logged in, no popup; (2) approval push — native macOS notifications for pending agent-warrant approvals. Local wallet MCP explicitly out of scope tonight.
- **Ground rules:** branch proto/menubar-wallet + new top-level dir, nothing deploys, build/test against prod browserid.me with a test identity; Dan's real account only for the morning demo. Playwright + Chromium-with-extension for e2e; Arc validated by Dan in the morning.

## Todo

- [ ] Recon: map the dialog.js login ceremony (endpoints, session requirements, presentation shape, include.js delivery)
- [ ] Recon: map bootstrap/pairing lanes + pending-approval visibility for notifications
- [ ] Scaffold Electron app: tray, keystore, localhost server, ceremony client
- [ ] Scaffold MV3 extension: navigator.id shim content script + service worker bridge
- [ ] Bootstrap pairing flow working against prod (test identity)
- [ ] Login e2e: demo RP signs in via the app under Playwright
- [ ] Approval-push notifications (best-effort without broker changes; if it needs a new endpoint, document instead of deploying)
- [ ] Write-up: what worked, protocol gaps found (expect kmvm territory), morning test instructions for Arc
