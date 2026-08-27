---
# browserid-ng-7oi3
title: 'Prototype: menubar wallet (Electron) + Chrome/Arc extension — native login + approval push'
status: completed
type: task
priority: normal
created_at: 2026-08-26T23:52:02Z
updated_at: 2026-08-27T08:57:36Z
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
- [x] Bootstrap pairing flow working against prod — Dan walked it live 2026-08-28: /account session detect + identity chooser + primary-IdP hop (silent issue on warm session), certs for danmills@sandmill.org stored
- [x] Login e2e: demo RP signs in via the app under Playwright (e2e.mjs green: shim owns navigator.id on the real broker-demo, no popup, /verify okay)
- [x] Approval-push notifications: wired via persisted-Electron-session polling of /wsapi/warrant_requests (test-approvals.mjs green); no external endpoint exists, clean fix documented in README (device-cert-authed inbox)
- [x] Write-up: README.md with morning Arc instructions, design notes, and protocol findings

**Overnight status (2026-08-28 early):** all automated lanes green against a local broker: ceremony unit test (bootstrap, device/config certs, self-signed warrant, cookie-free access mint, /verify okay, warrant reuse, wrong-audience rejected), approvals-path test, and the full Playwright e2e (Chromium + unpacked extension + real broker-demo page: no popup, page logs in). Remaining: the morning walk-through by Dan (interactive bootstrap window against prod browserid.me + the same click-through in Arc). Code on branch proto/menubar-wallet under prototypes/menubar-wallet/.

## Summary of Changes

Working end-to-end, human-confirmed in a real browser with a real primary identity (2026-08-28): Electron menubar wallet (tray, native approval dialogs, localhost bridge with pairing token) + MV3 extension (page-world navigator.id shim that survives include.js, relay, service worker) sign danmills@sandmill.org into broker-demo with no popup — IdP-issued device+config certs via the device-authorize return_url lane, per-audience managed access mints at idp.browserid.me, self-signed login warrants, /verify okay. Approval-push wired via persisted-session polling of /wsapi/warrant_requests. Test suites: ceremony unit, approvals path, full Playwright e2e — green against a local broker.

Hard-won findings: macOS 26 grants menubar status items only to LaunchServices-launched processes (run.sh / open -n; terminal-spawned trays are invisible, zero-height even for native AppKit); device-authorize hard-requires return_origin even when return_url is the delivery lane; managed identities must name the audience in the access request (dialog parity); Electron apps need Edit menu roles for Cmd+V; agent-provision lane yields no config cert so the session lane is the right bootstrap. Design outcome agreed with Dan: the double-login bootstrap is wrong — follow-ups filed for email-first single-login (auth_with_presentation join) and a device-cert-authed registry lane; the client-broker vs server-broker delineation is recorded on the parent explore bean (7v5l).
