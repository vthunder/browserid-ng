---
# browserid-ng-7v5l
title: 'Explore: native wallet (browser extension / menubar app) — the real escape hatch'
status: todo
type: feature
priority: normal
created_at: 2026-08-26T23:21:44Z
updated_at: 2026-08-27T08:57:50Z
---

## Idea

Principle 7 says openness lives in the ability to leave — but today there is no way to leave the hosted wallet; the escape hatch is theoretical. A native wallet would make it real, and would dissolve three standing pain points at once:

- popup-blocking lanes (0zj6, a2eu) — an extension needs no popups
- Safari ITP localStorage eviction for broker choice (dcgm, 0efn) — extension storage is not partitioned or engagement-evicted
- the missing approval-push channel (4w3n part 3) — native surfaces can just notify

## Feasibility sketch (the "how does it touch the browser" question)

Two distinct shapes, not mutually exclusive:

**A. WebExtension (MV3, Chrome/Firefox/Safari):**
- content script injects the include.js-equivalent → pages get navigator.id natively, no popup, no iframe
- background service worker holds keys (WebCrypto non-extractable keys in extension storage) and runs the device-cert state machine
- consent UI in the extension action popup; notifications API for approval pushes
- risks: three store review pipelines, MV3 service-worker lifetime quirks, key backup/sync across devices (the hosted wallet's real advantage)

**B. Menubar/tray app (no browser integration at all):**
- hosts the wallet MCP server locally + OS notifications for approvals
- solves the agent-side wallet + push problem without touching the browser; doesn't solve the sign-in-lane problems
- much smaller lift; could ship first as the approval-push fix, with the extension as phase 2

## First steps

- [ ] Decide the wedge: B-first (small, fixes 4w3n push) vs A-first (bigger, proves the escape hatch)
- [ ] Spike: MV3 extension that holds a device cert and answers a navigator.id request on one demo RP

**2026-08-27 (Dan):** really cool idea — would dissolve many of the scaffolding concerns. Green light to prototype if feasible; the MV3 spike (hold a device cert, answer a navigator.id request on one demo RP) is the first concrete step.

## Prototype outcome + the broker delineation (2026-08-28)

The 7oi3 prototype validated the thesis end-to-end (Dan's real primary identity, real browser, no popup). Design insight it surfaced — "the broker" is four roles in a trenchcoat:

1. **User-agent half** — dialog UI, keystore, holder cache, include.js mediation. The wallet replaces this; principle 8 says its loyalty runs to the user. PROVEN by the prototype.
2. **Fallback IdP** — issuance for secondary identities. Server-side, stays.
3. **Registry** — holders/devices, warrant consent + registry, status lists, approvals inbox. Server-side; today reachable only with a cookie session, so a native wallet is a second-class client. Fix tracked in [[bw9q]] (device-cert-authed registry lane); a self-hosted registry is the principle-7 escape hatch for the one role that currently has none — a future prototype.
4. **Hosted conveniences** — /verify, hosted wallet UI, demos.

Agreed next step for the wallet itself: single-login bootstrap ([[gxi9]]) — email-first, one login at the issuer, auth_with_presentation joins the broker silently. The double login in the prototype came from inheriting the dialog's broker-first worldview.
