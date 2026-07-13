---
# browserid-ng-93z2
title: 'Origin-split spike: move key-custody/IdP surface to a separate origin — what breaks?'
status: completed
type: task
priority: high
created_at: 2026-07-13T08:26:50Z
updated_at: 2026-07-13T08:38:21Z
blocking:
    - browserid-ng-omxf
---

Spike: browserid depends on a complex set of cross-origin interactions between RPs and the broker — hidden iframes (communication_iframe, provision), first-party popups (dialog, sign), postMessage relays. Before any origin split (e.g. key-custody pages on id.browserid.me, marketing on apex; or fallback IdP on its own subdomain), we need to know how these flows react to the split.

Motivation: gating decision for auth-safe PostHog client JS (see blocked bean), and general security win (same-origin script on landing page can currently reach the keystore + CSRF token).

## Todo
- [x] Map all cross-origin interactions (see Findings)
- [x] Pick a candidate split boundary
- [x] Prototype locally (two origins) and catalog what breaks
- [x] Write up findings + recommendation

## Findings (2026-07-13)

Prototype: e2e-tests/tests/cross-origin-rp.spec.ts runs a real RP on a second origin (127.0.0.1 random port AND rp.localhost, vs broker on localhost:3000) and drives both RP-facing flows across the boundary. All 4 tests pass (documenting behavior).

**The split is viable and low-risk. The RP-facing URL derivation already supports it via one knob.**

1. **One knob controls everything RP-facing:** include.js derives ipServer from (window.BROWSERID_URL, or the data-browserid-url attr, or the include.js script origin). Every URL it opens (communication_iframe, the /sign_in dialog popup, /relay) is built off ipServer. Point RPs at id.browserid.me and the whole auth cluster follows. Demo RPs using relative include.js need updating to absolute.

2. **Popup dialog flow works cross-origin (verified).** WinChan learns the true RP origin, the assertion returns to the cross-origin RP page, and /verify accepts it for the RP audience. This is the design-intent path and is unaffected by the split.

3. **Silent assertion via communication_iframe is ALREADY BROKEN for any real (cross-origin) RP, independent of the split.** When the comm iframe is embedded under a different top-level origin it gets a partitioned third-party storage bucket and cannot see the keystore/localStorage the dialog wrote first-party, so watch() fires onlogout even when the broker session is live. Diagnostic: after cross-origin sign-in the broker's own top-level tab still shows authenticated:true (session cookie, host-only, survives) but the embedded iframe returns logout. Same-origin returns login. Same-site (rp.localhost) did NOT rescue it. Modern-browser storage partitioning, a pre-existing Persona-era reality, NOT caused by the split. Filed as browserid-ng-1sy5.

4. **The only broker-owned page that moves is the guestbook, and it is signed by agents over MCP (server-to-server, origin-agnostic), not by any browser assertion flow.** The page is read-only display. Marketing/guestbook can move to browserid.me with zero auth impact.

5. **Cookies (browserid_session, fb_email) are host-only (no Domain=)** and do not/must not span the split. Safe as long as the entire cookie/keystore/dialog/wsapi/provision/auth/sign/consent/account cluster stays on ONE origin (id.browserid.me). Do not split any /wsapi, /auth, or /provision route off that origin.

**Recommended cut line:** Cluster A (id.browserid.me): dialog, /sign_in, /relay, /communication_iframe, /sign, /provision, /auth, /account, /consent, /agents, all /wsapi, /cert_key, keystore. Cluster B (browserid.me): /, /guestbook, demos as plain RPs pointing include.js at Cluster A. Agent/MCP flows unaffected (credential-named base URLs).

**Net for PostHog (browserid-ng-omxf):** after this split the marketing origin carries NO keystore/cookies/wsapi, so locked-down client-side posthog-js there is genuinely contained; the auth origin keeps connect-src self and no analytics JS. The split unblocks the hybrid analytics plan.

**Code changes the real split needs (small):** (a) demo RPs absolute include.js URL / BROWSERID_URL; (b) deploy id + apex as two origins (dokku already multi-app); (c) decide guestbook audience origin (guestbook_audience derives from state.domain); (d) CSP tightening on the auth origin. No changes to the dialog/keystore/WinChan machinery itself.

## Summary of Changes

Spike complete. Built a cross-origin RP harness (e2e-tests/tests/cross-origin-rp.spec.ts) proving the origin split is viable: the popup dialog flow works cross-origin and verifies; the split only requires pointing RP include.js at the auth origin plus small deploy/config changes; no changes to the dialog/keystore/WinChan internals. Surfaced a pre-existing, split-independent limitation (silent assertion dead for cross-origin RPs due to third-party storage partitioning) filed as browserid-ng-1sy5. Unblocks the PostHog hybrid plan (browserid-ng-omxf).
