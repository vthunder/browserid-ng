---
# browserid-ng-0zj6
title: Same-tab redirect fallback for the login dialog (Arc / popup-blocked browsers)
status: todo
type: feature
priority: normal
created_at: 2026-07-19T15:21:34Z
updated_at: 2026-08-26T23:08:09Z
parent: browserid-ng-oup3
---

Full-page redirect alternative to the WinChan popup, auto-engaged when the popup fails. Design scoped 2026-07-19 (see bean body).

## Design
- RP leg (include.js): try popup first; if window.open returns null OR the dialog's WinChan 'ready' ping doesn't arrive within ~4s (Arc's detached-popup case), stash {returnTo: location.href, state: nonce, options} in RP sessionStorage and navigate the tab to /dialog/dialog.html?rp_origin=&return_to=&state=&params=<b64 options>. On RP page load, consume #browserid=<b64 {presentation,email,sbo_sign_granted,state}> fragment: verify state nonce, strip via replaceState, buffer until watch() registers, deliver via observers.login. mingo's silentLogin already handles exactly this delivery shape.
- Dialog leg: redirect entry mode (validate return_to.origin === rp_origin — the anti-exfiltration control postMessage targetOrigin gave us for free); sendResponse/sendCancel navigate back with the fragment. Fallback-SMTP path needs zero changes (same-origin screens). PRIMARY path becomes a same-tab hop: stash keypairs in the keystore 'pending' IndexedDB store (already exists, structured-clones non-extractable CryptoKeys — built for mingo-ytrs), navigate to the IdP's device-authorize page with return_url, resume at dialog.html?resume=device_auth#device_cert=..&config_cert=..&state=..
- device-authorize pages (sandmill blade + mingo static): add return_url redirect mode alongside postMessage (~20 lines each; both already sessionStorage their params across the login round-trip).
- Remove the vestigial classic needsPopupFix/doPopupFix (commChan redirect_flow) — superseded; Chrome-iOS rides the new fallback.
- Promise wrapper caveat: browserid.login() can't resolve across a navigation — redirect-mode RPs must use watch() (mingo does); document it.

## Security controls
- return_to origin MUST equal rp_origin (presentation would otherwise be exfiltratable to an attacker return_to while audience-bound to the victim RP).
- state nonce binds return to the initiating tab (login-CSRF guard: prevents injecting an attacker's presentation return into a victim tab).
- Fragments stripped immediately (history.replaceState) at both resume and return; presentation stays audience-bound + 5-min assertion.
- Certs in fragments are public objects; private keys never navigate (IndexedDB pending store).

## Order + estimate (~1 day incl. deploys)
- [x] 1. Redirect entry + fragment return + include.js auto-fallback (4s ready watchdog + popup-blocked branch + explicit request({redirect:true})); browserid.login() removed, rp-quickstart on watch()
- [x] 2. Primary same-tab hop: keystore pending store carries the CryptoKeys across navigation; ?resume=device_auth; return_url mode on sandmill blade + mingo static pages
- [x] 3. e2e green: full redirect create-account round trip (verified okay, fragment stripped) + mock-primary same-tab hop (device-authorize -> issue -> resume -> cross-origin mint w/ preflight -> presentation delivered). Popup mode + 29 broker suites unaffected
- [ ] 4. Arc manual validation (Dan)

## Decision (Dan, 2026-07-19): remove browserid.login() entirely — watch()/request() is the only RP API (a .login() promise cannot survive the redirect navigation; the user would land back logged-out).

**Audit note 2026-08-27:** all engineering done and e2e-tested (b2e4f82 redirect fallback in include.js/dialog.js; 2a6e9ac made redirect the default on mobile; 12 passing e2e tests). Only step 4 — Arc manual validation by Dan — remains unconfirmed, so moved back to todo pending that check. Circumstantial evidence it works: Arc on macOS holds the canonical browser holder in prod (i8a2).
