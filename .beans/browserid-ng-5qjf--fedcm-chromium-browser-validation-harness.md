---
# browserid-ng-5qjf
title: FedCM Chromium browser-validation harness
status: todo
type: task
priority: normal
created_at: 2026-07-13T17:34:30Z
updated_at: 2026-07-13T17:34:30Z
blocked_by:
    - browserid-ng-mhyp
---

Browser-validation phase of the FedCM spike ([[fedcm-idp-support-spike]] / browserid-ng-mhyp). The server-side IdP is built + proven at the crypto/format level (token verifies unchanged, security gate in place); this bean covers what only a real Chromium session can validate.

## Goal
Stand up an HTTPS FedCM IdP (browserid.me) + a cross-origin RP in Chromium and drive the full flow, confirming the pieces a Rust test can't:
- The native account chooser actually renders (browserid.me branding, the fallback email).
- The credentialed `/fedcm/accounts` fetch carries the `SameSite=None` FedCM cookie cross-site and returns the account.
- `/fedcm/assertion` CORS (echo Origin + allow-credentials) is accepted by the browser and the token is returned to the RP.
- The token round-trips through `/verify` with `accepted_fallbacks`.

## Tasks
- [ ] Playwright harness: broker (FedCM IdP) + a second-origin RP page calling `navigator.credentials.get({identity:{providers:[{configURL, clientId:<rp-origin>, nonce}]}})`. (Chromium; FedCM needs a secure context — localhost qualifies.)
- [ ] Prototype the `include.js` feature-detect → FedCM → popup-fallback branch (not touching the shipped shim until validated).
- [ ] Add `Set-Login: logged-in/out` on session establish/logout; confirm auto-reauthn (zero-click return) works.
- [ ] Passkey-account filtering in `/fedcm/accounts` (once [[passkey-graduation-for-fallback-identities]] exists; for now all Secondary emails are returned).
- [ ] Measure UX: clicks for first sign-in vs return vs the popup; screenshot the native chooser.
- [ ] Verify the security gate holds in-browser: a cross-origin `fetch()` to `/fedcm/assertion` (no Sec-Fetch-Dest) is rejected.

## Notes
- The spike branch is deployed to production so live manual tests can run against real browsers before building this automated harness.
- FedCM is Chromium-only; the harness is Chromium-only by nature. The popup remains the cross-browser path.
