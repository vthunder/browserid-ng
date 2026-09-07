---
# browserid-ng-qze7
title: 'Ceremony page: accept only loopback, custom-scheme, or issuer-trusted web return origins'
status: completed
type: feature
priority: high
created_at: 2026-09-07T20:45:39Z
updated_at: 2026-09-07T21:13:55Z
blocking:
    - browserid-ng-0c49
---

Decided 2026-09-07 while discussing i63t. Spec text landed in fallback-idp-api-v1 §2 (`wallet-origins`), §3.1, §6 (`return_origin_not_allowed`), §7 decision 8.

## Why

The ceremony page authenticates the user, never the wallet. Any web page can open it with its own keys and `return_origin=https://evil.com`, and today both `idp-device-authorize.js` and `fb-device-authorize.js` accept any well-formed http(s) origin. The user signs in, the page posts a victim-identity config cert to evil.com. This is the drive-by case of i63t and closes here; local attackers and consent phishing stay on i63t.

## Rule

- Loopback (`127.0.0.1`, `[::1]`, `localhost`, any port) and any non-http(s) custom scheme: always accepted.
- http(s): only if on the issuer's configured trusted-wallet list. Reference broker default: `https://browserid.me` plus its own origin. Off-spec recommendation for other deployments, not a MUST.
- Otherwise: `return_origin_not_allowed`, shown in the page (no accepted origin to deliver to).

## Todo

- [x] Broker config: `TRUSTED_WALLET_ORIGINS` (default own origin + browserid.me); hosted-primary tenants inherit it
- [x] Server-side enforcement on the device-cert issuance endpoint(s) the pages call (`/idp/device_cert`, broker lane): page passes `return_origin`, endpoint refuses outside the set
- [x] Page-side check in both `idp-device-authorize.js` and `fb-device-authorize.js`: replace the any-http(s) rule; render `return_origin_not_allowed` in-page
- [x] Advertise `wallet-origins` in `/.well-known/browserid`
- [x] Wallets — no change needed; both pass the issuer OWN origin as return_origin with a never-loaded issuer return_url they intercept in their webview, which is always accepted and safe (only the context owning the webview sees that navigation). (menubar prototype, `wallet/src/bootstrap.js`): confirm they use loopback or a custom scheme, not an http(s) page origin
- [x] Tests: evil-origin refused server-side and page-side; loopback + custom scheme accepted; e2e for the dialog still passing (CI does not run e2e; run locally)
- [x] CSP inline-script hashes: n/a, both pages use external scripts only

## Related

- i63t (structural fix, stays open), 9it0 (return_url same-origin, already done in the pages), 0c49 registry guard.

## Summary of Changes

- `browserid-broker/src/return_origin.rs`: the classifier (loopback / custom scheme always; http(s) only own host or configured list) and `TRUSTED_WALLET_ORIGINS` env parsing (default `https://browserid.me`; empty string = trust none).
- `AppState.trusted_wallet_origins`, `return_origin_accepted()`, `wallet_origins()`; wired in main.rs.
- `/device/issue` and `/idp/device_cert` take an optional `return_origin`; refused with 403 `return_origin_not_allowed` when present and not accepted. Absent = the issuer's own dialog (same-origin, CSRF-bound).
- Both support documents advertise `wallet-origins` (core `SupportDocument.wallet_origins`).
- Both ceremony pages: client-side classifier, `wallet-origins` check BEFORE the sign-in form (refusal shown in-page, no delivery lane), `return_origin` passed to issuance, custom-scheme origins use the return_url lane only.
- Tests: unit (classifier), broker integration (both endpoints + both support docs), e2e (refusal + loopback/custom-scheme acceptance on both pages). Full workspace and 121 e2e green.

Residual (stays on i63t): a local attacker squatting loopback or a custom scheme; consent phishing through a trusted wallet.
