---
# browserid-ng-qze7
title: 'Ceremony page: accept only loopback, custom-scheme, or issuer-trusted web return origins'
status: todo
type: feature
priority: high
created_at: 2026-09-07T20:45:39Z
updated_at: 2026-09-07T20:45:59Z
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

- [ ] Broker config: `TRUSTED_WALLET_ORIGINS` (default own origin + browserid.me); hosted-primary tenants inherit it
- [ ] Server-side enforcement on the device-cert issuance endpoint(s) the pages call (`/idp/device_cert`, broker lane): page passes `return_origin`, endpoint refuses outside the set
- [ ] Page-side check in both `idp-device-authorize.js` and `fb-device-authorize.js`: replace the any-http(s) rule; render `return_origin_not_allowed` in-page
- [ ] Advertise `wallet-origins` in `/.well-known/browserid`
- [ ] Wallets (menubar prototype, `wallet/src/bootstrap.js`): confirm they use loopback or a custom scheme, not an http(s) page origin
- [ ] Tests: evil-origin refused server-side and page-side; loopback + custom scheme accepted; e2e for the dialog still passing (CI does not run e2e; run locally)
- [ ] CSP inline-script hashes if any inline script changes

## Related

- i63t (structural fix, stays open), 9it0 (return_url same-origin, already done in the pages), 0c49 registry guard.
