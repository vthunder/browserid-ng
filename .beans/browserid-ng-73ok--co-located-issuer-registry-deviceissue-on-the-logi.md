---
# browserid-ng-73ok
title: 'Co-located issuer + registry: /device/issue on the login key, ceremony page returns a login token, one ceremony on a new device'
status: completed
type: feature
priority: high
created_at: 2026-09-15T00:12:21Z
updated_at: 2026-09-15T01:05:40Z
parent: browserid-ng-0vdu
blocked_by:
    - browserid-ng-noqd
---

fallback-idp-api-v1 §3: an issuer that is also the wallet's registry accepts the registry Proof header on its issuance endpoint for broker-vouched identities (SMTP, agent) — never bridged (live bridge proof always) or primary; ceremony page MAY append login=<token> when the proof it took meets the enrol rule; wallet detects co-location from discovery (same origin). authorize_mint gains the device input (login-key record + policy mint rule). Wallet: bootstrap uses the token, renew on the login key. Dialog: same. Removes the double password prompt on a new native device. Tests: mint_chokepoint_test, fallback-device-authorize e2e, wallet e2e.

## Summary of Changes

Shipped and deployed 2026-09-15 (commit 924b106). fallback-idp-api-v1 §3.3: /device/issue takes the registry session form (login key) for broker-vouched identities under the account's mint rule; the cookie form returns a login token (want_login) when the session's proof meets the enrol rule; ceremony page, dialog, and native wallet spend it; the wallet renews its pair on the login key. Tests: registry_api_test (key-form issuance, mint rule, bridged refusal, ceremony token), mint unit test, fallback-device-authorize e2e asserts login=, wallet e2e (loginVia=ceremony, reissue). Playwright 128 passed.
