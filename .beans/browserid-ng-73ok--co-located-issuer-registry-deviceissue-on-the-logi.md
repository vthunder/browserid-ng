---
# browserid-ng-73ok
title: 'Co-located issuer + registry: /device/issue on the login key, ceremony page returns a login token, one ceremony on a new device'
status: todo
type: feature
priority: high
created_at: 2026-09-15T00:12:21Z
updated_at: 2026-09-15T00:12:21Z
parent: browserid-ng-0vdu
blocked_by:
    - browserid-ng-noqd
---

fallback-idp-api-v1 §3: an issuer that is also the wallet's registry accepts the registry Proof header on its issuance endpoint for broker-vouched identities (SMTP, agent) — never bridged (live bridge proof always) or primary; ceremony page MAY append login=<token> when the proof it took meets the enrol rule; wallet detects co-location from discovery (same origin). authorize_mint gains the device input (login-key record + policy mint rule). Wallet: bootstrap uses the token, renew on the login key. Dialog: same. Removes the double password prompt on a new native device. Tests: mint_chokepoint_test, fallback-device-authorize e2e, wallet e2e.
