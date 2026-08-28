---
# browserid-ng-9it0
title: 'SECURITY: device-authorize page delivers certs to an unvalidated return_url'
status: todo
type: bug
priority: high
created_at: 2026-08-28T20:05:50Z
updated_at: 2026-08-28T21:18:17Z
parent: browserid-ng-9yyk
---

Found in d0xb adversarial review (2026-08-28). browserid-broker/static/common/js/idp-device-authorize.js validates return_origin for the postMessage lane (targetOrigin line 43; ev.origin check line 103) but the return_url delivery lane (lines 49-52, 87-90) does location.replace(returnUrl + '#device_cert=…&config_cert=…') with NO check that return_url is same-origin with return_origin. Certs certify the FRAGMENT's pubkeys, so an attacker web page can window.open this page with attacker-held pubkeys + an attacker return_url, phish a victim through the legitimate first-party sign-in, and receive a valid config cert for the victim's identity bound to the attacker's warrant-signing key = config-cert takeover. Affects the CURRENT primary/hosted-IdP flow, not just the proposed fallback lane. Fix: return_url MUST be same-origin with return_origin (and return_origin validated); reject otherwise before any location.replace.
