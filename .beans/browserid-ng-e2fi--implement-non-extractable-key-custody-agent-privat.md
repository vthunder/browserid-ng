---
# browserid-ng-e2fi
title: Implement non-extractable key custody (agent private keys are extractable in localStorage)
status: todo
type: feature
priority: high
created_at: 2026-07-08T06:13:39Z
updated_at: 2026-07-08T06:13:39Z
parent: browserid-ng-8u60
---

The typed-signing design specifies a non-extractable CryptoKey in IndexedDB as the XSS mitigation, and says the extension 'assumes it'. Reality: identity private key is an extractable JWK in localStorage (priv.d); sbo-sign.js:118 comment overstates it. Affects assertions AND SBO (same key). Broker-origin XSS exfiltrates every key.
- [ ] Generate keys extractable:false; persist CryptoKey handles via IndexedDB
- [ ] Migrate existing stored keys / handle upgrade
- [ ] Update design doc + sbo-sign.js:118 comment to match reality
- [ ] Applies to both assertion and SBO signing paths
