---
# browserid-ng-e2fi
title: Implement non-extractable key custody (agent private keys are extractable in localStorage)
status: completed
type: feature
priority: high
created_at: 2026-07-08T06:13:39Z
updated_at: 2026-07-11T22:57:44Z
parent: browserid-ng-8u60
---

The typed-signing design specifies a non-extractable CryptoKey in IndexedDB as the XSS mitigation, and says the extension 'assumes it'. Reality: identity private key is an extractable JWK in localStorage (priv.d); sbo-sign.js:118 comment overstates it. Affects assertions AND SBO (same key). Broker-origin XSS exfiltrates every key.
- [x] Generate keys extractable:false; persist CryptoKey handles via IndexedDB
- [x] Migrate existing stored keys / handle upgrade
- [x] Update design doc + sbo-sign.js:118 comment to match reality
- [x] Applies to both assertion and SBO signing paths

## Summary of Changes

Added common/js/keystore.js — a shared IndexedDB store (window.Keystore) holding non-extractable Ed25519 CryptoKey handles keyed by issuer+email. Migrated every identity-key signing path to it: the login dialog (assertions), the consent page and /account (agent warrants), and the SBO signer popup (typed signing). sbo-sign.js signEnvelope now signs with a CryptoKey handle directly; raw private bytes never enter JS. A one-time migrateFromLocalStorage() imports legacy emails JWKs as non-extractable keys then wipes the plaintext blob. Provisioning keys stay extractable (exported to agents). Coverage: 3 browser round-trip tests (keystore.spec.ts) + full 89-test e2e green. Deployed to browserid.me and live-verified. Design doc (2026-06-24-typed-signing-extension-design.md) updated to reflect implementation. Known residual: legacy communication_iframe SBO binding (start.js) left on the old path — not the live channel, unreachable under storage partitioning.
