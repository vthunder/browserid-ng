---
# browserid-ng-u6jq
title: Wallet lane drops the RP's acceptedFallbacks (§8.1) — forward extension → wallet
status: completed
type: bug
priority: normal
created_at: 2026-08-28T19:35:34Z
updated_at: 2026-08-28T22:30:46Z
parent: browserid-ng-9yyk
---

Core §8.1 lets the RP name the fallback IdPs it accepts; include.js forwards options.acceptedFallbacks to the dialog (include.js:656) and the verifier enforces it (verify.rs:632). The native wallet lane loses it: the extension's login request to the wallet's localhost bridge does not carry acceptedFallbacks, so the wallet cannot warn when its identity's fallback issuer will be rejected at verify, nor prefer an acceptable identity. Forward it through the shim → extension → /login request, and have the wallet surface a mismatch in the confirm dialog. Found during d0xb review 2026-08-28.

## Summary of Changes

navigator.id.request(opts).acceptedFallbacks now flows shim.js → background.js → localhost /login → wallet login(). When the wallet's identity is fallback-issued (issuer != email domain) and the issuer is not in the RP's set, approveLogin shows a warning-styled dialog (Cancel default) naming the issuer. No warning when the RP sends no list (default = any) or the identity is primary.
