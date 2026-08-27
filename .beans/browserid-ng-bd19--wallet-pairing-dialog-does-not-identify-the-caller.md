---
# browserid-ng-bd19
title: Wallet pairing dialog does not identify the caller (confused-deputy pairing)
status: completed
type: bug
priority: normal
created_at: 2026-08-27T19:28:40Z
updated_at: 2026-08-27T19:34:10Z
---

The wallet's /pair native dialog says only "Sign in to *a browser extension (pairing request)*?" — it does not identify WHICH local process/origin is pairing. A hostile local process (or, until b8q0 lands, any web page) produces the same generic prompt as the legitimate extension, so the human can't distinguish a confused-deputy pairing from the real one. Pairing is the trust-establishing step, and right now it's approved blind.

## Options
- Show the requesting origin / caller in the pairing dialog (the extension's chrome-extension:// origin arrives on the request once b8q0 tightens CORS).
- Bind the issued token to the extension id, so a token minted for one caller can't be used by another.
- Consider moving off the single-shared-token model (see the per-caller-token bean).

## Context
wallet/src/server.js /pair handler. Flagged during gxi9 wallet review 2026-08-27. Related: b8q0 (wildcard CORS), and the per-login-confirm and token-model beans.

## Summary of Changes

The pairing dialog now identifies the caller: a dedicated approvePair dialog
(wallet/src/main.js) names the requesting origin — "a browser extension
(chrome-extension://…)" from the browser-attached Origin header, or "a local
process on this machine (no browser origin)" — and defaults to Cancel, since
pairing is the trust-establishing step. The issued token is bound to the
origin it was paired under (store.pairOrigin): presenting a valid token from
any other origin is refused 401. e2e covers the binding (token paired
origin-less is refused when replayed under an extension origin). Moving off
the single-shared-token model remains tracked on browserid-ng-2m7y.
