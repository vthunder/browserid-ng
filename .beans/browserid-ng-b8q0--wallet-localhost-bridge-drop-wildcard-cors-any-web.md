---
# browserid-ng-b8q0
title: 'Wallet localhost bridge: drop wildcard CORS (any website can reach 127.0.0.1:8873)'
status: completed
type: bug
priority: high
created_at: 2026-08-27T19:28:11Z
updated_at: 2026-08-27T19:34:06Z
---

The native wallet's localhost bridge (wallet/src/server.js) sets `Access-Control-Allow-Origin: *` (plus an OPTIONS preflight that echoes `x-wallet-token`). It's there so the MV3 extension's service worker can call in, but it also makes the bridge reachable from ANY website the user visits: a random page can fetch 127.0.0.1:8873, trigger the /pair native dialog, and — if approved — drive /login. The bridge should only answer the extension.

## Fix
- Mirror only `chrome-extension://<extension-id>` as the allowed origin (and `http://127.0.0.1`/localhost for the e2e harness); reject everything else. Reflect-and-allowlist, not `*`.
- Extend wallet/e2e.mjs to prove a cross-origin web page is now refused (the current e2e only exercises the extension path).

## Context
Blast radius if a caller gets through the two native gates (pair + per-login confirm): a full login presentation for any audience as the user's identity (login-scoped). Flagged during gxi9 wallet review 2026-08-27; the prototype README already noted the bridge is un-hardened. Sibling hardening beans: caller identification on pairing, richer per-login confirm, per-caller token model.

## Summary of Changes

wallet/src/server.js: wildcard CORS is gone. Browser callers are gated by an
origin allowlist (`chrome-extension://<32-char-id>` + loopback http origins
for the e2e harness); any other Origin is 403'd *before* the pairing dialog
can fire, and CORS headers reflect the specific allowed caller (with
`vary: origin`) — never `*`. Requests with no Origin (native local
processes) pass the CORS gate — CORS can't constrain them — and are handled
by the named-caller dialogs (bd19/dgsg).

wallet/e2e.mjs: new hostile-caller checks — spoofed web-origin /pair and
token use are 403'd, refusal provably happens before pairing (token not
rotated under WALLET_AUTO_APPROVE), a real cross-origin page in Chromium
cannot reach the bridge, and ACAO reflects the caller rather than `*`.
Full suite green against a local broker.
