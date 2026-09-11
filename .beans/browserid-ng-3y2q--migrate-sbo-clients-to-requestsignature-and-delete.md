---
# browserid-ng-3y2q
title: Migrate SBO clients to request("signature") and delete the /sign popup + sboSign login bundle
status: todo
type: task
created_at: 2026-09-11T14:25:08Z
updated_at: 2026-09-11T14:25:08Z
---

The legacy /sign signer popup (common/js/sbo-signer.js, sign.html) and the sboSign option bundled into login are compatibility transports over common/js/wallet-signer.js. Move SBO clients (sbo-smoke-test.html, scripts/e2e/signer-device-test.mjs, mingo, any external RP) to navigator.id.request("warrant") + request("signature"), then delete sign.html, sbo-signer.js, the sboSign normalize/consent bundle in dialog.js, the /sign route + CSP tier, and sbo-signing-grants.spec.ts (request-kinds.spec.ts covers the same claims). Related: g69e.
