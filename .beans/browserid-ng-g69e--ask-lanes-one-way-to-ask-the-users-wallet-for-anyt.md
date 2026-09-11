---
# browserid-ng-g69e
title: 'Ask lanes: one way to ask the user''s wallet for anything (JS present-ask + server out-of-band), one card, one signer'
status: completed
type: epic
priority: high
created_at: 2026-09-11T06:47:46Z
updated_at: 2026-09-11T14:22:08Z
---

Design + build epic (Dan, 2026-09-10/11). Eight flows end at a consent card or a non-login signature; all but login sign inside a broker page with a keystore key the native wallet does not have, and three of them (connection, authoring, provisioning) are server-filed then REDIRECT a present user to the card — where native-wallet users strand. Target: two lanes (present ask over navigator.id, routed to whichever wallet; out-of-band ask over the registry inbox, also the fallback for platforms without the JS API), one consent component hosted by the wallet, one signing interface answered from the keystore (web) or natively (shim → wallet). The ask vocabulary is a set of schemas kept as a side spec. Manual signing card deleted.

Full context, matrix, open questions, pointers, verification: docs/plans/2026-09-11-ask-lanes-handoff.md. Current-state diagram: https://claude.ai/code/artifact/c47a05a5-da6c-49f2-9c60-a534b1dcb9e1

Design first (fresh context), in this order:
- [x] Settle the ask vocabulary (docs/specs/request-kinds/): kinds (login, warrant, admission, signature, provision), per-kind request schema, card, artefact, result delivery — as a side spec (docs/specs/ask-vocabulary/ or similar), referenced from core §7.3 and registry-api-v1 §5.3
- [x] Spec edits (2026-09-11): core §7.3 mediator gains the ask surface; §7.5 keeps the out-of-band lane and drops 'the user, at their broker, signs'; registry respond accepts the same artefacts from either lane
- [x] Write the plan as flows first (~150 lines) for Dan's review before code (docs/plans/2026-09-11-ask-lanes-design-draft.md, reviewed 2026-09-11; fta9 filed for the shim origin bug)

Then build, in migration order:
- [x] Delete the account page's manual signing card (account.html advanced card + CSP hash) — 2026-09-11
- [x] Signing interface in both wallets (web: common/js/wallet-signer.js behind navigator.id.request(kind); native: shim → /request bridge → wallet/src/request.js) — 2026-09-11
- [x] SBO grant + SBO action onto the interface: request("warrant") / request("signature") on both wallets; /sign popup kept as a compatibility transport over the same signer — 2026-09-11
- [x] Connection + authoring admissions onto the present lane; server lane stays as fallback — 2026-09-11: registrar generic POST/GET /api/v1/requests + claim page_origin; dialog + native wallet answer request("admission", {code}); gate interstitial hands the code to the wallet (no redirect), consent_uri fallback
- [x] Provisioning approval onto the present lane — 2026-09-11 web dialog (embeds /authorize?present=1, CSP frame-ancestors self); native wallet deferred to bean 1iif (prepare/complete need the token lane)
- [x] Per-page signing consolidated: consent.html + authorize.html sign through common/js/wallet-signer.js (the one web signer, same as the dialog); the resource redirect is no longer the primary path (gate hands the code to the wallet) and consent_uri remains the deliberate no-JS fallback (Dan: server lane stays) — 2026-09-11
- [x] e2e per lane × wallet: request-kinds.spec.ts (web dialog: warrant, signature, admission, provision), wallet/e2e.mjs (native shim: login, warrant, signature, admission), connection-sharing.spec.ts (present lane + no-JS fallback with include.js blocked); native provision → bean 1iif

Related epic: 9yyk (wallets on one standardized API surface) — an epic cannot parent an epic, so linked here instead.

Design draft for review (2026-09-11): docs/plans/2026-09-11-ask-lanes-design-draft.md

## Summary of Changes

Design (2026-09-11): docs/plans/2026-09-11-ask-lanes-design-draft.md (reviewed), core §7.3/§7.5, registry §5.3, docs/specs/request-kinds/.

Built: manual signing card deleted; navigator.id.request(kind, args) promise API (include.js) with kinds login/warrant/signature/admission/provision on the web dialog; common/js/wallet-signer.js is the one web signer (dialog, /sign popup, consent.html, authorize.html); native wallet: shim → POST /request bridge → wallet/src/request.js (login/warrant/signature/admission; provision deferred to 1iif); registrar: generic POST /api/v1/requests + GET /api/v1/requests/<code>, claim page_origin (present-lane audience proof); gate interstitial hands the code to the wallet on its own origin, consent_uri fallback; /authorize framed by self for the embedded provision card. fta9 (page-claimed shim origin) fixed along the way.

Deferred: 1iif native provisioning approval; deleting the legacy /sign popup + sboSign bundle once SBO clients use request("signature"). Nothing deployed from this work yet.
