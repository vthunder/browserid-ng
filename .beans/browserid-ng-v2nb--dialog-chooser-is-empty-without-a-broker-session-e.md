---
# browserid-ng-v2nb
title: Dialog chooser is empty without a broker session even when this browser holds cached identities
status: todo
type: bug
created_at: 2026-08-19T17:26:21Z
updated_at: 2026-08-19T17:26:21Z
---

Owner's confusing test (2026-08-19, right after the shyj rollout):
- Signed into mingo.place by typing vthunder@gmail.com → instant success (cached device pair: completeSignIn → storedDevicePair → /access/mint, which is deliberately sessionless — the cert is the credential; no Google hop, no password, no broker session created).
- Signed out of mingo, signed back in → dialog showed the cold type-your-email screen, not the account's email picker.
- browserid.me/account showed the login screen.

Why: the picker is fed by /wsapi/list_emails, which needs a broker session — and every pre-existing session was deliberately wiped by the ca29 rollout (migration v30 forces re-auth). Cert-based RP sign-in never re-establishes a broker session. So the browser "remembers" the user well enough to silently sign them into RPs, but not enough to show the picker. Consistent with the device-cert model, but reads as broken.

Fix: when session_context says unauthenticated, populate the chooser from the LOCAL keystore's cached device pairs (the browser knows exactly which identities it holds certs for) — selecting one runs completeSignIn as usual (sessionless), and an 'add another' path runs the normal cold flows. Possibly label them ("remembered on this browser"). Do NOT auto-create broker sessions from certs — the sessionless property is deliberate (a broker session grants /wsapi account surface; a cert only grants RP sign-in for its address).

Also note: because the cached pair short-circuits issuance, such users never hit the new bridge-first/E2-upgrade flow (kts0) until their cached certs expire or are revoked.
