---
# browserid-ng-v2nb
title: Dialog chooser is empty without a broker session even when this browser holds cached identities
status: todo
type: bug
priority: normal
created_at: 2026-08-19T17:26:21Z
updated_at: 2026-08-19T18:34:23Z
---

Owner's confusing test (2026-08-19, right after the shyj rollout):
- Signed into mingo.place by typing vthunder@gmail.com → instant success (cached device pair: completeSignIn → storedDevicePair → /access/mint, which is deliberately sessionless — the cert is the credential; no Google hop, no password, no broker session created).
- Signed out of mingo, signed back in → dialog showed the cold type-your-email screen, not the account's email picker.
- browserid.me/account showed the login screen.

Why: the picker is fed by /wsapi/list_emails, which needs a broker session — and every pre-existing session was deliberately wiped by the ca29 rollout (migration v30 forces re-auth). Cert-based RP sign-in never re-establishes a broker session. So the browser "remembers" the user well enough to silently sign them into RPs, but not enough to show the picker. Consistent with the device-cert model, but reads as broken.

Fix: when session_context says unauthenticated, populate the chooser from the LOCAL keystore's cached device pairs (the browser knows exactly which identities it holds certs for) — selecting one runs completeSignIn as usual (sessionless), and an 'add another' path runs the normal cold flows. Possibly label them ("remembered on this browser"). Do NOT auto-create broker sessions from certs — the sessionless property is deliberate (a broker session grants /wsapi account surface; a cert only grants RP sign-in for its address).

Also note: because the cached pair short-circuits issuance, such users never hit the new bridge-first/E2-upgrade flow (kts0) until their cached certs expire or are revoked.

## Owner design decision (2026-08-19) — SUPERSEDES the fix sketch above

The dialog must be session-first; local certs are an issuance shortcut, never a sign-in credential:

1. **No broker session → the local cert store is not consulted at all.** Signing into an RP through the dialog always requires a live broker session; a cached device pair may short-circuit /device/issue only AFTER the session exists.
2. **Explicit broker sign-out clears the local cert store.** (Open question: also revoke those certs server-side — right thing on shared machines; the /account device list machinery exists.)
3. **Expired session (no explicit sign-out): show a remembered-email chooser from a LOCAL CACHE of the account's email list** — cached at every authenticated dialog boot, independent of which addresses have certs. Choosing one runs the appropriate re-auth for its provenance (primary hop / bridge claim / password) to restore the session, then sign-in proceeds normally.

Implementation notes:
- completeSignIn: check session_context.authenticated before storedDevicePair; unauthenticated → route into the provenance re-auth for the chosen email (handleEmailChosen already branches correctly per address_info).
- Local email-list cache on the broker origin (localStorage alongside siteInfo); refresh on authenticated boot; clear on explicit sign-out.
- Clear keystore device pairs on /account signout and any dialog-level broker logout. RP-level logout (include.js) must NOT clear broker state.
- /access/mint stays sessionless SERVER-side — headless agents depend on it; this is interactive-dialog client policy. (The cert remains valid credential material at RPs; the dialog just refuses to wield it without a session.)
- Side benefit: closes the gap where a stolen browser profile could sign into RPs with zero session-level checks, which quietly bypassed the shyj session-level machinery.
- Effect: interactive users re-auth at most every 30d (session TTL), via their provenance-appropriate ceremony (E2 = possibly silent bridge hop).
