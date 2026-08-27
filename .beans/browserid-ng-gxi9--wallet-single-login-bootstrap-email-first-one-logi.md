---
# browserid-ng-gxi9
title: 'Wallet single-login bootstrap: email-first, one login at the issuer, auth_with_presentation joins the broker'
status: todo
type: feature
created_at: 2026-08-27T08:57:18Z
updated_at: 2026-08-27T08:57:18Z
---

Agreed redesign from the menubar-wallet prototype (7oi3): the prototype bootstraps through a broker /account session and then hops to the IdP — the user logs in twice, which inverts the wallet's loyalty order. The protocol already supports the right shape:

1. Wallet asks WHICH email first (native prompt, e.g. served from its localhost page).
2. Unauthenticated address_info → primary: ONE login at the IdP (device-authorize hop, already built); secondary: the broker IS the IdP, so the /account login is the single login.
3. With certs in hand, the wallet joins the broker registry silently via POST /wsapi/auth_with_presentation (verified against the broker's own audience; mints/links the account — built for exactly this). No second password ever.

Details to handle: holder without a prior broker session (IdP assigns; heal to the browsers prefix after the auth_with_presentation join via the existing rrve machinery), and keeping approval-watch working off the joined session.

Depends on nothing server-side; wallet-only change.
