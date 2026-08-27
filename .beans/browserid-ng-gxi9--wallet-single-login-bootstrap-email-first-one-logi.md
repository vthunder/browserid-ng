---
# browserid-ng-gxi9
title: 'Wallet single-login bootstrap: email-first, one login at the issuer, auth_with_presentation joins the broker'
status: in-progress
type: feature
priority: normal
created_at: 2026-08-27T08:57:18Z
updated_at: 2026-08-27T18:48:03Z
---

Agreed redesign from the menubar-wallet prototype (7oi3): the prototype bootstraps through a broker /account session and then hops to the IdP — the user logs in twice, which inverts the wallet's loyalty order. The protocol already supports the right shape:

1. Wallet asks WHICH email first (native prompt, e.g. served from its localhost page).
2. Unauthenticated address_info → primary: ONE login at the IdP (device-authorize hop, already built); secondary: the broker IS the IdP, so the /account login is the single login.
3. With certs in hand, the wallet joins the broker registry silently via POST /wsapi/auth_with_presentation (verified against the broker's own audience; mints/links the account — built for exactly this). No second password ever.

Details to handle: holder without a prior broker session (IdP assigns; heal to the browsers prefix after the auth_with_presentation join via the existing rrve machinery), and keeping approval-watch working off the joined session.

Depends on nothing server-side; wallet-only change.

**Confirmed 2026-08-28 (code check): zero broker/IdP changes needed, no security weakening.** The primary lane never touches the broker: address_info is unauthenticated; the hosted IdP's /idp/device_cert accepts a passthrough holder or self-assigns a fresh namespace on cold login (hosted_idp.rs:386-393); the optional broker join uses the existing auth_with_presentation, which requires a full valid presentation for the broker's own audience — strictly stronger than the password lane it replaces. Holder healing after the join rides the existing rrve/i8a2 machinery. Secondary identities are unaffected (the broker is their IdP, so that login is already single).

**Venue decision (Dan, 2026-08-28):** build gxi9 as the FIRST FEATURE OF THE REAL WALLET, not further prototype iteration — production app skeleton with real .app packaging (fixes macOS 26 tray via LaunchServices properly) and Keychain/secure-enclave key custody replacing the 0600 JSON file. The prototype (proto/menubar-wallet) becomes reference material to mine, not extend. Also fold in ig9p phase 1: mint scopes [{scope: "registry"}] on broker-audience warrants from day one. See docs/plans/2026-08-28-registry-api-and-wallet-build-handoff.md.

## Progress (2026-08-27)

Built as the first feature of the real wallet (`wallet/` at repo root — the production Electron app; prototype demoted to reference). Email-FIRST bootstrap per this bean: askEmail window → unauthenticated address_info → primary lane (ONE login at the IdP device-authorize page, return_url delivery, no holder passed — IdP self-assigns, join-side healing) then silent registry-scoped auth_with_presentation join; secondary lane (broker /account login IS the single login → /device/issue). Approval-watch now rides the registry API token lane (no borrowed session — works across restarts for both identity types). E2E green: single-login secondary bootstrap, token-lane inbox, popup-free RP login, site warrants WITH allocated status refs.

Remaining before completing: human validation of the PRIMARY lane (device-authorize hop + silent join) with a real primary identity — needs Dan's machine (dev box display unobserved); prototype's hop code was mined verbatim but the email-first ordering is new.
