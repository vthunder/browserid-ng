---
# browserid-ng-pn5n
title: 'Design: in-place identity activation from /account (return path)'
status: draft
type: feature
created_at: 2026-07-10T21:25:19Z
updated_at: 2026-07-10T21:25:19Z
---

Deferred design (vthunder, 2026-07-10) — folds together the /account "Activate" UX with the standalone-login-page idea. Not urgent.

## Problem
Activating a **primary** identity (e.g. dan@mingo.place) from /account needs a fresh cert cached at **browserid.me origin**. The IdP /auth page is a dialog shim (hangs standalone). The real gap: no standalone (non-dialog) way to provision + return a cert to the calling origin.

## Return-path options
- **A. /account as a full RP (winchan):** load include.js, navigator.id.request({provisionEmail}); dialog provisions + caches at browserid.me; returns assertion via the normal RP callback; /account re-scans localStorage. Reuses everything, no dialog changes; but makes browserid.me an RP of its own broker + popup fragility.
- **B. Standalone provision mode in the dialog (return_to param):** new dialog.js branch — skip the RP/winchan handshake, provision provision_email, cache, same-origin redirect back to return_to. Cleanest for our case; doubles as the standalone login page (hosted at browserid.me so cert-origin is right). New dialog code; must drive primary provisioning outside the RP handshake.
- **C. Full protocol feature (`login` support-doc field):** pointer + pubkey-in/cert-out/return-to-origin contract, IdP-hosted. General (any RP/CLI/offline), most work, cross-origin cert handling.

## Load-bearing unknown
Does the dialog's primary + **parent-chain** provisioning (dan@mingo.place → danmills@sandmill.org) run correctly *outside* the RP handshake? Primary-provisioning iframe uses its own navigator.id provisioning API (maybe survives standalone); parent substitution + whether sandmill.org serves a working provisioning page are open. Secondary identities: B is trivially clean.

## Next step
Spike B on a secondary first (guaranteed), then try dan@mingo.place to see how far the primary/parent chain gets standalone → decide if B covers primaries or C is needed for them. Open question: is full auto-activation worth it for parent-chained identities, or is "take you to the app sign-in (which handles the chain)" the right ceiling, reserving B/C for single-hop identities?
