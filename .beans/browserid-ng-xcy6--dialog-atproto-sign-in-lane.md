---
# browserid-ng-xcy6
title: 'Dialog: claim-and-return plumbing + discovery copy (no atproto UI)'
status: completed
type: feature
priority: normal
created_at: 2026-07-30T20:35:08Z
updated_at: 2026-07-30T22:54:02Z
parent: browserid-ng-tsqk
blocked_by:
    - browserid-ng-5kf3
---

A handle identity is just an address typed into the ordinary email field. No "Sign in with Bluesky" button, no handle input, no new screen.

What does NOT work: presenting the handle domain as a primary with device_auth pointing at the bridge so the existing primary lane runs verbatim. It breaks on the issuer rule twice — finishPrimaryCerts rejects certs unless dc.iss === domain, and resolve_conformant_key requires an accepted fallback for a no-primary domain — and the design rests on iss=browserid.me.

What is actually needed is small: once the identity is verified on the session, completeSignIn -> issueDevicePair -> /device/issue runs UNCHANGED. Only getting the identity onto the session is new — one navigation out and one return, same shape as clicking a link in a verification email.

- [x] On proof=atproto, handleAtprotoClaim runs the bridge claim hop: claimPopupFlow (postMessage + BroadcastChannel handback for the COOP-severed return leg, pending announcement, tap-to-continue on popup block) or claimRedirectHop (Keystore pending record, kind handle_claim) + resumeHandleClaim at ?resume=handle_claim. Redeems via /wsapi/complete_handle_claim then completeSignIn — issueDevicePair//device/issue unchanged
- [x] Email-screen hint added under the input: Bluesky user? Try me@your.handle
- [x] Bare handle-shaped input offers a one-tap "Did you mean me@<handle>?" (input switched to type=text inputmode=email so the browser's native validation doesn't eat it first)
- [x] Add-email wired in BOTH places: the dialog's add-email screen routes proof=atproto to the claim hop, and /account's add-address rail got openHandleClaim (same popup + BroadcastChannel handback; complete_handle_claim lands on the signed-in session). account.html is inline-script — INLINE_SCRIPT_HASHES updated
- [x] Error copy: claim page passes through the bridge's resolution errors ("X does not resolve to an atproto account — check the handle…"); dialog shows "Bluesky verification failed: <reason>"; unprovable domains (proof=none) get "can't receive email and isn't a Bluesky handle" before any create screen

## Summary of Changes

- dialog.js: claim-flow block (claimPopupFlow / claimRedirectHop / redeemHandleAttestation / handleAtprotoClaim / handoffClaimResume / resumeHandleClaim) mirroring the device_auth machinery but simpler — no keys cross the hop, only the short-lived attestation. Wired into: email submit, handleEmailChosen (chooser), add-email screen, boot dispatch (?resume=handle_claim), tap-to-continue screen.
- dialog.html: claim-continue screen, email-input hint, input type=text inputmode=email.
- account.html: openHandleClaim on the add-address rail; CSP hash updated in routes/mod.rs.
- e2e: full suite green twice (77 passed / 0 failed) against a warm broker with the hierarchy live — no regressions from the input-type change or the new branches.

NOT yet covered: e2e specs for the atproto lane itself (needs a mock bridge + static authority probes via test endpoints) and a live end-to-end claim with a real handle — follow-up bean.
