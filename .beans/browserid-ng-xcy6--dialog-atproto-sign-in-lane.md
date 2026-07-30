---
# browserid-ng-xcy6
title: 'Dialog: claim-and-return plumbing + discovery copy (no atproto UI)'
status: todo
type: feature
priority: normal
created_at: 2026-07-30T20:35:08Z
updated_at: 2026-07-30T20:46:55Z
parent: browserid-ng-tsqk
blocked_by:
    - browserid-ng-5kf3
---

A handle identity is just an address typed into the ordinary email field. No "Sign in with Bluesky" button, no handle input, no new screen.

What does NOT work: presenting the handle domain as a primary with device_auth pointing at the bridge so the existing primary lane runs verbatim. It breaks on the issuer rule twice — finishPrimaryCerts rejects certs unless dc.iss === domain, and resolve_conformant_key requires an accepted fallback for a no-primary domain — and the design rests on iss=browserid.me.

What is actually needed is small: once the identity is verified on the session, completeSignIn -> issueDevicePair -> /device/issue runs UNCHANGED. Only getting the identity onto the session is new — one navigation out and one return, same shape as clicking a link in a verification email.

- [ ] On the new address_info state, navigate to the bridge claim URL (popup or redirect, per the lane in use) and resume on return
- [ ] Email-screen copy: "Bluesky user? Try me@<your handle>"
- [ ] Bare handle-shaped input with no @ suggests me@<handle> instead of erroring
- [ ] Confirm the same path yields add-email-to-existing-account from the account page for free
- [ ] Helpful error copy when the handle does not resolve
