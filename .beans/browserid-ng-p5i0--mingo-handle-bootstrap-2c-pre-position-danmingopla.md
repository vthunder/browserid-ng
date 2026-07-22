---
# browserid-ng-p5i0
title: 'mingo handle bootstrap (2c): pre-position dan@mingo.place into the broker account'
status: todo
type: task
priority: normal
created_at: 2026-07-21T22:02:35Z
updated_at: 2026-07-22T18:57:50Z
parent: browserid-ng-oup3
---

Handoff §2c: signing in AS dan@mingo.place cold fails (mingo-idp only acts as IdP once a mingo session exists — recursive). Dan's framing: mingo pre-positions the handle identity into browserid when the handle is claimed (or on login).

Finding (2026-07-21 session): MOST of this already stands. broker auth_with_presentation (routes/primary.rs) attaches a primary email to the CURRENT broker account on dialog login (add_email_with_type verified/Primary when a session exists; transfer-on-proof when it lives elsewhere). So from the browser that claimed the handle (which has a mingo session), one dialog login as dan@mingo.place attaches it — and the poster approval's identity picker then offers it.

Remaining:
- [ ] Cold-browser recursion: a FRESH browser can't sign in as dan@mingo.place at all until it first establishes a mingo session via the external identity. Decide the pre-positioning trigger (on handle claim, mingo-web drives a broker-audience dialog login as the handle so the identity + config cert land in the broker account/keystore proactively).
- [ ] Poster-enable UX: if dan@mingo.place is not yet on the broker account when the approval page opens, the picker won't offer it — surface a hint ("sign in to an app as <handle> first") instead of a dead end.

## Warm-browser half RESOLVED (2026-07-22, mingo 9e2abe8)
Root cause of the "not signed in" dead end during CLI provisioning: the SPA's signed-in state is localStorage-only, so it looks logged in after the IdP session cookie lapses; device-authorize checked /whoami once and gave up. Fixed: device-authorize does a one-shot hop to /?return=/device-authorize (pending params survive in sessionStorage); the SPA verifies the IdP session — live cookie bounces straight back, else a click-driven sign-in modal runs the normal browserid dialog (rooted at the EXTERNAL identity — no recursion into mingo's own lane) and returns to finish issuance.

Remaining here = the true cold-start: a fresh browser with no mingo session AND no external-identity login yet (the same hop works mechanically, but the user must complete the external sign-in + handle mapping first — verify the onboarding path through the ?return hop, and the pre-positioning question stands for browsers that never visit mingo-web at all).
