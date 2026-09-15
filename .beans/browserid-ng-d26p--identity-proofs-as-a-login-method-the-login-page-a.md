---
# browserid-ng-d26p
title: 'Identity proofs as a login method: the login page asks the wallet for proofs through the in-page mediator (web dialog + native wallet)'
status: todo
type: feature
priority: normal
created_at: 2026-09-15T00:12:21Z
updated_at: 2026-09-15T01:05:49Z
parent: browserid-ng-0vdu
blocked_by:
    - browserid-ng-noqd
    - browserid-ng-e98a
---

Login page method 'prove another identity': after one proof, masked address hints, ask navigator.id for a proof of a chosen identity; verify; count toward proofs>=k; return token. Web dialog: registry-session.js loginPage without a password opens the page; deferred attach (certs from the second proof attach only under the resulting session). Native wallet: navigator.id inside the embedded window answered by the wallet, deferred attach, re-entrancy state machine, cancel unwinding — bean e98a's list; e98a blocks this. Playwright: gmail+primary account enrols with no password.

Build notes 2026-09-15: backend /wsapi/registry_login_hints + /wsapi/registry_login_proofs (presentations for the broker's own audience; masked hints after one proof; token when the account's rule is met). Login page method 'Prove your identities' (navigator.id via include.js or the wallet's in-window mediator). Dialog: proveIdentities() proves the current identity plus any held identities matching the hints; a screen names what is missing. Native wallet: login-page-preload.js installs navigator.id in the login window; mediator.js answers login (held identity; a hinted other address runs its issuer ceremony, pair held unattached until the session exists, then deferredAttach). Not covered by Playwright: the dialog's proofs chooser needs a non-password second identity (mock primary) — deferred.
