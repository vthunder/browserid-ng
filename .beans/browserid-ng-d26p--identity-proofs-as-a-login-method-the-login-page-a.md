---
# browserid-ng-d26p
title: 'Identity proofs as a login method: the login page asks the wallet for proofs through the in-page mediator (web dialog + native wallet)'
status: todo
type: feature
priority: normal
created_at: 2026-09-15T00:12:21Z
updated_at: 2026-09-15T00:12:21Z
parent: browserid-ng-0vdu
blocked_by:
    - browserid-ng-noqd
    - browserid-ng-e98a
---

Login page method 'prove another identity': after one proof, masked address hints, ask navigator.id for a proof of a chosen identity; verify; count toward proofs>=k; return token. Web dialog: registry-session.js loginPage without a password opens the page; deferred attach (certs from the second proof attach only under the resulting session). Native wallet: navigator.id inside the embedded window answered by the wallet, deferred attach, re-entrancy state machine, cancel unwinding — bean e98a's list; e98a blocks this. Playwright: gmail+primary account enrols with no password.
