---
# browserid-ng-e98a
title: 'Wallet: mediator inside the embedded browser, deferred attach, re-entrancy, identity choice (for the login page''s later methods)'
status: todo
type: feature
priority: high
created_at: 2026-09-07T22:06:11Z
updated_at: 2026-09-09T15:24:46Z
parent: browserid-ng-9yyk
blocked_by:
    - browserid-ng-0c49
---

From the 0c49 guard ruling (Dan, 2026-09-08): registry-api-v1 §4.2 now has ONE required guard kind, `page`. The page may ask the wallet for proof of another identity through the login mediator, like any site. That needs no protocol change but the wallet has to be built carefully. Gotchas, all agreed in discussion:

## What the wallet must do

- [ ] **Expose the login mediator inside the embedded browser.** Pages the wallet opens (guard page, issuer sign-in, anything) get `navigator.id.*`, answered by the wallet itself. Native wallets do not do this today (menubar prototype, `wallet/`). This is generally useful: any RP works inside the wallet's browser.
- [ ] **Deferred attach.** When the guard page asks for proof of identity Y and the wallet holds no cert for Y, the wallet runs Y's issuer sign-in and gets fresh certs. It MUST NOT attach them to the registry yet (no session; a bare attach of a fresh cert creates a NEW account). Hold them unattached, answer the page, finish X's guarded attach, then attach Y under the resulting session. Abandoned flows leave orphan certs: drop or revoke them.
- [ ] **Re-entrancy.** The wallet is mid-flow with the guard page open when the page asks for a presentation; answering may need a second issuer sign-in on top. Model this as an explicit state machine, not nested callbacks. Cancel paths must unwind both layers.
- [ ] **Identity choice.** The page cannot name the account's identities (never revealed), so the user picks in the mediator; the page rejects and re-asks if the pick is not on the account or is the identity being attached. Dan has ideas for helping the user choose that live entirely in the guard page (no protocol change). Coordinate with the broker's guard page once it exists.
- [ ] **Presentations need no registry.** Assertion + login warrant are signed locally under issuer certs; make sure the wallet's presentation path does not assume a registry session or a registered warrant.
- [ ] Tests: e2e against a warm broker (CI does not run e2e) covering: guard page with password; guard page asking for a second identity the wallet already holds; same when it must fetch fresh certs first (deferred attach ordering asserted via registry state); cancel mid-nested-flow.

## Related
0c49 (registry spec + r5 checklist step 12), 2026-08-28 native wallet design handoff (add the mediator-in-webview requirement there), qze7 (why the page can rely on native wallets by construction).

2026-09-09: the guard became login (registry-api-v1 §4.2; bean r9jo). Everything here still applies, now to the registry's login page and its later methods (approval by another device, proof of another identity through the mediator). The password baseline is shipped; the wallet runs the login page in its own window today.

2026-09-09 first item (Dan): native approvals — the wallet answers inbox requests itself with a native dialog and signs with its config key, posting requests/respond; today it opens the consent page, which has no key in a native-wallet browser. Plan in docs/plans/2026-09-09-registry-pages-handoff.md.
