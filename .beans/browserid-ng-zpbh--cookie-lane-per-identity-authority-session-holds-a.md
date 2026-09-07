---
# browserid-ng-zpbh
title: 'Cookie lane: per-identity authority (session holds a set of proven identities)'
status: todo
type: task
priority: normal
created_at: 2026-09-04T23:32:18Z
updated_at: 2026-09-07T19:14:28Z
parent: browserid-ng-71vt
blocked_by:
    - browserid-ng-0c49
---

registry-api-v1 r5 (2026-09-05) moves the API from account-wide authority to per-identity authority: a session token is minted from a SET of cert proofs and grants each proven identity its tier (auth = read, config = write); account-shared data is only the roster, namespaces, and notices. The browker's cookie lane (\`/wsapi/*\`) still mints a session from ONE identity's presentation and grants account-wide authority — so any IdP of any identity on the account can still reach every other identity's warrants via the cookie lane. The r5 fix is cosmetic until this lane matches.

Ruled by Dan 2026-09-05: real gap, tackle separately once the token lane is fully deployed and working.

- [ ] Cookie session carries a set of proven identities (one added per sign-in / presentation), not an account
- [ ] Every /wsapi handler resolves its subject identity and checks it against the session's set + tier (same §3.3 subject table as the API)
- [ ] /account page UI: show which identities the session has proven; prompt to sign in as another to act on it
- [ ] §3.4 / invariant 1 in registry-api-v1: restate parity as 'same subject rule' and close the gap note

2026-09-07: spec committed at 45b8f0c. Cookie lane work starts after 0c49 step 13 (token shim removed). Note the target moved: per-identity authority was replaced by account tiers + the guard; the cookie session should become a session on an explicit account at a tier, minted from a presentation, with the same guard at first sign-in from a new browser.
