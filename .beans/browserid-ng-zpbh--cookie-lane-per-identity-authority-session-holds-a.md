---
# browserid-ng-zpbh
title: 'Cookie lane: per-identity authority (session holds a set of proven identities)'
status: todo
type: task
priority: normal
created_at: 2026-09-04T23:32:18Z
updated_at: 2026-09-08T08:48:09Z
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

## Scope as of 2026-09-08 (after 0c49)

The API side is done; what remains is the cookie lane's registry-role surface, which still serves three pages. Migrating it means: account.html (warrants list/revoke, holders list/rename/forget, certs list/revoke, manual signing allocate+register — ~12 call sites), consent.html (warrant_requests, warrant_respond, warrants) and authorize.html on `Registry` (registry-session.js; pick a keystore pair for an identity on the account; the fresh-session guard rule applies), then deleting /wsapi/{warrants,register_warrant,forget_warrant,revoke_warrant,allocate_warrant_status,warrant_requests,warrant_respond,device_certs,revoke_device_cert,cert_revocation_status,holders,rename_holder,forget_holder,move_holder,holder_assignment} and reworking the Rust tests that drive them (agent_flows_v2, connection_record, device_cert, hosted_primary, merged_provision, status_endpoints, warrant_return_url, warrant_device) and the e2e specs that assert through them (device-auth-resume, silent-assertion, connection-sharing, sbo-signing-grants). The dialog's holder_assignment/browser_holder cookie calls go with it (holders/move is gone from the spec). Estimate: 2–3 days.
