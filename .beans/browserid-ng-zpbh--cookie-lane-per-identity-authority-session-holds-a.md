---
# browserid-ng-zpbh
title: 'Cookie lane: per-identity authority (session holds a set of proven identities)'
status: in-progress
type: task
priority: normal
created_at: 2026-09-04T23:32:18Z
updated_at: 2026-09-09T16:28:48Z
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

2026-09-09: holder moves removed end to end (registrar cores, broker /wsapi/move_holder + holder_assignment, issuance/presentation healing, dialog's pending-move checks). The holder_moves table and its store methods remain, dead; drop them with the rest of the cookie lane.

2026-09-09 rulings + plan: see docs/plans/2026-09-09-registry-pages-handoff.md. The account page logs in as its own keyless device (page-local login key → login page with password → stored_key after); §4.3 becomes 'sign' only (management writes need a session, signing needs a config cert); signing stays where the key is (dialog keystore on the web, the wallet natively — e98a).

2026-09-09 (Dan): /account as an RP rejected; the RP is the login page, later methods live there. §4.3 becomes 'a session suffices; signing calls carry a valid recorded config cert' (no config tier at all); warrants/lookup removed (redundant with GET warrants, no callers).

- [x] Step 1: spec §4.3/§5/§7.1 + drop require_config/has_config + delete warrants/lookup

- [x] Step 2: keyless mode in registry-session.js; /account logs in as its own device (page-local login key; password at sign-in or in the card; stored_key after); 'Signed in to this account' card lists login keys with sign-out; session_context carries the account id. API: POST /api/v1/login-keys provable by the submitted key itself (a page-login session has no member), answering a session body. e2e: account-registry-session.spec.ts.

Open for step 3: accounts with no password (primary/bridge-only) cannot open a registry session until the login page has a second method (e98a). Today the card says so and the rest of the page still runs on the cookie; when warrants/certs/holders move to the API (step 3) that becomes a page-wide gate — decide then whether reads stay on the cookie for those accounts.
