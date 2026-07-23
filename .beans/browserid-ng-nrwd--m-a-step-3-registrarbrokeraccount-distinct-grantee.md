---
# browserid-ng-nrwd
title: 'M-A step 3: registrar/broker/account distinct-grantee warrant request + approval'
status: completed
type: task
priority: high
created_at: 2026-07-23T14:02:51Z
updated_at: 2026-07-23T17:42:40Z
parent: browserid-ng-atge
blocked_by:
    - browserid-ng-ztkh
---

warrant/provision request carries grantee (+ its supplied holder) distinct from grantor; approval signs the warrant with D's config cert naming grantee=G, grantor=D; record in D's external-services registry; account UI surfaces 'G acting for you'. Activate the external path.


## Step-3 design (investigated 2026-07-23)
Model A poster = mingo-poster@mingo.place, a DISTINCT identity minted by mingo-idp (it holds the mingo.place IdP key; the /agent_device_cert endpoint + stale create_agent_identity/poster_key are the seed). browserid mints NO cert for it. The user only signs a WARRANT (grantor=user, grantee=mingo-poster) with their config cert — a NEW consent surface: delegating to a service identity you do NOT own.

Registrar changes:
- validate_grant_warrants currently checks config.authorizes_identity(agent_email==grantee). For delegated it must check config authorizes the GRANTOR and warrant.grantee == the external grantee (mingo-poster). The current binding assumes grantee==the config's identity — must split.
- agent-provision request (or a dedicated external-warrant path) must carry an EXTERNAL GRANTEE (identity + its mingo-assigned holder) distinct from the approving grantor, and the approval must NOT mint a device cert (skip complete_device_cert's cert issuance), just collect + return the D-signed warrant~config.

Account UI: signDeviceWarrant(config, identity,...) signs grantor==grantee today. Needs a grantor/grantee split for the delegated case. Approval card must present "mingo-poster@mingo.place (a mingo service) wants to post as you (dan@mingo.place)".

## OPEN FORK for Dan
Extend /agent-provision with an `external_grantee` branch (reuses the pending-record + poll plumbing) vs a dedicated /warrant/external endpoint (activate the inert consent.rs `external` scaffold). Lean: extend agent-provision — least new surface, reuses the poster's existing enable/poll. And confirm the consent framing for delegating to a foreign service identity.



## Backend DONE (2026-07-23, committed 5ffe436, pushed)
Registrar grantor/grantee pins + delegated foreign-grantee warrant-only path built + integration-tested (delegated_foreign_grantee_is_warrant_only). validate_grant_warrants splits grantor/grantee. Owned flows + full suite green.
REMAINING on step 3: account.html approval card — render the delegated case (foreign grantee derived from account.emails), as-you warning, sign grantor!=grantee warrant + delegated complete. Needs a CSP inline-hash bump. Not yet built.

## DONE + deploying (2026-07-23). Registrar backend + account.html delegated card built, tested, pushed. Deploying browserid.me.
