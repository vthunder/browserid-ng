---
# browserid-ng-nrwd
title: 'M-A step 3: registrar/broker/account distinct-grantee warrant request + approval'
status: in-progress
type: task
priority: high
created_at: 2026-07-23T14:02:51Z
updated_at: 2026-07-23T15:02:02Z
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
