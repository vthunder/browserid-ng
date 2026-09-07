---
# browserid-ng-fp66
title: Review registry-api-v1 §5.4 warrant registry mechanics (allocate_status / register / status refs)
status: todo
type: task
priority: normal
created_at: 2026-09-07T20:16:40Z
updated_at: 2026-09-07T20:16:58Z
blocked_by:
    - browserid-ng-0c49
---

Dan 2026-09-07: "this sounds like some corner of the spec I haven't reviewed carefully and maybe has stuff I don't want." Parked to revisit after 0c49 wraps and the core wallet-auth gap is tackled.

## What §5.4 currently says (post-simplification)
- Records keyed by (account, grantor, grantee, audience, scopes-as-set); every record carries a status ref THIS registry allocated, so every record is revocable here.
- `allocate_status {grantee, audience, scopes}` → {uri, idx} before the wallet signs a login warrant (inbox requests get theirs at `claim`). Config-cert member.
- `register {warrant, config_cert}` records a warrant signed outside the inbox flow (login warrants); ref MUST equal the allocated one (status_ref_mismatch). Never clears a set bit; re-register replaces bytes/timestamps.
- `revoke {id}` sets the bit, sticky; next allocation for the key gets a fresh index; indexes never reused.
- Deleted this round: unindexed/foreign-ref records, `unlist`, confirm_unrevoked, live_warrant, no_status_ref, `indexing` field.

## Questions to decide
- Is a two-step allocate-then-register the right shape for login warrants, or should the wallet sign and register in one call with the registry filling the ref (registry returns the ref, wallet re-signs?) — or should login warrants be minted via the inbox path too?
- Is `register` needed at all if every wallet-signed warrant goes through claim/allocate?
- Record key: is scopes-as-set the right identity for "same warrant"? Fresh-index-after-revoke rule OK?
- Migration between registries (foreign refs) stays v2 — confirm.
