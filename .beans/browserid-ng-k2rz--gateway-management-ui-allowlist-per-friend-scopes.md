---
# browserid-ng-k2rz
title: 'Gateway management UI: allowlist, per-friend scopes, attribution log'
status: in-progress
type: feature
priority: normal
created_at: 2026-08-12T13:10:26Z
updated_at: 2026-08-12T16:11:26Z
parent: browserid-ng-81s6
blocked_by:
    - browserid-ng-in36
---

An admin-signed-in webpage for a running gateway. Start SMALL: configure the grantor allowlist. Grow: per-friend scope caps and the attribution log viewer. Per-friend scopes need NO new BrowserID infra and NO cross-user warrant — generalize the allowlist from {email->allowed} to {email->allowed scopes}, enforced in the gate proxy at CALL time as warrant.scopes ∩ owner.policy[grantor] (call-time because the gateway learns which human approved only after the browserid.me approval returns the warrant). The friend's warrant is a normal self-delegation; the owner cap is local gateway policy on top; intersection is the effective scope. Rich exploration area. Parent epic browserid-ng-81s6. Enforcement wiring lives with the gate CLI (browserid-ng-in36).

SUBSUMED by gate v2 (browserid-ng-oxio): the management UI becomes the admin console.
