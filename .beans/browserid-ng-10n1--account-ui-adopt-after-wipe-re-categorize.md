---
# browserid-ng-10n1
title: 'Account UI: adopt-after-wipe + re-categorize'
status: todo
type: feature
priority: low
created_at: 2026-07-21T21:02:32Z
updated_at: 2026-07-22T15:14:46Z
parent: browserid-ng-oup3
---

Deferred client-provisioning flows from the holder model note (Account UI section): adopt-after-wipe (re-bind a wiped device to its existing holder slot) and re-categorize (move holder to a new namespace -> rotate prefix, re-issue cert + affected warrants; heavy, warned). Both need client-side re-provisioning orchestration.

Move/reorg workflow SHIPPED on browserid.me (2026-07-22): /wsapi/move_holder (revoke-up-front + permanent old->new redirect + label carry-over), /wsapi/holder_assignment device check, dialog re-issue on next sign-in (popup w/ pinned holder for primaries, /device/issue redirect for broker ids + stale-client silent redirect), account UI move action + moving-to badges, forget_holder remove action. Remaining here: adopt-after-wipe. Primary-cert revocation immediacy gap filed separately.
