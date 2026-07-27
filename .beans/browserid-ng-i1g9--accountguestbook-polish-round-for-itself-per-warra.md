---
# browserid-ng-i1g9
title: 'Account/guestbook polish round: for-itself, per-warrant revoke, own-origin sites, name edit, wallet warrant mgmt'
status: completed
type: task
created_at: 2026-07-27T00:29:20Z
updated_at: 2026-07-27T00:29:20Z
---

Five fixes from Dan's testing + one follow-on:
- [x] walls (homepage, www guestbook, broker guestbook page) say 'for itself' when a warrant is self-granted instead of a hanging 'for'
- [x] /account holder detail: per-warrant Revoke/Forget buttons (same levers as site detail; endpoint already existed)
- [x] /account Sites now lists broker-origin sub-audiences (the guestbook); only the bare broker origin stays excluded
- [x] I2 name edits win everywhere: root cause was the holder label being set from the requester's label — it now prefers the user-chosen display_name (the emails.display_name path was already correct); verified via e2e with an edited name (P card + devices list both show it)
- [x] wallet MCP warrant management: new 'warrants' (list with grantor/grantee/relation/expiry) and 'drop_grant' tools; authorize gains a grantor pin ('self' | email) that REPLACES a held warrant with different attribution — the redo-with-a-different-on-behalf-of lever
- [x] production guestbook wiped (rm /data/guestbook.json + restart; feed now empty)

Broker suite green; CSP hash updated. NOTE: the new wallet tools need @browserid-ng/wallet 0.4.0 published to reach npx users.
