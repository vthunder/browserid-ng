---
# browserid-ng-v9x2
title: 'mingo: changing your username leaves the old handle attached at browserid'
status: todo
type: task
created_at: 2026-09-11T22:16:57Z
updated_at: 2026-09-11T22:16:57Z
---

Saving a new username on mingo claims the new handle and attaches it to the browserid account (join, verified 2026-09-11: foo@mingo.place joined user 1 with parent link). The previous handle stays attached as a live identity. mingo should detach the old handle at the broker when the user changes it (or the account page should show it so the user can remove it) — the registry's detach needs the wallet's session, so this is a directed dialog call from mingo or a registry API call the wallet makes on the user's behalf. Related: 38im (remove address), bjiv.
