---
# browserid-ng-78hi
title: 'e2e: guestbook/provisioning specs broken by prefix-chip handle UI (#pv-handles hidden)'
status: todo
type: bug
priority: normal
created_at: 2026-07-13T09:15:35Z
updated_at: 2026-07-13T09:15:35Z
---

guestbook.spec.ts (and any spec using the paired-provisioning approval UI) fails at page.fill('#pv-handles', handle): the element resolves but is 'not visible'. Introduced by commit 3a67e8a 'prefix-chip handle UI, single-handle default' which replaced the plain handles text input with a prefix-chip UI. #pv-handles still exists (placeholder 'claude, researcher, svc+*') but is hidden behind the chip control.

Pre-existing on main, NOT caused by the origin-split work (confirmed: guestbook.spec.ts fails identically without any split changes).

Fix: update the e2e provisioning helper to drive the new chip UI (or unhide/keep #pv-handles fillable). Affects guestbook.spec.ts step 1 and likely paired-provisioning.spec.ts. The marketing-split.spec.ts test avoids this by asserting feed<->marketing parity instead of freshly signing.
