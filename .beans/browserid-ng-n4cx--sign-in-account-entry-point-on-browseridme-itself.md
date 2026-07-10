---
# browserid-ng-n4cx
title: Sign-in / account entry point on browserid.me itself
status: todo
type: task
created_at: 2026-07-10T17:04:47Z
updated_at: 2026-07-10T17:04:47Z
---

browserid.me has no sign-in button — today you can only establish a broker session via an RP's login dialog (observed while trying to test agent flows: /agents and /consent both need a session). Add a first-party sign-in entry (e.g. on the landing page nav or /account) that drives the same dialog flow with the broker as its own RP. Relates to w7xu (landing repositioning).
