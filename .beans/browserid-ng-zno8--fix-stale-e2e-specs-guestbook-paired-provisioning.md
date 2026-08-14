---
# browserid-ng-zno8
title: 'Fix stale e2e specs: guestbook + paired-provisioning drive an outdated /authorize flow'
status: todo
type: bug
created_at: 2026-08-14T17:37:40Z
updated_at: 2026-08-14T17:37:40Z
---

Both specs fail identically on main (verified at commit 5d022b5, pre-warrant-v2-broker changes): guestbook.spec.ts drives the OLD single-stage authorize page (#pv-identity select before any #pv-match step) and paired-provisioning.spec.ts 'no downloaded credential' fails after reaching the Meet screen (agent pickup leg). Reproduced twice on the dirty tree and once on clean HEAD (2 failed / 3 passed each time). Not caused by the warrant-v2 work — the same failures exist without it. Diagnose whether the page flow drifted from the specs (eywc Flow-I refactor?) or the agent pickup broke, and fix spec or page.
