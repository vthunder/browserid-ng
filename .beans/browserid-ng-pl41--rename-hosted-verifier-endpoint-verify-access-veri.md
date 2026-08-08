---
# browserid-ng-pl41
title: Rename hosted verifier endpoint /verify-access → /verify
status: todo
type: task
priority: normal
created_at: 2026-08-08T10:10:42Z
updated_at: 2026-08-08T10:10:42Z
parent: browserid-ng-8g49
---

The broker's hosted verification endpoint is currently /verify-access; it should be the shorter /verify. This is the RP-convenience HTTP service (NOT part of the core protocol spec — that was removed from browserid-ng-protocol.md §6 in the 2026-08-08 pass). Touch points: browserid-broker route (routes/device.rs verify_access + routes/mod.rs), docs/verify-quickstart.md (the HTTP contract doc), sdk/js createVerifier default, and any consumer defaults. Coordinate as an endpoint rename with a deprecation alias if anything external calls the old path.
