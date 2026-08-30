---
# browserid-ng-lej3
title: authority checker caches probe FAILURES as Unprovable for 600s
status: todo
type: bug
priority: normal
created_at: 2026-08-30T18:01:42Z
updated_at: 2026-08-30T18:01:50Z
parent: browserid-ng-9yyk
---

Found debugging the chris.toshokelectric.com report (see sibling bean on the bridge hang). authority.rs handle_did() collapses 'bridge said valid:false' and 'bridge unreachable/timed out' into the same None, and authority_and_mx caches whatever came out for AUTHORITY_CACHE_SECONDS=600 — so a transient bridge timeout condemns a perfectly valid handle domain to proof:none for 10 minutes of retries (exactly what made Chris's retries hopeless). Fix: make the bridge probe tri-state (valid(did) / definitively-not-a-handle / cannot-tell) and either skip caching cannot-tell or cache it briefly (~30s). Definitive answers keep the 600s cache.
