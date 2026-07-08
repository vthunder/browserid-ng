---
# browserid-ng-sdp2
title: Per-key rate limiting on /agent/* endpoints
status: todo
type: task
created_at: 2026-07-08T19:05:55Z
updated_at: 2026-07-08T19:05:55Z
parent: browserid-ng-l8lw
---

The l8lw design calls for a coarse per-API-key rate limit (in-memory token bucket is fine for v1) on the /agent/* provisioning endpoints, deferred out of the initial implementation. Population-level throttles come from the dedicated agent domain; this is the per-key layer.
