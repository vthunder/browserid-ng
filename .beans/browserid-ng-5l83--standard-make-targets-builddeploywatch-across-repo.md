---
# browserid-ng-5l83
title: Standard make targets (build/deploy/watch) across repos + mingo CI image deploys
status: completed
type: task
priority: normal
created_at: 2026-08-11T17:27:58Z
updated_at: 2026-08-11T17:43:24Z
---

Same Makefile vocabulary in browserid-ng, mingo, sbo, browserid-bsky: build/test/push/watch/release[-app]/deploy so deploy commands are never improvised. Move the mingo app to the CI-image pattern (deploy-mingo.yml mirroring the validated deploy-daemon.yml; rework deploy/mingo/Dockerfile to cook deps into image layers instead of target cache mounts; one-time dokku builder config on sandmill.org).

## Summary of Changes
Standard Makefile vocabulary (build/test/push/watch/release[-app]/deploy) in
browserid-ng, mingo, sbo, browserid-bsky. mingo app moved to CI-image deploys:
deploy-mingo.yml + Dockerfile layer-cook rework (cold CI build <5 min; the
target cache mounts were why on-host builds cold-compiled) + one-time dokku
builder config. Bonus: fixed o7ip (per-repo CI dokku keys) so CI releases
everywhere; deploy = push + watch in ng/bsky/mingo. sbo deploys documented as
the mingo-side SBO_REV pin. Legacy on-host targets kept with the
dockerfile-path restore recipe.
