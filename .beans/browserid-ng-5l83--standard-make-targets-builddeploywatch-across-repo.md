---
# browserid-ng-5l83
title: Standard make targets (build/deploy/watch) across repos + mingo CI image deploys
status: in-progress
type: task
created_at: 2026-08-11T17:27:58Z
updated_at: 2026-08-11T17:27:58Z
---

Same Makefile vocabulary in browserid-ng, mingo, sbo, browserid-bsky: build/test/push/watch/release[-app]/deploy so deploy commands are never improvised. Move the mingo app to the CI-image pattern (deploy-mingo.yml mirroring the validated deploy-daemon.yml; rework deploy/mingo/Dockerfile to cook deps into image layers instead of target cache mounts; one-time dokku builder config on sandmill.org).
