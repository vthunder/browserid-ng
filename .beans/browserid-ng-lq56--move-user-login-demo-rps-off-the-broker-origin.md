---
# browserid-ng-lq56
title: Move user-login demo RPs off the broker origin
status: todo
type: task
priority: low
created_at: 2026-07-21T21:02:32Z
updated_at: 2026-07-21T21:02:32Z
parent: browserid-ng-oup3
---

A warrant audience is the ORIGIN, so RPs hosted on browserid.me (e.g. /broker-demo) collapse into the broker's own audience, which Authorized sites deliberately filters. Host user-login demos on their own origin (e.g. demo.browserid.me). Guestbook (agent-scoped) can stay.
