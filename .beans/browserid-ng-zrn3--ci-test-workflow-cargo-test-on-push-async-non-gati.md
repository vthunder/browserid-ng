---
# browserid-ng-zrn3
title: 'CI test workflow: cargo test on push (async, non-gating)'
status: in-progress
type: task
priority: normal
created_at: 2026-07-29T11:56:36Z
updated_at: 2026-07-29T14:32:37Z
---

From deploy-speed investigation (browserid-ng-0t19): nothing gates main today — neither workflow runs cargo test, Playwright is manual. Add a test workflow that runs the Rust suite in GHA on push (independent of deploy, deploy-immediately/test-async), so testing moves off the human's critical path. Do after the proxy-stall fix lands (suite is then a few minutes). Consider cargo-nextest afterward, and add a paths filter to deploy-broker.yml while in there (today docs-only pushes rebuild + no-op-deploy the broker, exiting 1).
