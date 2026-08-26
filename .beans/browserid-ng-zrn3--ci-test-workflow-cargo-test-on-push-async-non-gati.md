---
# browserid-ng-zrn3
title: 'CI test workflow: cargo test on push (async, non-gating)'
status: completed
type: task
priority: normal
created_at: 2026-07-29T11:56:36Z
updated_at: 2026-08-26T23:07:54Z
---

From deploy-speed investigation (browserid-ng-0t19): nothing gates main today — neither workflow runs cargo test, Playwright is manual. Add a test workflow that runs the Rust suite in GHA on push (independent of deploy, deploy-immediately/test-async), so testing moves off the human's critical path. Do after the proxy-stall fix lands (suite is then a few minutes). Consider cargo-nextest afterward, and add a paths filter to deploy-broker.yml while in there (today docs-only pushes rebuild + no-op-deploy the broker, exiting 1).

## Summary of Changes

Added .github/workflows/test.yml (8434db6): cargo test --workspace on every push to main and every PR, pinned to Rust 1.85.0 to match the release Dockerfile, with rust-cache and paths filters scoped to the Rust crates. Runs independently of the deploy workflows (deploy immediately, test async) and has been green on every main push since. The same commit added the image-paths filter to deploy-broker.yml, ending the spurious red X from git:from-image no-ops on docs-only pushes. cargo-nextest and fmt/clippy gating deliberately left as follow-ups. (Closed by audit 2026-08-27.)
