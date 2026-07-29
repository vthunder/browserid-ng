---
# browserid-ng-0t19
title: 'Explore: make deploys faster (45+ min for small changes)'
status: completed
type: task
priority: normal
created_at: 2026-07-29T11:32:55Z
updated_at: 2026-07-29T11:56:36Z
---

User report 2026-07-29: a small change takes 45+ minutes to deploy; hypothesis is most time is spent testing. Investigate where the time actually goes (local cargo test compile, CI image build cache effectiveness, dokku release) with evidence from gh run timings + local build profiling, and produce ranked recommendations with expected savings. Investigation only — no changes yet.

## Summary of Changes

Investigation complete (see session 2026-07-29). Headline: deploy pipeline is 2-3 min end-to-end and correctly cached (docs-only image build: 4s; source change: 59s; dokku release 1-2.5min). The 45 min is local + pre-commit: every broker test binary pays ~11.5s blocked in macOS system proxy detection because AppState::new_with_arcs -> Analytics::disabled() constructs an unused reqwest::Client (sampled stack: 100% in hyper_util Matcher::from_system). ~28 test binaries x 115 AppState call sites -> ~11 min of idle waiting per cargo test run; 45 min = 3-4 iterations. Also hits browserid-agent (mingo CLI ~11s/op), browserid-rp, and local broker startup. NO_PROXY does not bypass it; fix must be in code. CI-side work (sccache, cargo-chef, self-hosted) explicitly not worth doing. Follow-up beans filed for the fixes.
