---
# browserid-ng-7v1h
title: 'Flaky browserid-agent consent_flow_test: session_context csrf_token missing'
status: todo
type: bug
created_at: 2026-07-14T21:01:40Z
updated_at: 2026-07-14T21:01:40Z
---

consent_flow_test tests fail intermittently (different subsets each run, also with --test-threads=1) on clean main @ 3eb363a. Panic at tests/common/mod.rs:119 — /wsapi/session_context returns JSON without csrf_token after complete_user_creation succeeded (set-cookie present). Pre-existing; discovered while verifying the external-warrant-request change (2026-07-14).
