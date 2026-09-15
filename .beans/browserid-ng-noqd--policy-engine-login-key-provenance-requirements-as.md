---
# browserid-ng-noqd
title: 'Policy engine + login-key provenance: requirements as data, enrolled_by on login keys, spec §4.2/§5.2.3 edits'
status: completed
type: task
priority: high
created_at: 2026-09-15T00:11:58Z
updated_at: 2026-09-15T00:40:01Z
parent: browserid-ng-0vdu
---

Per docs/plans/2026-09-14-account-authentication-policy-draft.md. Registrar: policy model (alternatives of conditions: password, proofs>=k, approval, enrolled, proven>=k, proven(identity), enrolled_by), baseline in code, per-account override row, evaluate at login/enrol. Store: enrolled_by (+ proving identities / approving key) on login_certs (sqlite migration + memory store), GET/PUT /api/v1/account/policy. Broker: one account-authentication module behind /wsapi/registry_login and the ceremony backend (proofs collected in a ceremony -> rule met?). Spec: registry-api-v1 §4.2 (methods stay; login-key record gains enrolled_by), §5.2.3, §5.1 discovery. Tests: registry_api_test.rs + a SqliteStore test for the new columns.

## Summary of Changes

Shipped and deployed 2026-09-15 (commit eabbc6f; prod migrated schema 43→44). browserid_registrar::policy (conditions, alternatives, baseline, floors, per-account override), enrolled_by/enrolled_with on login keys, login tokens carry the method, GET/PUT /api/v1/account/policy, broker account_auth module behind /wsapi/registry_login. Spec §4.2, §5.2.3, §5.2.7. Tests: policy unit tests, registry_api_test (provenance + floors), SqliteStore round-trip. Playwright 126 passed.
