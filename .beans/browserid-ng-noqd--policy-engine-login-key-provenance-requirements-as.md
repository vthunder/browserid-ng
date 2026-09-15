---
# browserid-ng-noqd
title: 'Policy engine + login-key provenance: requirements as data, enrolled_by on login keys, spec §4.2/§5.2.3 edits'
status: todo
type: task
priority: high
created_at: 2026-09-15T00:11:58Z
updated_at: 2026-09-15T00:12:21Z
parent: browserid-ng-0vdu
---

Per docs/plans/2026-09-14-account-authentication-policy-draft.md. Registrar: policy model (alternatives of conditions: password, proofs>=k, approval, enrolled, proven>=k, proven(identity), enrolled_by), baseline in code, per-account override row, evaluate at login/enrol. Store: enrolled_by (+ proving identities / approving key) on login_certs (sqlite migration + memory store), GET/PUT /api/v1/account/policy. Broker: one account-authentication module behind /wsapi/registry_login and the ceremony backend (proofs collected in a ceremony -> rule met?). Spec: registry-api-v1 §4.2 (methods stay; login-key record gains enrolled_by), §5.2.3, §5.1 discovery. Tests: registry_api_test.rs + a SqliteStore test for the new columns.
