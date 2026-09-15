---
# browserid-ng-svs7
title: 'Account page: policy editor (proof count, password pinned, approval on/off, proven>=k before mint) and devices list with how each was enrolled'
status: completed
type: task
priority: normal
created_at: 2026-09-15T00:11:59Z
updated_at: 2026-09-15T01:19:29Z
parent: browserid-ng-0vdu
blocked_by:
    - browserid-ng-noqd
---

GET/PUT /api/v1/account/policy UI within floors; login-keys list shows enrolled_by and proven identities; revoke. Inline module script -> update INLINE_SCRIPT_HASHES.

## Summary of Changes

Built 2026-09-15. Account settings 'How devices get in': proofs count (capped by identities), password always, approval on/off, mint_proven; saved via PUT /api/v1/account/policy. Device rows carry a badge and the detail line says how the browser was let in (password / another device / proving addresses). Playwright test in account-registry-session.spec. CSP hash updated.
