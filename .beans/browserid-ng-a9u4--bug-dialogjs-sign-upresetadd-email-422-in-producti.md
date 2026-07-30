---
# browserid-ng-a9u4
title: 'BUG: dialog.js sign-up/reset/add-email 422 in production (missing email field)'
status: completed
type: bug
priority: critical
created_at: 2026-07-29T12:35:42Z
updated_at: 2026-07-29T13:01:52Z
---

Commit 416c7b4 (audit C1) added a required `email` field to CompleteUserCreationRequest, CompleteResetRequest, and CompleteEmailRequest (broker looks up the pending code by (email, verification_type)). account.html was updated to pass email; dialog.js was MISSED on all three, so the popup dialog's new-user sign-up (dialog.js:1402), password reset (:1458), and add-email (:1546) verification steps all 422 in production. e2e specs call the APIs directly with email, so they didn't catch it. Found via the stale browserid-agent test (merged_provision_sdk_test).

## Summary of Changes
- dialog.js:1402 completeUserCreation: add `email: state.email`
- dialog.js:1458 completeReset: add `email: state.email`
- dialog.js:1546 completeEmailAddition: add `email: state.newEmail` (code was issued to the new address)
- merged_provision_sdk_test.rs:80: send `email: DELEGATOR` (stale cross-crate caller missed by 416c7b4)
dialog.js is external (<script src>), no CSP inline-hash update needed. Diagnosed by test-422 agent (found the sign-up one); reset + add-email found by checking all three structs in the commit.
