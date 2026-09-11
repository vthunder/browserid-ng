---
# browserid-ng-38im
title: 'Account page: remove an address (registry detach §5.2.5)'
status: completed
type: feature
priority: normal
created_at: 2026-09-11T21:46:09Z
updated_at: 2026-09-11T21:47:50Z
---

The account page's 'Your addresses' rail listed identities but offered no way to remove one; the registry API has had detach since registry-api-v1 §5.2.5. Add a per-address remove with an in-page confirmation (never window.confirm), backed by POST /api/v1/account/detach; hidden for the last address (delete the account instead) and without a registry session. Dan asked for it 2026-09-11 to re-test adding a mingo handle.

## Summary of Changes

account.html: each address in 'Your addresses' gets a remove control (hidden without a registry session or when it is the last address); an in-page confirmation explains the hold; confirm calls POST /api/v1/account/detach and reloads. CSP hash updated. e2e: account-remove-address.spec.ts.
